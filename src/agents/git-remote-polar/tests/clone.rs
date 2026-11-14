/*
   ACE Tool

   Copyright 2026 Carnegie Mellon University.

   NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
   FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
   EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
   PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
   MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
   TRADEMARK, OR COPYRIGHT INFRINGEMENT.

   Licensed under a MIT (SEI)-style license, please see license.txt or contact
   permission@sei.cmu.edu for full terms.

   [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
   distribution.  Please see Copyright notice for non-US Government use and distribution.

   This Software includes and/or makes use of Third-Party Software each subject to its own license.

   DM26-0670
*/

//! Plain git through the helper: `git clone polar://<repo>` and `git push` against a real polar-git over mTLS, with no
//! more configured than a person has: their Polar folder (`POLAR_ADMIN_DIR`), their username, and where polar-git is.

use polar_git::edge::PolicyAsker;
use polar_git::events::Recorder;
use polar_git::http::{PolarGitState, router};
use polar_git_server::git::GitRunner;
use polar_git_server::store::RepoStore;
use polar_git_server::tls::{ClientIdentities, alpn, client_verifier, serve_tls};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType,
};
use std::path::Path;
use std::sync::Arc;

const FIRST_POLICY: &str = include_str!("../../../../infra/seeds/signed/policy.cedar");

fn issue(
    issuer: &Issuer<'static, KeyPair>,
    sans: Vec<SanType>,
    eku: ExtendedKeyUsagePurpose,
) -> (String, String) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = sans;
    params.extended_key_usages = vec![eku];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_pem())
}

async fn git(cwd: &Path, admin: &Path, host: &str, args: &[&str]) -> (bool, String) {
    let helpers = Path::new(env!("CARGO_BIN_EXE_git-remote-polar"))
        .parent()
        .unwrap();
    let path = format!(
        "{}:{}",
        helpers.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = tokio::process::Command::new("git")
        .current_dir(cwd)
        .env("PATH", path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_SSL_CAINFO")
        .env_remove("SSL_CERT_FILE")
        .env_remove("GIT_CONFIG_COUNT")
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1")
        .env("POLAR_ADMIN_DIR", admin)
        .env("POLAR_USER", "alice")
        .env("POLAR_GIT_HOST", host)
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
        .args(["-c", "init.defaultBranch=main"])
        .args(args)
        .output()
        .await
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

/// docs/architecture/polar-git.md: a person pushes a new repository with `git push polar://tools`, clones it back with
/// `git clone polar://tools`, and pushes again from the clone, all with plain git.
#[tokio::test]
async fn plain_git_clones_and_pushes_a_polar_url() {
    let dir = tempfile::tempdir().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "polar-test-ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_pem = params.self_signed(&ca_key).unwrap().pem();
    let issuer = Issuer::new(params, ca_key);

    // The person's Polar folder, as their certificate's issuance leaves it.
    let admin = dir.path().join("polar-admin");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::write(admin.join("ca.pem"), &ca_pem).unwrap();
    let (cert, key) = issue(
        &issuer,
        vec![
            SanType::DnsName("alice".try_into().unwrap()),
            SanType::URI("g:repo-developers".try_into().unwrap()),
        ],
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    std::fs::write(admin.join("alice.crt"), cert).unwrap();
    std::fs::write(admin.join("alice.key"), key).unwrap();

    // polar-git, under the cluster's first policy.
    let (server_cert, server_key) = issue(
        &issuer,
        vec![SanType::IpAddress("127.0.0.1".parse().unwrap())],
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let (cert_file, key_file, ca_file) = (
        dir.path().join("server.pem"),
        dir.path().join("server.key"),
        dir.path().join("ca.pem"),
    );
    std::fs::write(&cert_file, server_cert).unwrap();
    std::fs::write(&key_file, server_key).unwrap();
    std::fs::write(&ca_file, &ca_pem).unwrap();
    let (permissions, _) = ractor::Actor::spawn(None, polar_permissions::PermissionsActor, ())
        .await
        .unwrap();
    let (policy, _) = ractor::Actor::spawn(
        None,
        polar_policy::PolicyActor,
        polar_policy::PolicyActorArgs {
            permissions_actor: permissions,
        },
    )
    .await
    .unwrap();
    ractor::call!(policy, |reply| polar_policy::PolicyMessage::UpdatePolicy {
        policy_source: FIRST_POLICY.to_string(),
        reply,
    })
    .unwrap()
    .unwrap();
    let store = RepoStore::new(dir.path().join("repos"));
    let app = router(PolarGitState {
        store: store.clone(),
        runner: GitRunner::default(),
        asker: Arc::new(PolicyAsker(Some(policy))),
        reporter: Arc::new(Recorder::default()),
        max_body: 64 * 1024 * 1024,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
        polar_crypto::tls::server_config(
            client_verifier(&ca_file, None).unwrap(),
            alpn(),
            &polar_crypto::tls::KeySource::Files {
                certificate: cert_file.display().to_string(),
                key: key_file.display().to_string(),
            },
        )
        .unwrap(),
    ));
    let stop = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(serve_tls(
        listener,
        acceptor,
        app,
        stop.clone(),
        Default::default(),
        Arc::new(ClientIdentities::new(None).unwrap()),
    ));

    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    assert!(git(&work, &admin, &host, &["init", "-q"]).await.0);
    std::fs::write(work.join("README.md"), "hello").unwrap();
    assert!(git(&work, &admin, &host, &["add", "README.md"]).await.0);
    let (ok, said) = git(
        &work,
        &admin,
        &host,
        &["commit", "-q", "-m", "chore: hello"],
    )
    .await;
    assert!(ok, "{said}");
    let (ok, said) = git(
        &work,
        &admin,
        &host,
        &["push", "-q", "polar://tools", "HEAD:main"],
    )
    .await;
    assert!(ok, "{said}");
    assert_eq!(
        store.owner("tools").await.unwrap().as_deref(),
        Some("alice")
    );

    let (ok, said) = git(
        dir.path(),
        &admin,
        &host,
        &["clone", "-q", "polar://tools", "copy"],
    )
    .await;
    assert!(ok, "{said}");
    let copy = dir.path().join("copy");
    assert_eq!(
        std::fs::read_to_string(copy.join("README.md")).unwrap(),
        "hello"
    );
    std::fs::write(copy.join("more.txt"), "more").unwrap();
    assert!(git(&copy, &admin, &host, &["add", "more.txt"]).await.0);
    assert!(
        git(&copy, &admin, &host, &["commit", "-q", "-m", "chore: more"])
            .await
            .0
    );
    let (ok, said) = git(&copy, &admin, &host, &["push", "-q"]).await;
    assert!(ok, "a push to the clone's own remote: {said}");
    stop.notify_one();
}
