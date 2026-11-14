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

//! polar-git against the real `git` CLI over real mTLS, with certificates minted for the test and the cluster's first
//! policy (infra/seeds/signed/policy.cedar) in a real policy actor: what a person may do is what that policy says.

use polar_git::edge::PolicyAsker;
use polar_git::events::{GitDone, GitEvent, Recorder};
use polar_git::http::{PolarGitState, router};
use polar_git_server::git::GitRunner;
use polar_git_server::store::RepoStore;
use polar_git_server::tls::{ClientIdentities, alpn, client_verifier, serve_tls};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

const FIRST_POLICY: &str = include_str!("../../../../infra/seeds/signed/policy.cedar");

struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

fn new_ca() -> Ca {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "polar-test-ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().unwrap();
    let pem = params.self_signed(&key).unwrap().pem();
    Ca {
        issuer: Issuer::new(params, key),
        pem,
    }
}

/// Writes `<name>.pem` and `<name>.key` signed by `ca`; returns their paths.
fn leaf(
    ca: &Ca,
    dir: &Path,
    name: &str,
    sans: Vec<SanType>,
    eku: ExtendedKeyUsagePurpose,
) -> (PathBuf, PathBuf) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = sans;
    params.extended_key_usages = vec![eku];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    let (c, k) = (
        dir.join(format!("{name}.pem")),
        dir.join(format!("{name}.key")),
    );
    std::fs::write(&c, cert.pem()).unwrap();
    std::fs::write(&k, key.serialize_pem()).unwrap();
    (c, k)
}

/// A person, by the identity their certificate gives, in the groups named.
fn person(ca: &Ca, dir: &Path, identity: &str, groups: &[&str]) -> (PathBuf, PathBuf) {
    let mut sans = vec![SanType::DnsName(identity.try_into().unwrap())];
    for group in groups {
        sans.push(SanType::URI(format!("g:{group}").try_into().unwrap()));
    }
    leaf(ca, dir, identity, sans, ExtendedKeyUsagePurpose::ClientAuth)
}

struct Harness {
    dir: tempfile::TempDir,
    ca: Ca,
    ca_file: PathBuf,
    port: u16,
    events: Arc<Recorder>,
    store: RepoStore,
    stop: Arc<Notify>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.notify_one();
    }
}

async fn policy(source: &str) -> ractor::ActorRef<polar_policy::PolicyMessage> {
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
        policy_source: source.to_string(),
        reply,
    })
    .unwrap()
    .unwrap();
    policy
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = new_ca();
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let (cert, key) = leaf(
            &ca,
            dir.path(),
            "server",
            vec![SanType::IpAddress("127.0.0.1".parse().unwrap())],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let store = RepoStore::new(dir.path().join("repos"));
        let events = Arc::new(Recorder::default());
        let app = router(PolarGitState {
            store: store.clone(),
            runner: GitRunner::default(),
            asker: Arc::new(PolicyAsker(Some(policy(FIRST_POLICY).await))),
            reporter: events.clone(),
            max_body: 64 * 1024 * 1024,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(
            polar_crypto::tls::server_config(
                client_verifier(&ca_file, None).unwrap(),
                alpn(),
                &polar_crypto::tls::KeySource::Files {
                    certificate: cert.display().to_string(),
                    key: key.display().to_string(),
                },
            )
            .unwrap(),
        ));
        let stop = Arc::new(Notify::new());
        tokio::spawn(serve_tls(
            listener,
            acceptor,
            app,
            stop.clone(),
            Default::default(),
            Arc::new(ClientIdentities::new(None).unwrap()),
        ));
        Self {
            dir,
            ca,
            ca_file,
            port,
            events,
            store,
            stop,
        }
    }

    fn url(&self, repo: &str) -> String {
        format!("https://127.0.0.1:{}/{repo}.git", self.port)
    }

    /// Runs git as the holder of `creds` in `cwd`: whether it succeeded, and what it said.
    async fn git(&self, cwd: &Path, creds: &(PathBuf, PathBuf), args: &[&str]) -> (bool, String) {
        let out = tokio::process::Command::new("git")
            .current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_SSL_CAINFO")
            .env_remove("SSL_CERT_FILE")
            .env("NO_PROXY", "127.0.0.1")
            .env("no_proxy", "127.0.0.1")
            .args(["-c", &format!("http.sslCAInfo={}", self.ca_file.display())])
            .args(["-c", &format!("http.sslCert={}", creds.0.display())])
            .args(["-c", &format!("http.sslKey={}", creds.1.display())])
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

    /// A working copy for `who`, with a first commit on main.
    async fn working(&self, who: &(PathBuf, PathBuf), name: &str) -> PathBuf {
        let work = self.dir.path().join(name);
        std::fs::create_dir_all(&work).unwrap();
        assert!(self.git(&work, who, &["init", "-q"]).await.0);
        self.commit(&work, who, "README.md", "hello").await;
        work
    }

    async fn commit(&self, work: &Path, who: &(PathBuf, PathBuf), file: &str, text: &str) {
        std::fs::write(work.join(file), text).unwrap();
        assert!(self.git(work, who, &["add", "--all"]).await.0);
        let (ok, said) = self
            .git(
                work,
                who,
                &["commit", "-q", "-m", &format!("chore: {file}")],
            )
            .await;
        assert!(ok, "{said}");
    }

    fn events(&self) -> Vec<GitEvent> {
        self.events.0.lock().unwrap().clone()
    }
}

/// docs/architecture/polar-git.md: a repo developer pushes to a repository that is not there, and it is made, theirs;
/// another repo developer clones it, pushes forward and tags, but may not rewrite or delete a branch in it; its owner may.
/// Each is said as an event.
#[tokio::test]
async fn repo_developers_work_as_on_any_git_server_and_only_the_owner_rewrites() {
    let h = Harness::start().await;
    let alice = person(&h.ca, h.dir.path(), "alice", &["repo-developers"]);
    let bob = person(&h.ca, h.dir.path(), "bob", &["repo-developers"]);

    let work = h.working(&alice, "alice-tools").await;
    let url = h.url("tools");
    let (ok, said) = h
        .git(&work, &alice, &["push", "-q", &url, "HEAD:main"])
        .await;
    assert!(ok, "{said}");
    assert_eq!(
        h.store.owner("tools").await.unwrap().as_deref(),
        Some("alice")
    );

    let bobs = h.dir.path().join("bob-tools");
    let (ok, said) = h
        .git(
            h.dir.path(),
            &bob,
            &["clone", "-q", &url, bobs.to_str().unwrap()],
        )
        .await;
    assert!(ok, "{said}");
    h.commit(&bobs, &bob, "b.txt", "b").await;
    let (ok, said) = h
        .git(&bobs, &bob, &["push", "-q", "origin", "HEAD:main"])
        .await;
    assert!(ok, "a push forward: {said}");
    let (ok, said) = h.git(&bobs, &bob, &["tag", "v1"]).await;
    assert!(ok, "{said}");
    let (ok, said) = h.git(&bobs, &bob, &["push", "-q", "origin", "v1"]).await;
    assert!(ok, "a tag: {said}");
    let (ok, said) = h
        .git(&bobs, &bob, &["push", "-q", "origin", "HEAD:feature"])
        .await;
    assert!(ok, "a branch: {said}");

    // A rewrite of main, and deleting a branch: not bob's repository.
    let (ok, said) = h
        .git(
            &bobs,
            &bob,
            &["commit", "-q", "--amend", "-m", "chore: rewritten"],
        )
        .await;
    assert!(ok, "{said}");
    let (ok, said) = h
        .git(
            &bobs,
            &bob,
            &["push", "-q", "--force", "origin", "HEAD:main"],
        )
        .await;
    assert!(!ok, "bob may not force: {said}");
    assert!(said.contains("git-force-push"), "{said}");
    let (ok, said) = h
        .git(&bobs, &bob, &["push", "-q", "origin", ":feature"])
        .await;
    assert!(!ok, "bob may not delete: {said}");

    // Its owner may.
    let (ok, said) = h.git(&work, &alice, &["pull", "-q", &url, "main"]).await;
    assert!(ok, "{said}");
    let (ok, said) = h
        .git(
            &work,
            &alice,
            &["commit", "-q", "--amend", "-m", "chore: rewritten"],
        )
        .await;
    assert!(ok, "{said}");
    let (ok, said) = h
        .git(&work, &alice, &["push", "-q", "--force", &url, "HEAD:main"])
        .await;
    assert!(ok, "the owner forces: {said}");
    let (ok, said) = h
        .git(&work, &alice, &["push", "-q", &url, ":feature"])
        .await;
    assert!(ok, "the owner deletes: {said}");

    let events = h.events();
    assert_eq!(events[0].what, GitDone::Created);
    assert_eq!(events[0].who, "alice");
    let pushed: Vec<(String, Vec<String>)> = events
        .iter()
        .filter_map(|e| match &e.what {
            GitDone::Pushed { moved } => Some((
                e.who.clone(),
                moved.iter().map(|m| m.action.clone()).collect(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        pushed,
        [
            ("alice".to_string(), vec!["git-push".to_string()]),
            ("bob".to_string(), vec!["git-push".to_string()]),
            ("bob".to_string(), vec!["git-tag".to_string()]),
            ("bob".to_string(), vec!["git-push".to_string()]),
            ("alice".to_string(), vec!["git-force-push".to_string()]),
            ("alice".to_string(), vec!["git-delete".to_string()]),
        ]
    );
    let refused: Vec<String> = events
        .iter()
        .filter_map(|e| match &e.what {
            GitDone::Refused { asked, .. } => Some(format!("{} {asked}", e.who)),
            _ => None,
        })
        .collect();
    assert_eq!(refused, ["bob git-force-push", "bob git-delete"]);
    assert!(
        events
            .iter()
            .any(|e| e.what == GitDone::Read && e.who == "bob")
    );
}

/// Someone policy says nothing of may do nothing: no repository is made for them, they read none, and each refusal is
/// said; and what they are told is the same whether the repository is there or not.
#[tokio::test]
async fn someone_policy_says_nothing_of_is_refused_everything_and_it_is_said() {
    let h = Harness::start().await;
    let alice = person(&h.ca, h.dir.path(), "alice", &["repo-developers"]);
    let mallory = person(&h.ca, h.dir.path(), "mallory", &[]);
    let work = h.working(&alice, "alice-tools").await;
    let (ok, said) = h
        .git(&work, &alice, &["push", "-q", &h.url("tools"), "HEAD:main"])
        .await;
    assert!(ok, "{said}");

    let theirs = h.working(&mallory, "mallory-work").await;
    let (ok, made) = h
        .git(
            &theirs,
            &mallory,
            &["push", "-q", &h.url("mine"), "HEAD:main"],
        )
        .await;
    assert!(!ok, "{made}");
    assert!(!h.store.exists("mine"), "no repository is made");
    let (ok, there) = h
        .git(
            h.dir.path(),
            &mallory,
            &["clone", "-q", &h.url("tools"), "m1"],
        )
        .await;
    assert!(!ok, "{there}");
    let (ok, absent) = h
        .git(
            h.dir.path(),
            &mallory,
            &["clone", "-q", &h.url("nothing"), "m2"],
        )
        .await;
    assert!(!ok, "{absent}");
    assert!(
        there.contains("403") && absent.contains("403"),
        "{there}\n{absent}"
    );

    let refused: Vec<String> = h
        .events()
        .iter()
        .filter(|e| e.who == "mallory")
        .filter_map(|e| match &e.what {
            GitDone::Refused { asked, .. } => Some(format!("{} {asked}", e.repo)),
            _ => None,
        })
        .collect();
    assert_eq!(
        refused,
        ["mine git-create", "tools git-read", "nothing git-read"]
    );
}
