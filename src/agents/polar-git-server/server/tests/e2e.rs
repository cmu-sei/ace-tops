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

//! The server against the real `git` CLI over real mTLS, with certificates minted for the test.

use polar_git_server::access::{RepoAcl, RuntimeAcl, StaticAcl};
use polar_git_server::git::GitRunner;
use polar_git_server::http::{ServerState, router};
use polar_git_server::logs::{LogsActor, LogsArgs, LogsMessage};
use polar_git_server::notify::{PushLog, Recorder, RepoChanged, Tee};
use polar_git_server::signed::{CommitPolicy, SignedRepos};
use polar_git_server::store::RepoStore;
use polar_git_server::tls::{ClientIdentities, alpn, client_verifier, serve_tls};
use polar_signing::testing::{CommitSigner, commit_signer};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, SanType,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

const REPO: &str = "polar-schedules";
const EVIDENCE_REPO: &str = polar_git_server_common::EVIDENCE_REPO;
/// A repository whose every commit must be signed.
const SIGNED_REPO: &str = "deploy-test";
/// The name the cluster gives the server, which its certificate carries.
const CLUSTER_NAME: &str = "polar-git-server.polar.svc.cluster.local";

struct Ca {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

fn new_ca(name: &str) -> Ca {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
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

fn client(ca: &Ca, dir: &Path, identity: &str) -> (PathBuf, PathBuf) {
    leaf(
        ca,
        dir,
        identity,
        vec![SanType::DnsName(identity.try_into().unwrap())],
        ExtendedKeyUsagePurpose::ClientAuth,
    )
}

struct Harness {
    dir: tempfile::TempDir,
    ca: Ca,
    deployment_ca: Ca,
    ca_file: PathBuf,
    port: u16,
    notes: Arc<Recorder>,
    stop: Arc<Notify>,
    logs: ractor::ActorRef<LogsMessage>,
}

/// The pipeline's certificate, and another's under its own CA. An RSA key is slow to make, so each is made once.
fn pipeline() -> &'static CommitSigner {
    static SIGNER: std::sync::OnceLock<CommitSigner> = std::sync::OnceLock::new();
    SIGNER.get_or_init(|| commit_signer("pipeline"))
}

fn stranger() -> &'static CommitSigner {
    static SIGNER: std::sync::OnceLock<CommitSigner> = std::sync::OnceLock::new();
    SIGNER.get_or_init(|| commit_signer("pipeline"))
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = new_ca("polar-test-ca");
        let ca_file = dir.path().join("ca.pem");
        std::fs::write(&ca_file, &ca.pem).unwrap();
        let deployment_ca = new_ca("polar-deploy-test-ca");
        let deployment_ca_file = dir.path().join("deployment-ca.pem");
        std::fs::write(&deployment_ca_file, &deployment_ca.pem).unwrap();
        let (cert, key) = leaf(
            &ca,
            dir.path(),
            "server",
            vec![
                SanType::IpAddress("127.0.0.1".parse().unwrap()),
                SanType::DnsName(CLUSTER_NAME.try_into().unwrap()),
            ],
            ExtendedKeyUsagePurpose::ServerAuth,
        );

        let store = RepoStore::new(dir.path().join("repos"));
        std::fs::create_dir_all(dir.path().join("repos")).unwrap();
        store.create(REPO).await.unwrap();
        let seed = dir.path().join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        std::fs::write(seed.join("credentials.dhall"), "{ seeded = True }").unwrap();
        store.seed(REPO, &seed).await.unwrap();
        store.create(SIGNED_REPO).await.unwrap();
        store.create(EVIDENCE_REPO).await.unwrap();
        store.seed(EVIDENCE_REPO, &seed).await.unwrap();
        let signed = SignedRepos::new(
            [(
                SIGNED_REPO.to_string(),
                CommitPolicy::new(&pipeline().ca_pem, "pipeline").unwrap(),
            )]
            .into(),
        );

        let acl = StaticAcl {
            admins: ["root".to_string()].into(),
            repos: [
                (
                    REPO.to_string(),
                    RepoAcl {
                        readers: ["polar-scheduler-observer".to_string()].into(),
                        writers: ["alice".to_string()].into(),
                    },
                ),
                (
                    SIGNED_REPO.to_string(),
                    RepoAcl {
                        readers: ["deployment:flux".to_string()].into(),
                        writers: ["alice".to_string()].into(),
                    },
                ),
                (
                    EVIDENCE_REPO.to_string(),
                    RepoAcl {
                        readers: ["eve".to_string()].into(),
                        writers: ["alice".to_string()].into(),
                    },
                ),
            ]
            .into(),
        };
        let notes = Arc::new(Recorder::default());
        let acl = Arc::new(
            RuntimeAcl::new(acl, Some(dir.path().join("repos/runtime-acl.json"))).unwrap(),
        );
        let (logs, _) = ractor::Actor::spawn(
            None,
            LogsActor,
            LogsArgs {
                root: dir.path().join("logs"),
                origin: "polar-git-server.test".to_string(),
                signer: std::sync::Arc::new(polar_git_server::logs::testing::KeySigner::new(
                    "polar-git-server.test",
                )),
            },
        )
        .await
        .unwrap();
        let app = router(ServerState {
            store,
            authorizer: acl.clone(),
            runtime: acl,
            runner: GitRunner::default(),
            notifier: Arc::new(Tee(vec![
                Arc::new(PushLog::new(dir.path().join("repos/push-log.jsonl"))),
                notes.clone(),
            ])),
            max_body: 64 * 1024 * 1024,
            signed: Arc::new(signed),
            logs: Some(logs.clone()),
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // The configuration the server's crypto actor makes from its key files (docs/plans/crypto-actor.md).
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(
            polar_crypto::tls::server_config(
                client_verifier(&ca_file, Some(&deployment_ca_file)).unwrap(),
                alpn(),
                &polar_crypto::tls::KeySource::Files {
                    certificate: cert.display().to_string(),
                    key: key.display().to_string(),
                },
            )
            .unwrap(),
        ));
        let identities = ClientIdentities::new(Some(&deployment_ca_file)).unwrap();
        let stop = Arc::new(Notify::new());
        tokio::spawn(serve_tls(
            listener,
            acceptor,
            app,
            stop.clone(),
            Default::default(),
            Arc::new(identities),
        ));
        Self {
            dir,
            ca,
            deployment_ca,
            ca_file,
            port,
            notes,
            stop,
            logs,
        }
    }

    fn url(&self) -> String {
        format!("https://127.0.0.1:{}/{REPO}.git", self.port)
    }

    fn changes(&self) -> Vec<RepoChanged> {
        self.notes.0.lock().unwrap().clone()
    }

    /// Runs git as the holder of `creds` (None: no client certificate) in `cwd`.
    async fn git(
        &self,
        cwd: &Path,
        creds: Option<&(PathBuf, PathBuf)>,
        args: &[&str],
    ) -> (bool, String) {
        let mut cmd = tokio::process::Command::new("git");
        cmd.current_dir(cwd)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_SSL_CAINFO")
            .env_remove("SSL_CERT_FILE")
            .env("NO_PROXY", "127.0.0.1")
            .env("no_proxy", "127.0.0.1")
            .args(["-c", &format!("http.sslCAInfo={}", self.ca_file.display())])
            .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"]);
        if let Some((c, k)) = creds {
            cmd.args(["-c", &format!("http.sslCert={}", c.display())])
                .args(["-c", &format!("http.sslKey={}", k.display())]);
        }
        let out = cmd.args(args).output().await.unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    async fn clone_as(
        &self,
        creds: Option<&(PathBuf, PathBuf)>,
        into: &str,
    ) -> (bool, PathBuf, String) {
        let dest = self.dir.path().join(into);
        let (ok, text) = self
            .git(
                self.dir.path(),
                creds,
                &["clone", &self.url(), dest.to_str().unwrap()],
            )
            .await;
        (ok, dest, text)
    }

    async fn commit(&self, repo: &Path, file: &str, content: &str) {
        std::fs::write(repo.join(file), content).unwrap();
        let (ok, t) = self.git(repo, None, &["add", "--all"]).await;
        assert!(ok, "{t}");
        let (ok, t) = self
            .git(
                repo,
                None,
                &["commit", "-m", &format!("chore: edit {file}")],
            )
            .await;
        assert!(ok, "{t}");
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.notify_one();
    }
}

#[tokio::test]
async fn an_authorized_reader_clones_the_seeded_content() {
    let h = Harness::start().await;
    let creds = client(&h.ca, h.dir.path(), "polar-scheduler-observer");
    let (ok, dest, text) = h.clone_as(Some(&creds), "obs").await;
    assert!(ok, "{text}");
    assert_eq!(
        std::fs::read_to_string(dest.join("credentials.dhall")).unwrap(),
        "{ seeded = True }"
    );
}

#[tokio::test]
async fn an_identity_with_no_access_is_refused() {
    let h = Harness::start().await;
    let creds = client(&h.ca, h.dir.path(), "mallory");
    let (ok, _, text) = h.clone_as(Some(&creds), "m").await;
    assert!(!ok, "{text}");
    assert!(text.contains("403"), "{text}");
}

#[tokio::test]
async fn there_is_no_anonymous_access() {
    let h = Harness::start().await;
    let (ok, _, text) = h.clone_as(None, "anon").await;
    assert!(!ok, "{text}");
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused() {
    let h = Harness::start().await;
    let rogue = new_ca("rogue");
    let creds = client(&rogue, h.dir.path(), "alice");
    let (ok, _, text) = h.clone_as(Some(&creds), "rogue").await;
    assert!(!ok, "{text}");
}

#[tokio::test]
async fn a_writer_pushes_and_the_change_is_announced() {
    let h = Harness::start().await;
    let creds = client(&h.ca, h.dir.path(), "alice");
    let (ok, repo, text) = h.clone_as(Some(&creds), "a").await;
    assert!(ok, "{text}");
    h.commit(&repo, "new.dhall", "1").await;
    let (ok, text) = h
        .git(&repo, Some(&creds), &["push", "origin", "HEAD:main"])
        .await;
    assert!(ok, "{text}");

    let changes = h.changes();
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0].repo, REPO);
    assert_eq!(changes[0].refname, "refs/heads/main");
    assert_eq!(changes[0].pusher, "alice");

    // And a reader now sees it.
    let obs = client(&h.ca, h.dir.path(), "polar-scheduler-observer");
    let (ok, dest, text) = h.clone_as(Some(&obs), "obs").await;
    assert!(ok, "{text}");
    assert!(dest.join("new.dhall").exists());
}

/// A clone of depth one, as Flux's source-controller makes the deployment's (go-git, depth 1): the head alone, cut there,
/// with its whole tree. Found on u7c, 2026-11-10: the server refused `deepen`, and Flux could fetch nothing from it.
#[tokio::test]
async fn a_clone_of_depth_one_has_the_head_alone_and_its_whole_tree() {
    let h = Harness::start().await;
    let creds = client(&h.ca, h.dir.path(), "alice");
    let (ok, repo, text) = h.clone_as(Some(&creds), "a").await;
    assert!(ok, "{text}");
    h.commit(&repo, "second.dhall", "2").await;
    h.commit(&repo, "third.dhall", "3").await;
    let (ok, text) = h
        .git(&repo, Some(&creds), &["push", "origin", "HEAD:main"])
        .await;
    assert!(ok, "{text}");
    let (_, head) = h.git(&repo, None, &["rev-parse", "HEAD"]).await;

    let obs = client(&h.ca, h.dir.path(), "polar-scheduler-observer");
    let dest = h.dir.path().join("shallow");
    let (ok, text) = h
        .git(
            h.dir.path(),
            Some(&obs),
            &["clone", "--depth", "1", &h.url(), dest.to_str().unwrap()],
        )
        .await;
    assert!(ok, "{text}");
    let (_, count) = h.git(&dest, None, &["rev-list", "--count", "HEAD"]).await;
    assert_eq!(count.trim(), "1");
    assert_eq!(
        std::fs::read_to_string(dest.join(".git/shallow"))
            .unwrap()
            .trim(),
        head.trim()
    );
    for (file, text) in [
        ("credentials.dhall", "{ seeded = True }"),
        ("second.dhall", "2"),
        ("third.dhall", "3"),
    ] {
        assert_eq!(
            std::fs::read_to_string(dest.join(file)).unwrap(),
            text,
            "{file}"
        );
    }
    let (ok, text) = h.git(&dest, None, &["fsck", "--strict"]).await;
    assert!(ok, "{text}");
}

#[tokio::test]
async fn a_reader_cannot_push_and_nothing_is_announced() {
    let h = Harness::start().await;
    let creds = client(&h.ca, h.dir.path(), "polar-scheduler-observer");
    let (ok, repo, text) = h.clone_as(Some(&creds), "r").await;
    assert!(ok, "{text}");
    h.commit(&repo, "sneaky.dhall", "x").await;
    let (ok, text) = h
        .git(&repo, Some(&creds), &["push", "origin", "HEAD:main"])
        .await;
    assert!(!ok, "{text}");
    assert!(h.changes().is_empty());
}

#[tokio::test]
async fn a_rewrite_of_history_is_refused_and_not_announced() {
    let h = Harness::start().await;
    let creds = client(&h.ca, h.dir.path(), "alice");
    let (_, repo, _) = h.clone_as(Some(&creds), "w").await;
    h.commit(&repo, "one.dhall", "1").await;
    let (ok, text) = h
        .git(&repo, Some(&creds), &["push", "origin", "HEAD:main"])
        .await;
    assert!(ok, "{text}");
    assert_eq!(h.changes().len(), 1);

    let (ok, t) = h.git(&repo, None, &["reset", "--hard", "HEAD~1"]).await;
    assert!(ok, "{t}");
    h.commit(&repo, "two.dhall", "2").await;
    let (ok, text) = h
        .git(
            &repo,
            Some(&creds),
            &["push", "--force", "origin", "HEAD:main"],
        )
        .await;
    assert!(!ok, "{text}");
    assert_eq!(
        h.changes().len(),
        1,
        "a refused update must not be announced"
    );
}

#[tokio::test]
async fn a_push_to_a_tag_is_refused() {
    let h = Harness::start().await;
    let creds = client(&h.ca, h.dir.path(), "alice");
    let (_, repo, _) = h.clone_as(Some(&creds), "t").await;
    let (ok, t) = h.git(&repo, None, &["tag", "v1"]).await;
    assert!(ok, "{t}");
    let (ok, text) = h.git(&repo, Some(&creds), &["push", "origin", "v1"]).await;
    assert!(!ok, "{text}");
    assert!(h.changes().is_empty());
}

/// What `just polar-git-clone` relies on: the URL keeps the name on the certificate, and curl is
/// told that name lives on the forwarded local port.
#[tokio::test]
async fn the_cluster_name_works_through_a_local_forward() {
    let h = Harness::start().await;
    let creds = client(&h.ca, h.dir.path(), "polar-scheduler-observer");
    let dest = h.dir.path().join("by-name");
    let url = format!("https://{CLUSTER_NAME}:{}/{REPO}.git", h.port);
    let resolve = format!("http.curloptResolve={CLUSTER_NAME}:{}:127.0.0.1", h.port);
    let (ok, text) = h
        .git(
            h.dir.path(),
            Some(&creds),
            &["-c", &resolve, "clone", &url, dest.to_str().unwrap()],
        )
        .await;
    assert!(ok, "{text}");
    assert!(dest.join("credentials.dhall").exists());

    // Without the mapping the name does not resolve, so the test is not passing by accident.
    let other = h.dir.path().join("unmapped");
    let (ok, _) = h
        .git(
            h.dir.path(),
            Some(&creds),
            &["clone", &url, other.to_str().unwrap()],
        )
        .await;
    assert!(!ok);
}

impl Harness {
    /// Calls the admin interface as the holder of `creds` with curl, which can present a client
    /// certificate; returns the HTTP status and body.
    async fn admin_put(&self, creds: &(PathBuf, PathBuf), name: &str, body: &str) -> (u16, String) {
        let out = tokio::process::Command::new("curl")
            .args(["--silent", "--show-error", "--noproxy", "*"])
            .args(["--cacert", self.ca_file.to_str().unwrap()])
            .args(["--cert", creds.0.to_str().unwrap()])
            .args(["--key", creds.1.to_str().unwrap()])
            .args(["--request", "PUT", "--data", body])
            .args(["--write-out", "\n%{http_code}"])
            .arg(format!(
                "https://127.0.0.1:{}/admin/repos/{name}",
                self.port
            ))
            .output()
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let (body, code) = text.rsplit_once('\n').unwrap_or(("", "0"));
        (code.trim().parse().unwrap_or(0), body.to_string())
    }
}

#[tokio::test]
async fn an_admin_creates_a_repository_that_its_writers_then_use() {
    let h = Harness::start().await;
    let root = client(&h.ca, h.dir.path(), "root");
    let (status, body) = h
        .admin_put(&root, "extra", r#"{"readers":["bob"],"writers":["carol"]}"#)
        .await;
    assert_eq!(status, 201, "{body}");
    // Asking again is not an error, and does not say "created" a second time.
    let (status, _) = h
        .admin_put(&root, "extra", r#"{"readers":["bob"],"writers":["carol"]}"#)
        .await;
    assert_eq!(status, 200);

    let carol = client(&h.ca, h.dir.path(), "carol");
    let url = format!("https://127.0.0.1:{}/extra.git", h.port);
    let work = h.dir.path().join("extra-work");
    let (ok, text) = h
        .git(
            h.dir.path(),
            Some(&carol),
            &["clone", &url, work.to_str().unwrap()],
        )
        .await;
    assert!(ok, "{text}");
    h.commit(&work, "a.dhall", "1").await;
    let (ok, text) = h
        .git(&work, Some(&carol), &["push", "origin", "HEAD:main"])
        .await;
    assert!(ok, "{text}");

    let bob = client(&h.ca, h.dir.path(), "bob");
    let (ok, text) = h
        .git(
            h.dir.path(),
            Some(&bob),
            &["clone", &url, h.dir.path().join("bob").to_str().unwrap()],
        )
        .await;
    assert!(ok, "{text}");
    let mallory = client(&h.ca, h.dir.path(), "mallory");
    let (ok, _) = h
        .git(
            h.dir.path(),
            Some(&mallory),
            &["clone", &url, h.dir.path().join("mal").to_str().unwrap()],
        )
        .await;
    assert!(!ok);
}

#[tokio::test]
async fn only_an_admin_may_create_and_a_declared_repository_is_not_reconfigured() {
    let h = Harness::start().await;
    let alice = client(&h.ca, h.dir.path(), "alice");
    let (status, _) = h.admin_put(&alice, "mine", "{}").await;
    assert_eq!(
        status, 403,
        "a writer of another repository is not an admin"
    );

    let root = client(&h.ca, h.dir.path(), "root");
    let (status, _) = h.admin_put(&root, REPO, r#"{"writers":["mallory"]}"#).await;
    assert_eq!(status, 409);
    let (status, _) = h.admin_put(&root, "Bad..Name", "{}").await;
    assert_eq!(status, 400);
    let (status, _) = h.admin_put(&root, "ok", r#"{"writerz":[]}"#).await;
    assert_eq!(status, 400, "a misspelled key is an error");

    // The refusal left alice's access to the declared repository as it was.
    let (ok, _, text) = h.clone_as(Some(&alice), "still").await;
    assert!(ok, "{text}");
}

#[tokio::test]
async fn accepted_pushes_are_recorded_and_refused_ones_are_not() {
    let h = Harness::start().await;
    let alice = client(&h.ca, h.dir.path(), "alice");
    let (_, repo, _) = h.clone_as(Some(&alice), "log").await;
    h.commit(&repo, "one.dhall", "1").await;
    let (ok, t) = h
        .git(&repo, Some(&alice), &["push", "origin", "HEAD:main"])
        .await;
    assert!(ok, "{t}");

    let mallory = client(&h.ca, h.dir.path(), "mallory");
    let (ok, _, _) = h.clone_as(Some(&mallory), "nope").await;
    assert!(!ok);

    let log = std::fs::read_to_string(h.dir.path().join("repos/push-log.jsonl")).unwrap();
    let lines: Vec<serde_json::Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 1, "{log}");
    assert_eq!(lines[0]["pusher"], "alice");
    assert_eq!(lines[0]["repo"], REPO);
    assert_eq!(lines[0]["ref"], "refs/heads/main");
}

// docs/architecture/key-custody.md, "Workload signing keys", item 7: a record is verified as of the commit that added it,
// so the evidence repository takes a push only of commits made about now, by the server's clock. A commit dated far from
// it, backdated into a certificate's life or ahead of the clock, is refused, and nothing stays or is announced.
#[tokio::test]
async fn the_evidence_repository_takes_only_commits_made_about_now() {
    let h = Harness::start().await;
    let alice = client(&h.ca, h.dir.path(), "alice");
    let url = format!("https://127.0.0.1:{}/{EVIDENCE_REPO}.git", h.port);
    let dest = h.dir.path().join("evidence");
    let (ok, t) = h
        .git(
            h.dir.path(),
            Some(&alice),
            &["clone", &url, dest.to_str().unwrap()],
        )
        .await;
    assert!(ok, "{t}");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    for (when, taken) in [(now - 3600, false), (now + 3600, false), (now, true)] {
        std::fs::write(dest.join(format!("record-{when}.json")), "{}").unwrap();
        let (ok, t) = h.git(&dest, None, &["add", "--all"]).await;
        assert!(ok, "{t}");
        let out = tokio::process::Command::new("git")
            .current_dir(&dest)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_COMMITTER_DATE", format!("{when} +0000"))
            .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
            .args(["commit", "-m", &format!("chore: a record at {when}")])
            .output()
            .await
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let (ok, text) = h
            .git(&dest, Some(&alice), &["push", "origin", "HEAD:main"])
            .await;
        assert_eq!(ok, taken, "{when}: {text}");
        if !taken {
            assert!(text.contains("server's clock"), "{text}");
            let (ok, t) = h.git(&dest, None, &["reset", "--hard", "HEAD~1"]).await;
            assert!(ok, "{t}");
            assert!(h.changes().is_empty(), "a refused push is not announced");
        }
    }
    assert_eq!(h.changes().len(), 1);
    assert_eq!(h.changes()[0].repo, EVIDENCE_REPO);

    // docs/architecture/record-store.md, "Pushes to the log": what a push adds is in the store's evidence log, as the
    // pusher's; a refused push added nothing. Only records count: a README and a hidden folder's file do not.
    let events = |leaves: Vec<polar_log::entry::Leaf>| -> Vec<(String, String)> {
        leaves
            .into_iter()
            .map(|l| {
                let entry = polar_log::entry::Entry::decode(&l.entry).unwrap();
                assert_eq!(entry.kind, "evidence-record");
                (l.submitter, String::from_utf8(entry.event).unwrap())
            })
            .collect()
    };
    assert_eq!(
        events(h.logged().await),
        [("alice".to_string(), "{}".to_string())]
    );
    std::fs::create_dir_all(dest.join(".hidden")).unwrap();
    std::fs::create_dir_all(dest.join("attestation/u7c")).unwrap();
    std::fs::write(dest.join("README.md"), "not a record").unwrap();
    std::fs::write(dest.join(".hidden/x.json"), "{\"hidden\":1}").unwrap();
    std::fs::write(dest.join("attestation/u7c/a.json"), "{\"a\":1}").unwrap();
    h.commit(&dest, "attestation/u7c/a.json", "{\"a\":1}").await;
    let (ok, text) = h
        .git(&dest, Some(&alice), &["push", "origin", "HEAD:main"])
        .await;
    assert!(ok, "{text}");
    assert_eq!(
        events(h.logged().await),
        [
            ("alice".to_string(), "{}".to_string()),
            ("alice".to_string(), "{\"a\":1}".to_string())
        ]
    );
}

// docs/architecture/cluster-bootstrap.md, "Handing off to Polar's git server": a deployment repository takes only what the pipeline signed.

/// A checkout with nothing in it, pointed at the signed repository, and a client that may write to it.
async fn signed_checkout(h: &Harness) -> (PathBuf, (PathBuf, PathBuf)) {
    let creds = client(&h.ca, h.dir.path(), "alice");
    let repo = h.dir.path().join("signed-checkout");
    std::fs::create_dir_all(&repo).unwrap();
    let url = format!("https://127.0.0.1:{}/{SIGNED_REPO}.git", h.port);
    for args in [vec!["init", "-q"], vec!["remote", "add", "origin", &url]] {
        let (ok, t) = h.git(&repo, None, &args).await;
        assert!(ok, "{t}");
    }
    (repo, creds)
}

/// A commit of `file`, on `parent`, signed by `signer` or by no one. Says its id.
async fn make_commit(
    h: &Harness,
    repo: &Path,
    file: &str,
    parent: Option<&str>,
    signer: Option<&CommitSigner>,
) -> String {
    std::fs::write(repo.join(file), file).unwrap();
    let (ok, t) = h.git(repo, None, &["add", "--all"]).await;
    assert!(ok, "{t}");
    let (ok, tree) = h.git(repo, None, &["write-tree"]).await;
    assert!(ok, "{tree}");
    let tree = tree.trim().to_string();
    let mut args = vec!["commit-tree", tree.as_str(), "-m", "chore(deploy): a layer"];
    if let Some(parent) = parent {
        args.extend(["-p", parent]);
    }
    let (ok, commit) = h.git(repo, None, &args).await;
    assert!(ok, "{commit}");
    let commit = commit.trim().to_string();
    let Some(signer) = signer else {
        return commit;
    };
    let (ok, raw) = h.git(repo, None, &["cat-file", "commit", &commit]).await;
    assert!(ok, "{raw}");
    let file = h.dir.path().join(format!("{commit}.raw"));
    std::fs::write(&file, signer.sign(raw.as_bytes())).unwrap();
    let (ok, signed) = h
        .git(
            repo,
            None,
            &["hash-object", "-t", "commit", "-w", file.to_str().unwrap()],
        )
        .await;
    assert!(ok, "{signed}");
    signed.trim().to_string()
}

async fn push(
    h: &Harness,
    repo: &Path,
    creds: &(PathBuf, PathBuf),
    commit: &str,
) -> (bool, String) {
    h.git(
        repo,
        Some(creds),
        &["push", "origin", &format!("{commit}:refs/heads/main")],
    )
    .await
}

/// What the server holds of the signed repository's `main`, and whether a commit reached its objects. Nothing of a refused push stays, and no
/// quarantine is left beside the repository.
async fn holds(h: &Harness, commit: &str) -> (Option<String>, bool) {
    let bare = h.dir.path().join(format!("repos/{SIGNED_REPO}.git"));
    let leftovers: Vec<_> = std::fs::read_dir(&bare)
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("polar-quarantine")
        })
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    let (ok, head) = h
        .git(
            &bare,
            None,
            &["rev-parse", "--verify", "-q", "refs/heads/main"],
        )
        .await;
    let (stored, _) = h.git(&bare, None, &["cat-file", "-e", commit]).await;
    (ok.then(|| head.trim().to_string()), stored)
}

#[tokio::test]
async fn a_commit_the_pipeline_signed_is_taken_and_announced() {
    let h = Harness::start().await;
    let (repo, creds) = signed_checkout(&h).await;
    let first = make_commit(&h, &repo, "a.yaml", None, Some(pipeline())).await;
    let (ok, text) = push(&h, &repo, &creds, &first).await;
    assert!(ok, "{text}");
    assert_eq!(holds(&h, &first).await, (Some(first.clone()), true));
    assert_eq!(h.changes().len(), 1);

    let second = make_commit(&h, &repo, "b.yaml", Some(&first), Some(pipeline())).await;
    let (ok, text) = push(&h, &repo, &creds, &second).await;
    assert!(ok, "{text}");
    assert_eq!(holds(&h, &second).await, (Some(second.clone()), true));
}

#[tokio::test]
async fn an_unsigned_commit_is_refused_from_someone_who_may_write_and_nothing_stays() {
    let h = Harness::start().await;
    let (repo, creds) = signed_checkout(&h).await;
    let commit = make_commit(&h, &repo, "a.yaml", None, None).await;
    let (ok, text) = push(&h, &repo, &creds, &commit).await;
    assert!(!ok, "{text}");
    // The person pushing is told why, in git's own words, not "the remote end hung up".
    assert!(text.contains("no signature"), "{text}");
    assert!(text.contains("-> main"), "{text}");
    assert_eq!(holds(&h, &commit).await, (None, false));
    assert!(h.changes().is_empty());
}

/// A signed head does not vouch for what is under it.
#[tokio::test]
async fn an_unsigned_commit_under_a_signed_one_is_refused() {
    let h = Harness::start().await;
    let (repo, creds) = signed_checkout(&h).await;
    let unsigned = make_commit(&h, &repo, "a.yaml", None, None).await;
    let head = make_commit(&h, &repo, "b.yaml", Some(&unsigned), Some(pipeline())).await;
    let (ok, text) = push(&h, &repo, &creds, &head).await;
    assert!(!ok, "{text}");
    assert_eq!(holds(&h, &head).await, (None, false));
}

#[tokio::test]
async fn a_commit_signed_under_another_ca_is_refused() {
    let h = Harness::start().await;
    let (repo, creds) = signed_checkout(&h).await;
    let commit = make_commit(&h, &repo, "a.yaml", None, Some(stranger())).await;
    let (ok, text) = push(&h, &repo, &creds, &commit).await;
    assert!(!ok, "{text}");
    assert_eq!(holds(&h, &commit).await, (None, false));
}

/// A commit already on the server gets no pass: the head of a ref is judged even when the push brings no objects, so a branch from before the
/// rule cannot be made what is deployed.
#[tokio::test]
async fn a_ref_cannot_be_pointed_at_an_unsigned_commit_already_on_the_server() {
    let h = Harness::start().await;
    let (repo, creds) = signed_checkout(&h).await;
    let unsigned = make_commit(&h, &repo, "a.yaml", None, None).await;
    let bare = h.dir.path().join(format!("repos/{SIGNED_REPO}.git"));
    let (ok, text) = h
        .git(
            &repo,
            None,
            &[
                "push",
                bare.to_str().unwrap(),
                &format!("{unsigned}:refs/heads/old"),
            ],
        )
        .await;
    assert!(ok, "{text}");
    let (ok, text) = push(&h, &repo, &creds, &unsigned).await;
    assert!(!ok, "{text}");
    let (ok, _) = h
        .git(
            &bare,
            None,
            &["rev-parse", "--verify", "-q", "refs/heads/main"],
        )
        .await;
    assert!(!ok, "main was moved");
}

#[tokio::test]
async fn deleting_the_deployed_branch_is_refused() {
    let h = Harness::start().await;
    let (repo, creds) = signed_checkout(&h).await;
    let commit = make_commit(&h, &repo, "a.yaml", None, Some(pipeline())).await;
    let (ok, text) = push(&h, &repo, &creds, &commit).await;
    assert!(ok, "{text}");
    let (ok, text) = h
        .git(&repo, Some(&creds), &["push", "origin", ":refs/heads/main"])
        .await;
    assert!(!ok, "{text}");
    assert_eq!(holds(&h, &commit).await.0, Some(commit));
}

/// Nothing changes for any other repository.
#[tokio::test]
async fn an_ordinary_repository_still_takes_an_unsigned_commit() {
    let h = Harness::start().await;
    let creds = client(&h.ca, h.dir.path(), "alice");
    let (ok, repo, text) = h.clone_as(Some(&creds), "ordinary").await;
    assert!(ok, "{text}");
    h.commit(&repo, "new.dhall", "1").await;
    let (ok, text) = h
        .git(&repo, Some(&creds), &["push", "origin", "HEAD:main"])
        .await;
    assert!(ok, "{text}");
}

// docs/architecture/cluster-bootstrap.md, "Handing off to Polar's git server": Flux holds a certificate of the deployment PKI, whose CA this server also trusts, and that CA's word is good
// only for names of its own: a certificate from it saying `alice` is not alice.

fn deployment_client(h: &Harness, name: &str) -> (PathBuf, PathBuf) {
    client(&h.deployment_ca, h.dir.path(), name)
}

/// A clone of the signed repository as `creds`, after the pipeline's first commit.
async fn clone_signed(h: &Harness, creds: &(PathBuf, PathBuf), into: &str) -> (bool, String) {
    let dest = h.dir.path().join(into);
    h.git(
        h.dir.path(),
        Some(creds),
        &[
            "clone",
            &format!("https://127.0.0.1:{}/{SIGNED_REPO}.git", h.port),
            dest.to_str().unwrap(),
        ],
    )
    .await
}

#[tokio::test]
async fn flux_reads_the_deployment_with_a_certificate_of_the_deployment_pki() {
    let h = Harness::start().await;
    let (repo, creds) = signed_checkout(&h).await;
    let commit = make_commit(&h, &repo, "a.yaml", None, Some(pipeline())).await;
    let (ok, text) = push(&h, &repo, &creds, &commit).await;
    assert!(ok, "{text}");
    let flux = deployment_client(&h, "flux");
    let (ok, text) = clone_signed(&h, &flux, "flux-clone").await;
    assert!(ok, "{text}");
}

#[tokio::test]
async fn flux_cannot_write_to_the_deployment() {
    let h = Harness::start().await;
    let (repo, creds) = signed_checkout(&h).await;
    let first = make_commit(&h, &repo, "a.yaml", None, Some(pipeline())).await;
    let (ok, text) = push(&h, &repo, &creds, &first).await;
    assert!(ok, "{text}");
    let flux = deployment_client(&h, "flux");
    let second = make_commit(&h, &repo, "b.yaml", Some(&first), Some(pipeline())).await;
    let (ok, text) = push(&h, &repo, &flux, &second).await;
    assert!(!ok, "{text}");
    assert_eq!(holds(&h, &first).await.0, Some(first));
}

#[tokio::test]
async fn flux_can_read_nothing_else() {
    let h = Harness::start().await;
    let flux = deployment_client(&h, "flux");
    let (ok, _, text) = h.clone_as(Some(&flux), "flux-schedules").await;
    assert!(!ok, "{text}");
}

/// The hole this closes: naming callers by a certificate's DNS name, with a second CA trusted, would let that CA name anyone.
#[tokio::test]
async fn a_deployment_pki_certificate_is_not_who_it_says_it_is_in_polar() {
    let h = Harness::start().await;
    let posing = deployment_client(&h, "alice");
    let (ok, repo, text) = h.clone_as(Some(&posing), "posing").await;
    assert!(
        !ok,
        "alice may read this repository, and this is not alice: {text}"
    );
    drop(repo);
    let admin = deployment_client(&h, "root");
    let (status, _) = h.admin_put(&admin, "made-by-a-stranger", "{}").await;
    assert_ne!(status, 200);
    assert_ne!(status, 201);
}

/// And the other way: Polar's CA cannot mint the deployment PKI's names.
#[tokio::test]
async fn a_polar_certificate_cannot_pose_as_the_deployment_pki() {
    let h = Harness::start().await;
    let posing = client(&h.ca, h.dir.path(), "deployment:flux");
    let (ok, text) = clone_signed(&h, &posing, "posing").await;
    assert!(!ok, "{text}");
}

impl Harness {
    /// Every leaf of the store's evidence log, in order; none when nothing was appended.
    async fn logged(&self) -> Vec<polar_log::entry::Leaf> {
        let mut leaves = Vec::new();
        loop {
            match ractor::call!(self.logs, |reply| LogsMessage::Leaf {
                log: "evidence".to_string(),
                seq: leaves.len() as u64,
                reply,
            })
            .unwrap()
            {
                Ok(Some(leaf)) => leaves.push(leaf),
                Ok(None) => return leaves,
                Err(why) if leaves.is_empty() && why.contains("no log") => return leaves,
                Err(why) => panic!("{why}"),
            }
        }
    }

    /// GETs `path` as the holder of `creds` with curl: the HTTP status and the body's bytes.
    async fn get(&self, creds: &(PathBuf, PathBuf), path: &str) -> (u16, Vec<u8>) {
        let body = self.dir.path().join("curl-body");
        let out = tokio::process::Command::new("curl")
            .args(["--silent", "--show-error", "--noproxy", "*"])
            .args(["--cacert", self.ca_file.to_str().unwrap()])
            .args(["--cert", creds.0.to_str().unwrap()])
            .args(["--key", creds.1.to_str().unwrap()])
            .args(["--output", body.to_str().unwrap()])
            .args(["--write-out", "%{http_code}"])
            .arg(format!("https://127.0.0.1:{}{path}", self.port))
            .output()
            .await
            .unwrap();
        let code = String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .unwrap_or(0);
        (code, std::fs::read(&body).unwrap_or_default())
    }
}

/// docs/architecture/record-store.md, "Bite 3": a person who may read the evidence repository reads the evidence log
/// as C2SP tiles over the server's mTLS interface, and gets back exactly what the checkpoint, signed with the store's
/// key, states. No one else reads it, and no other log is served.
#[tokio::test]
async fn a_reader_of_the_evidence_repository_reads_the_evidence_log_as_tiles() {
    use polar_log::checkpoint::{Checkpoint, NoteVerifier, open};
    use polar_log::entry::{Entry, Leaf};
    let h = Harness::start().await;
    let mut entries = Vec::new();
    for n in 0..300u32 {
        let entry = Entry {
            kind: "evidence-record".to_string(),
            version: 1,
            critical: true,
            writer: "test".to_string(),
            event: n.to_be_bytes().to_vec(),
        }
        .encode();
        ractor::call!(h.logs, |reply| LogsMessage::AppendOnce {
            log: "evidence".to_string(),
            entry: entry.clone(),
            submitter: "attestation-agent".to_string(),
            reply,
        })
        .unwrap()
        .unwrap();
        entries.push(entry);
    }
    let pinned = NoteVerifier::parse(
        &ractor::call!(h.logs, LogsMessage::VerifierKey)
            .unwrap()
            .unwrap(),
    )
    .unwrap();

    let eve = client(&h.ca, h.dir.path(), "eve");
    // Readers require the witness's co-signature (record-store.md, "Bite 5"): until it is given, no checkpoint.
    let (status, body) = h.get(&eve, "/logs/evidence/checkpoint").await;
    assert_eq!(status, 503);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "the log is not yet witnessed\n"
    );
    let witness = polar_log::checkpoint::Cosigner::new(
        "attestation-agent/witness",
        p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap(),
    )
    .unwrap();
    let witness_key = NoteVerifier::parse(&witness.verifier_key()).unwrap();
    let submission = ractor::call!(h.logs, |reply| LogsMessage::Submission {
        log: "evidence".to_string(),
        old: 0,
        reply,
    })
    .unwrap()
    .unwrap();
    let (submitted, _) = open(&submission.checkpoint, std::slice::from_ref(&pinned)).unwrap();
    let line = witness.cosign_line(&submitted, 1_731_300_000);
    let kept = ractor::call!(h.logs, |reply| LogsMessage::KeepCosigned {
        log: "evidence".to_string(),
        checkpoint: submission.checkpoint.clone(),
        line,
        witness: witness_key.clone(),
        reply,
    })
    .unwrap();
    assert_eq!(kept, Ok(300));
    let (status, note) = h.get(&eve, "/logs/evidence/checkpoint").await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&note));
    let (text, by) = open(&String::from_utf8(note).unwrap(), &[pinned, witness_key]).unwrap();
    assert_eq!(
        by,
        [
            submission_signer(&submission.checkpoint),
            "attestation-agent/witness".to_string()
        ]
    );
    let checkpoint = Checkpoint::parse(&text).unwrap();
    assert_eq!(checkpoint.size, 300);
    let mut fetched = Vec::new();
    for tile in polar_log::tiles::entry_tiles(checkpoint.size) {
        let (status, bytes) = h
            .get(&eve, &format!("/logs/evidence/{}", tile.path()))
            .await;
        assert_eq!(status, 200, "{}", tile.path());
        fetched.push((tile.path(), bytes));
    }
    let leaves = polar_log::tiles::read_log(&checkpoint, |path| {
        Ok(fetched
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, b)| b.clone()))
    })
    .unwrap();
    let held: Vec<Vec<u8>> = leaves
        .iter()
        .map(|l| Leaf::decode(l).unwrap().entry)
        .collect();
    assert_eq!(held, entries);
    let (status, _) = h.get(&eve, "/logs/evidence/tile/0/001.p/44").await;
    assert_eq!(status, 200);
    for absent in [
        "/logs/evidence/tile/0/1",
        "/logs/evidence/tile/entries/001.p/45",
        "/logs/schedules/checkpoint",
    ] {
        assert_eq!(h.get(&eve, absent).await.0, 404, "{absent}");
    }

    let mallory = client(&h.ca, h.dir.path(), "mallory");
    assert_eq!(h.get(&mallory, "/logs/evidence/checkpoint").await.0, 403);
    assert_eq!(
        h.get(&mallory, "/logs/evidence/tile/entries/000").await.0,
        403
    );

    // The logs not answering is the store's, now: unavailable, said, never an empty answer.
    h.logs.stop(None);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    for path in [
        "/logs/evidence/checkpoint",
        "/logs/evidence/tile/entries/000",
    ] {
        let (status, body) = h.get(&eve, path).await;
        assert_eq!(status, 503, "{path}");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "the log could not be read\n"
        );
    }
}

/// The logs' routes take no repository's place: a repository named `logs` is cloned at `/logs`, as any other is.
#[tokio::test]
async fn a_repository_named_logs_is_still_served() {
    let h = Harness::start().await;
    let root = client(&h.ca, h.dir.path(), "root");
    let (status, body) = h
        .admin_put(&root, "logs", r#"{"readers":[],"writers":["alice"]}"#)
        .await;
    assert_eq!(status, 201, "{body}");
    let alice = client(&h.ca, h.dir.path(), "alice");
    for (url, into) in [("logs", "logs-bare"), ("logs.git", "logs-dotgit")] {
        let url = format!("https://127.0.0.1:{}/{url}", h.port);
        let work = h.dir.path().join(into);
        let (ok, text) = h
            .git(
                h.dir.path(),
                Some(&alice),
                &["clone", &url, work.to_str().unwrap()],
            )
            .await;
        assert!(ok, "{url}: {text}");
    }
}

/// The name the store's checkpoint key signs under, as its note's signature line names it.
fn submission_signer(note: &str) -> String {
    let line = &note[note.rfind("\n\n").unwrap() + 2..];
    line.trim_start_matches('\u{2014}')
        .trim()
        .split(' ')
        .next()
        .unwrap()
        .to_string()
}
