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

//! The canary that proves network enforcement (docs/plans/runtime-attestation/network-enforcement.md, the canary).
//!
//! Polar's own checks are the guard: rather than take the cluster's word that the builds' policy is enforced, the
//! orchestrator runs a pod made as a build's, in the build namespace and under the builds' own policy, which must reach
//! the registry and must not reach the Kubernetes API or an address outside the cluster (`build-fetch --probe-network`,
//! in the fetch's image). A build is made only while a proof is fresh: the first build after the last proof grew older
//! than its bound proves again, and one that cannot be proved is refused, with why.
//!
//! The canary's Job is its template's pod changed only where a canary differs (`canary_job`), and checked before it is
//! made against what a canary may change (`canary_departures`), as a build's Job is.

use crate::job::{
    FETCH, JobOptions, PIPELINE, differing, extends, fetch_resources, plain, registry_alias,
    security_context, take, tmp_volume, tmp_volume_mount, to_value,
};
use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{Container, HostAlias, PodTemplate, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use orchestrator_core::types::Privileges;
use std::collections::BTreeMap;
use std::future::Future;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// The fetch image's binary and the argument that runs its probe (build-fetch's `probe::PROBE_ARG`).
pub const PROBE_COMMAND: [&str; 2] = ["build-fetch", "--probe-network"];
/// The settings the probe reads (build-fetch's `probe::REACH` and `probe::UNREACHABLE`).
pub const REACH_VAR: &str = "CYCLOPS_PROBE_REACH";
pub const UNREACHABLE_VAR: &str = "CYCLOPS_PROBE_UNREACHABLE";
/// The label that tells a canary's Job from a build's.
pub const CANARY_TYPE: &str = "canary";
/// The Kubernetes API, as every pod of a cluster may name it: the canary must not reach it. Resolved by the orchestrator,
/// as the registry's name is, since the canary has no DNS.
pub const KUBERNETES_API: &str = "kubernetes.default.svc:443";
/// How long a canary's Job may run before Kubernetes ends it.
pub const CANARY_DEADLINE: Duration = Duration::from_secs(120);
/// How long a canary's Job is kept once it ends: long enough to read why one failed.
const CANARY_KEPT: Duration = Duration::from_secs(3600);

/// What a canary tries: the addresses it must reach and must not, and the names it is given addresses for, since a
/// build's pod has no DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub reach: Vec<String>,
    pub unreachable: Vec<String>,
    pub aliases: Vec<(String, Ipv4Addr)>,
}

/// A canary's Job name: its template's, so that the attestation agent takes it as the build workload's, then `canary`
/// and an id (`build-runner-canary-` and a UUID are 56 characters, under Kubernetes' 63).
pub fn canary_name(template: &str, id: Uuid) -> String {
    format!("{template}-{CANARY_TYPE}-{id}")
}

/// A canary's Job, made from `template`: its pod with no init container, and in place of the pipeline, the fetch's
/// image running the probe, hardened as the fetch is; the scratch volume; the probe's aliases. A template without its
/// `fetch` init container is not the build workload's, and no canary is made from it.
pub fn canary_job(
    template: &PodTemplate,
    options: &JobOptions,
    probe: &Probe,
    id: Uuid,
) -> Result<Job, String> {
    let pod_template = template
        .template
        .as_ref()
        .ok_or("the PodTemplate has no pod")?;
    let mut pod = pod_template
        .spec
        .clone()
        .ok_or("the PodTemplate has no pod spec")?;
    let fetch = pod
        .init_containers
        .take()
        .into_iter()
        .flatten()
        .find(|c| c.name == FETCH)
        .ok_or("the PodTemplate has no `fetch` init container")?;
    pod.containers = vec![canary_container(&fetch, probe)];
    pod.volumes.get_or_insert_with(Vec::new).push(tmp_volume());
    let aliases = pod.host_aliases.get_or_insert_with(Vec::new);
    for (host, address) in &probe.aliases {
        aliases.push(registry_alias(host, *address));
    }

    let labels = canary_labels(id);
    let mut pod_metadata = pod_template.metadata.clone().unwrap_or_default();
    pod_metadata
        .labels
        .get_or_insert_with(BTreeMap::new)
        .extend(labels.clone());
    pod_metadata.name = None;

    Ok(Job {
        metadata: ObjectMeta {
            name: Some(canary_name(&options.template, id)),
            namespace: Some(options.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(JobSpec {
            template: PodTemplateSpec {
                metadata: Some(pod_metadata),
                spec: Some(pod),
            },
            backoff_limit: Some(0),
            active_deadline_seconds: Some(CANARY_DEADLINE.as_secs() as i64),
            ttl_seconds_after_finished: Some(CANARY_KEPT.as_secs() as i32),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn canary_labels(id: Uuid) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "app.kubernetes.io/managed-by".to_string(),
            "build-orchestrator".to_string(),
        ),
        ("cyclops.build/id".to_string(), id.to_string()),
        ("cyclops.build/type".to_string(), CANARY_TYPE.to_string()),
    ])
}

/// The probe's container: named as the pipeline is, so that its log is read as a build's is; the fetch's image, its
/// command the probe, its environment the probe's addresses, the fetch's resources and hardening, and scratch.
fn canary_container(fetch: &Container, probe: &Probe) -> Container {
    Container {
        name: PIPELINE.to_string(),
        image: fetch.image.clone(),
        image_pull_policy: fetch.image_pull_policy.clone(),
        command: Some(PROBE_COMMAND.iter().map(|s| s.to_string()).collect()),
        env: Some(vec![
            plain(REACH_VAR, probe.reach.join(",")),
            plain(UNREACHABLE_VAR, probe.unreachable.join(",")),
        ]),
        resources: Some(fetch_resources()),
        security_context: Some(security_context(
            fetch.security_context.as_ref(),
            &Privileges::default(),
        )),
        volume_mounts: Some(vec![tmp_volume_mount()]),
        ..Default::default()
    }
}

/// Where a canary's Job departs from what a canary may be, each said in a sentence; none, for one made by `canary_job`.
/// Said independently of it, and checked before every create. A canary may differ from its template's pod in:
///
/// - its labels, by labels added;
/// - its init containers, none;
/// - its containers, one: the fetch's image and pull policy, the probe's command, the probe's two settings as plain
///   values and nothing else, the fetch's resources and hardening, the scratch mount;
/// - its volumes, by the scratch volume;
/// - its host aliases, by one alias for each of `names`, each at an IPv4 address.
pub fn canary_departures(template: &PodTemplate, job: &Job, names: &[&str]) -> Vec<String> {
    let Some(want) = template.template.as_ref() else {
        return vec!["the template has no pod".into()];
    };
    let Some(got) = job.spec.as_ref().map(|s| &s.template) else {
        return vec!["the Job has no pod".into()];
    };
    let (Some(want_pod), Some(got_pod)) = (want.spec.as_ref(), got.spec.as_ref()) else {
        return vec!["the template or the Job has no pod spec".into()];
    };
    let mut found = Vec::new();

    let mut want_meta = to_value(&want.metadata.clone().unwrap_or_default());
    let mut got_meta = to_value(&got.metadata.clone().unwrap_or_default());
    let want_labels = take(&mut want_meta, "labels");
    let got_labels = take(&mut got_meta, "labels");
    take(&mut want_meta, "name");
    if want_meta != got_meta {
        found.push("the pod's metadata is not its template's, beyond its labels".into());
    }
    if !extends(&want_labels, &got_labels) {
        found.push("the pod's labels change or drop one of its template's".into());
    }

    let mut want_spec = to_value(want_pod);
    let mut got_spec = to_value(got_pod);
    for field in ["containers", "initContainers", "volumes", "hostAliases"] {
        take(&mut want_spec, field);
        take(&mut got_spec, field);
    }
    if want_spec != got_spec {
        found.push(format!(
            "the pod departs from its template's in {}",
            differing(&want_spec, &got_spec).join(", ")
        ));
    }

    if got_pod
        .init_containers
        .as_ref()
        .is_some_and(|c| !c.is_empty())
    {
        found.push("the canary's pod has init containers".into());
    }
    let mut volumes = want_pod.volumes.clone().unwrap_or_default();
    volumes.push(tmp_volume());
    if got_pod.volumes.clone().unwrap_or_default() != volumes {
        found.push("the pod's volumes are not its template's and the scratch volume".into());
    }

    let fetch = want_pod
        .init_containers
        .iter()
        .flatten()
        .find(|c| c.name == FETCH);
    match (fetch, got_pod.containers.as_slice()) {
        (None, _) => found.push("the template has no `fetch` init container".into()),
        (Some(fetch), [only]) => container_departs(fetch, only, &mut found),
        (Some(_), more) => found.push(format!(
            "the canary's pod has {} containers, and may have one",
            more.len()
        )),
    }

    let want_aliases = want_pod.host_aliases.clone().unwrap_or_default();
    let got_aliases = got_pod.host_aliases.clone().unwrap_or_default();
    match got_aliases.strip_prefix(want_aliases.as_slice()) {
        None => found.push("the pod's host aliases change or drop its template's".into()),
        Some(added) => {
            let mut named: Vec<&str> = Vec::new();
            for alias in added {
                let host = match alias.hostnames.as_deref() {
                    Some([host]) => host.as_str(),
                    _ => {
                        found.push("a host alias the canary adds names other than one host".into());
                        continue;
                    }
                };
                if !names.contains(&host)
                    || named.contains(&host)
                    || alias.ip.parse::<Ipv4Addr>().is_err()
                {
                    found.push(format!(
                        "the canary adds the host alias {} → {host}, where it may add one for each of {names:?}, at an \
                         IPv4 address",
                        alias.ip
                    ));
                }
                named.push(host);
            }
        }
    }
    found
}

fn container_departs(fetch: &Container, got: &Container, found: &mut Vec<String>) {
    let expected = Container {
        env: None,
        ..canary_container(
            fetch,
            &Probe {
                reach: vec![],
                unreachable: vec![],
                aliases: vec![],
            },
        )
    };
    let compared = Container {
        env: None,
        ..got.clone()
    };
    if to_value(&expected) != to_value(&compared) {
        found.push(format!(
            "the canary's container departs from the probe the fetch's image runs in {}",
            differing(&to_value(&expected), &to_value(&compared)).join(", ")
        ));
    }
    let env = got.env.clone().unwrap_or_default();
    let names: Vec<&str> = env.iter().map(|e| e.name.as_str()).collect();
    if names != [REACH_VAR, UNREACHABLE_VAR] || env.iter().any(|e| e.value_from.is_some()) {
        found.push(format!(
            "the canary is told {names:?}, where it may be told only {REACH_VAR} and {UNREACHABLE_VAR}, as plain values"
        ));
    }
}

/// The last proof, shared by every build: a build is made only while a successful one is younger than the bound, and
/// one proof runs at a time, so that builds arriving together wait for the same canary.
#[derive(Default)]
pub struct Enforcement {
    last: tokio::sync::Mutex<Option<(Instant, Result<(), String>)>>,
}

impl Enforcement {
    /// Ok while a proof younger than `max_age` succeeded; otherwise runs `prove`, keeps what it said, and says it. A
    /// failed proof is never taken as standing: the next asks again.
    pub async fn proved<F, Fut>(&self, max_age: Duration, prove: F) -> Result<(), String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), String>>,
    {
        let mut last = self.last.lock().await;
        if let Some((at, Ok(()))) = &*last
            && at.elapsed() < max_age
        {
            return Ok(());
        }
        let said = prove().await;
        *last = Some((Instant::now(), said.clone()));
        said
    }

    /// What the last proof said, and how long ago, if there has been one.
    pub async fn last(&self) -> Option<(Duration, Result<(), String>)> {
        self.last
            .lock()
            .await
            .as_ref()
            .map(|(at, said)| (at.elapsed(), said.clone()))
    }
}

/// The `host:port` a registry's address (`http(s)://host[:port]`) is reached at, its port the scheme's when it names
/// none; None for a value that is not a registry's address.
pub fn registry_authority(registry: &str) -> Option<(String, u16)> {
    let (rest, default_port) = if let Some(rest) = registry.strip_prefix("http://") {
        (rest, 80)
    } else {
        (registry.strip_prefix("https://")?, 443)
    };
    let authority = rest.split('/').next()?;
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, default_port),
    };
    (!host.is_empty()).then(|| (host.to_string(), port))
}

/// The host of a `host:port`, and whether it is a name, which a canary must be given an address for.
pub fn name_of(address: &str) -> Option<&str> {
    let (host, _) = address.rsplit_once(':')?;
    (host.parse::<Ipv4Addr>().is_err() && !host.is_empty()).then_some(host)
}

/// The aliases a probe's names have, given each its address.
pub fn aliases(names: &[(String, Ipv4Addr)]) -> Vec<HostAlias> {
    names.iter().map(|(h, a)| registry_alias(h, *a)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{build_job, departures};
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const FETCH_IMAGE: &str = "localhost:30500/build-fetch@sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const REGISTRY: &str = "registry.polar-registry.svc.cluster.local";

    fn template() -> PodTemplate {
        serde_json::from_value(json!({
            "metadata": {"name": "build-runner"},
            "template": {
                "metadata": {"labels": {"name": "build-runner"}},
                "spec": {
                    "automountServiceAccountToken": false,
                    "nodeSelector": {"polar.dev/pool": "observers"},
                    "restartPolicy": "Never",
                    "serviceAccountName": "build-runner",
                    "initContainers": [{"name": "fetch", "image": FETCH_IMAGE, "imagePullPolicy": "Always",
                        "env": [{"name": "CYCLOPS_WORKSPACE", "value": "/workspace"}],
                        "securityContext": {"runAsUser": 1000, "runAsGroup": 1000},
                        "volumeMounts": [{"name": "workspace", "mountPath": "/workspace"}]}],
                    "containers": [{"name": "pipeline", "image": FETCH_IMAGE, "imagePullPolicy": "Always",
                        "volumeMounts": [{"name": "workspace", "mountPath": "/workspace"}]}],
                    "volumes": [{"name": "workspace", "emptyDir": {}}]
                }
            }
        }))
        .unwrap()
    }

    fn probe() -> Probe {
        Probe {
            reach: vec![format!("{REGISTRY}:5000")],
            unreachable: vec!["10.96.0.1:443".into(), "github.com:443".into()],
            aliases: vec![
                (REGISTRY.into(), Ipv4Addr::new(10, 96, 97, 171)),
                ("github.com".into(), Ipv4Addr::new(140, 82, 112, 3)),
            ],
        }
    }

    fn names() -> [&'static str; 2] {
        [REGISTRY, "github.com"]
    }

    fn canary() -> Job {
        canary_job(
            &template(),
            &JobOptions::new("polar-builds", "build-runner"),
            &probe(),
            Uuid::nil(),
        )
        .unwrap()
    }

    fn pod(job: &mut Job) -> &mut k8s_openapi::api::core::v1::PodSpec {
        job.spec.as_mut().unwrap().template.spec.as_mut().unwrap()
    }

    #[test]
    fn a_canary_is_its_template_s_pod_running_the_probe_and_departs_nowhere() {
        let mut job = canary();
        assert!(
            canary_departures(&template(), &job, &names()).is_empty(),
            "{:?}",
            canary_departures(&template(), &job, &names())
        );
        let pod = pod(&mut job);
        assert!(pod.init_containers.is_none());
        let c = &pod.containers[0];
        assert_eq!(c.image.as_deref(), Some(FETCH_IMAGE));
        assert_eq!(
            c.command.clone().unwrap(),
            vec!["build-fetch", "--probe-network"]
        );
        assert_eq!(pod.host_aliases.as_ref().unwrap().len(), 2);
        assert_eq!(
            pod.node_selector.as_ref().unwrap()["polar.dev/pool"],
            "observers",
            "where builds run"
        );
    }

    #[test]
    fn a_canary_is_told_from_a_build_and_never_adopted_as_one() {
        let job = canary();
        let labels = job.metadata.labels.unwrap();
        assert_eq!(labels["cyclops.build/type"], CANARY_TYPE);
        assert!(
            job.metadata
                .name
                .unwrap()
                .starts_with("build-runner-canary-")
        );
    }

    #[test]
    fn every_change_a_canary_may_not_make_is_found() {
        type Change = Box<dyn Fn(&mut Job)>;
        let changes: Vec<(&str, Change)> = vec![
            (
                "another image",
                Box::new(|j| pod(j).containers[0].image = Some("evil@sha256:00".into())),
            ),
            (
                "another command",
                Box::new(|j| pod(j).containers[0].command = Some(vec!["sh".into()])),
            ),
            (
                "more settings",
                Box::new(|j| {
                    pod(j).containers[0]
                        .env
                        .as_mut()
                        .unwrap()
                        .push(plain("TOKEN", "x"))
                }),
            ),
            (
                "a second container",
                Box::new(|j| {
                    let c = pod(j).containers[0].clone();
                    pod(j).containers.push(c)
                }),
            ),
            (
                "an init container",
                Box::new(|j| {
                    let c = pod(j).containers[0].clone();
                    pod(j).init_containers = Some(vec![c])
                }),
            ),
            (
                "privileged",
                Box::new(|j| {
                    pod(j).containers[0]
                        .security_context
                        .as_mut()
                        .unwrap()
                        .privileged = Some(true)
                }),
            ),
            (
                "another node",
                Box::new(|j| {
                    pod(j).node_selector = Some(BTreeMap::from([("pool".into(), "core".into())]))
                }),
            ),
            (
                "the host's network",
                Box::new(|j| pod(j).host_network = Some(true)),
            ),
            (
                "an alias to another name",
                Box::new(|j| {
                    pod(j).host_aliases.as_mut().unwrap()[0].hostnames =
                        Some(vec!["kubernetes.default".into()])
                }),
            ),
            (
                "an alias that is no IPv4 address",
                Box::new(|j| pod(j).host_aliases.as_mut().unwrap()[0].ip = "fd00::1".into()),
            ),
            (
                "a name aliased twice",
                Box::new(|j| {
                    let a = pod(j).host_aliases.as_ref().unwrap()[0].clone();
                    pod(j).host_aliases.as_mut().unwrap().push(a)
                }),
            ),
            (
                "a host volume",
                Box::new(|j| {
                    pod(j).volumes.as_mut().unwrap().push(
                        serde_json::from_value(json!({"name": "h", "hostPath": {"path": "/"}}))
                            .unwrap(),
                    )
                }),
            ),
        ];
        for (what, change) in changes {
            let mut job = canary();
            change(&mut job);
            assert!(
                !canary_departures(&template(), &job, &names()).is_empty(),
                "{what} was not found"
            );
        }
    }

    #[test]
    fn a_build_s_job_is_no_canary_and_a_canary_is_no_build() {
        let canary = canary();
        assert!(
            !departures(&template(), &canary, &Privileges::default(), Some(REGISTRY)).is_empty()
        );
        let spec = orchestrator_core::types::BuildSpec::with_pipeline_runner(
            Uuid::nil(),
            orchestrator_core::types::SourceRef::Git {
                url: "https://e.test/r.git".into(),
                commit_sha: "a".repeat(40),
            },
            orchestrator_core::types::SourceArchive::new(format!(
                "localhost:30500/build-sources@sha256:{}",
                "0".repeat(64)
            ))
            .unwrap(),
            format!("registry.example.com/pipeline@sha256:{}", "0".repeat(64)),
            vec![],
            Privileges::default(),
        );
        let build = build_job(
            &template(),
            &spec,
            &JobOptions::new("polar-builds", "build-runner"),
        )
        .unwrap();
        assert!(!canary_departures(&template(), &build, &names()).is_empty());
    }

    #[test]
    fn a_registry_is_reached_at_its_host_and_port() {
        assert_eq!(
            registry_authority("http://registry.polar-registry.svc.cluster.local:5000"),
            Some((REGISTRY.into(), 5000))
        );
        assert_eq!(
            registry_authority("https://r.example.com"),
            Some(("r.example.com".into(), 443))
        );
        assert_eq!(
            registry_authority("http://10.0.2.2:5000/v2"),
            Some(("10.0.2.2".into(), 5000))
        );
        assert_eq!(registry_authority("registry:5000"), None);
        assert_eq!(name_of("github.com:443"), Some("github.com"));
        assert_eq!(name_of("10.96.0.1:443"), None);
    }

    #[tokio::test]
    async fn a_fresh_proof_stands_and_a_stale_or_failed_one_is_proved_again() {
        let e = Enforcement::default();
        let runs = Arc::new(AtomicUsize::new(0));
        let ok = |r: Arc<AtomicUsize>| {
            move || {
                r.fetch_add(1, Ordering::SeqCst);
                async { Ok(()) }
            }
        };
        assert!(
            e.proved(Duration::from_secs(60), ok(runs.clone()))
                .await
                .is_ok()
        );
        assert!(
            e.proved(Duration::from_secs(60), ok(runs.clone()))
                .await
                .is_ok()
        );
        assert_eq!(runs.load(Ordering::SeqCst), 1, "fresh: proved once");
        assert!(e.proved(Duration::ZERO, ok(runs.clone())).await.is_ok());
        assert_eq!(runs.load(Ordering::SeqCst), 2, "stale: proved again");
        let failed = e
            .proved(Duration::ZERO, || async {
                Err("reached 1.1.1.1:443".to_string())
            })
            .await;
        assert_eq!(failed, Err("reached 1.1.1.1:443".to_string()));
        assert!(
            e.proved(Duration::from_secs(60), ok(runs.clone()))
                .await
                .is_ok()
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            3,
            "a failure does not stand: the next asks again"
        );
    }

    #[tokio::test]
    async fn builds_arriving_together_wait_for_one_canary() {
        let e = Arc::new(Enforcement::default());
        let runs = Arc::new(AtomicUsize::new(0));
        let mut waiting = Vec::new();
        for _ in 0..5 {
            let (e, runs) = (Arc::clone(&e), Arc::clone(&runs));
            waiting.push(tokio::spawn(async move {
                e.proved(Duration::from_secs(60), || async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok(())
                })
                .await
            }));
        }
        for w in waiting {
            assert!(w.await.unwrap().is_ok());
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }
}
