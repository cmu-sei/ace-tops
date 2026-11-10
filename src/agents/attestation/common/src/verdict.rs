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

//! Whether an instance is what the deployment made (docs/architecture/runtime-attestation.md, "The instance check at
//! issuance").
//!
//! A pod is judged against its owner, which pins each container's image by digest. The owner is the one nearest the pod, a
//! ReplicaSet for a Deployment's pod and not the Deployment: an old pod restarted in place during a rollout is the old
//! revision's, and is genuine until it is gone. Whether a Deployment pins what the signed record says is a separate check.
//!
//! `polar-init` asks before the workload's container has started, so a container may have no `imageID` yet. Its image in
//! the pod's spec is judged now, and the `imageID` of each container that has one.

use rkyv::{Archive, Deserialize, Serialize};
use std::collections::BTreeMap;

/// What kind of thing owns a workload's pods.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize, serde::Deserialize,
)]
pub enum OwnerKind {
    Deployment,
    StatefulSet,
    Job,
}

/// A container of a pod, an init container and a sidecar included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerFacts {
    pub name: String,
    /// The image the pod's spec names.
    pub image: String,
    /// The kubelet's `imageID`: what is really running. None until the container has started.
    pub image_id: Option<String>,
    /// How its spec makes it run.
    pub hardening: Hardening,
}

/// How a container is made to run (docs/architecture/runtime-attestation.md, slice C, C1): a read-only root
/// (`readOnlyRootFilesystem`), no privilege escalation (`allowPrivilegeEscalation: false`, so `NoNewPrivs`), and a seccomp
/// profile that confines it (`RuntimeDefault` or `Localhost`, on the container or else the pod). The signed record says
/// what each container was rendered with, and a pod or a workload with less than that is not what the deployment made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hardening {
    pub read_only_root: bool,
    pub no_privilege_escalation: bool,
    pub confined_seccomp: bool,
}

impl Hardening {
    /// Every setting on, as Polar renders its own containers.
    pub const FULL: Hardening = Hardening {
        read_only_root: true,
        no_privilege_escalation: true,
        confined_seccomp: true,
    };

    /// The settings `wanted` has and this has not, by name, in a fixed order; none when this is as strong.
    pub fn lacks(&self, wanted: &Hardening) -> Vec<&'static str> {
        [
            (
                wanted.read_only_root && !self.read_only_root,
                "a read-only root",
            ),
            (
                wanted.no_privilege_escalation && !self.no_privilege_escalation,
                "no privilege escalation",
            ),
            (
                wanted.confined_seccomp && !self.confined_seccomp,
                "a seccomp profile",
            ),
        ]
        .into_iter()
        .filter_map(|(lacking, name)| lacking.then_some(name))
        .collect()
    }
}

/// What owns a pod, followed up to the workload: `kind` and `name` are the workload's, and `pins` is the image of each
/// container in the pod template of the owner nearest the pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    pub kind: OwnerKind,
    pub name: String,
    pub pins: BTreeMap<String, String>,
}

/// A pod, as the platform backend sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodFacts {
    pub service_account: String,
    pub owner: Option<Owner>,
    pub containers: Vec<ContainerFacts>,
    /// The names of its ephemeral containers (`kubectl debug`).
    pub ephemeral: Vec<String>,
}

/// What the signed record says about the workload an identity runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadFacts {
    pub owner_kind: OwnerKind,
    pub owner_name: String,
    pub service_account: String,
    /// How the record says each container runs, by its name; empty for a record that does not say (before schema 3).
    pub hardening: std::collections::BTreeMap<String, Hardening>,
}

/// Why an instance is not what the deployment made.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum NotGenuine {
    /// No pod has the UID its token was bound to.
    NoSuchPod,
    /// It has no owner: a pod someone made by hand.
    NoOwner,
    /// It is owned by another workload than the identity runs as.
    AnotherOwner { expected: String, found: String },
    /// It runs as another service account than the identity's.
    AnotherServiceAccount { expected: String, found: String },
    /// A container its owner's template does not have.
    UnexpectedContainer { container: String },
    /// A container its owner's template has and it does not: a sidecar left out, say.
    MissingContainer { container: String },
    /// A container whose image its owner does not pin by digest, so nothing says what it should be.
    NotPinned { container: String },
    /// A container whose image, in the spec or as it is running, is not the digest its owner pins.
    AnotherImage {
        container: String,
        pinned: String,
        found: String,
    },
    /// An ephemeral container was added to it.
    EphemeralContainer { container: String },
    /// A container runs with less than the signed record says it was rendered with: what it lacks, named (slice C, C1).
    Weakened { container: String, lacks: String },
}

/// The answer about an instance.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum Verdict {
    Genuine,
    NotGenuine(NotGenuine),
    /// The pod holds up against its owner, but the signed record does not name the identity yet. An asker treats this as if
    /// the agent could not be asked: it issues, records that it did so unattested, and it is attested afterwards.
    CannotSay,
}

/// The digest an image reference or an `imageID` names (`sha256:` and 64 lower-case hex digits), or None if it names none.
pub fn digest_of(image: &str) -> Option<&str> {
    let (_, digest) = image.rsplit_once('@')?;
    let hex = digest.strip_prefix("sha256:")?;
    let is_hex = hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    is_hex.then_some(digest)
}

/// Judges a pod (None: no pod has the UID asked about) against what the signed record says of the identity it claims (None:
/// the record does not name it). What a pod is against its own owner is decided whatever the record says, so that an identity
/// the record does not name yet is no way round it.
pub fn judge(record: Option<&WorkloadFacts>, pod: Option<&PodFacts>) -> Verdict {
    match against_owner(pod).and_then(|(pod, owner)| against_record(record, pod, owner)) {
        Ok(verdict) => verdict,
        Err(why) => Verdict::NotGenuine(why),
    }
}

fn against_owner(pod: Option<&PodFacts>) -> Result<(&PodFacts, &Owner), NotGenuine> {
    let pod = pod.ok_or(NotGenuine::NoSuchPod)?;
    if let Some(container) = pod.ephemeral.first() {
        return Err(NotGenuine::EphemeralContainer {
            container: container.clone(),
        });
    }
    let owner = pod.owner.as_ref().ok_or(NotGenuine::NoOwner)?;
    let mut containers: Vec<&ContainerFacts> = pod.containers.iter().collect();
    containers.sort_by(|a, b| a.name.cmp(&b.name));
    for container in containers {
        check_container(owner, container)?;
    }
    if let Some(name) = owner
        .pins
        .keys()
        .find(|name| !pod.containers.iter().any(|c| &c.name == *name))
    {
        return Err(NotGenuine::MissingContainer {
            container: name.clone(),
        });
    }
    Ok((pod, owner))
}

fn check_container(owner: &Owner, container: &ContainerFacts) -> Result<(), NotGenuine> {
    let name = &container.name;
    let pinned = owner
        .pins
        .get(name)
        .ok_or_else(|| NotGenuine::UnexpectedContainer {
            container: name.clone(),
        })?;
    let digest = digest_of(pinned).ok_or_else(|| NotGenuine::NotPinned {
        container: name.clone(),
    })?;
    let running = container.image_id.iter().map(String::as_str);
    for found in std::iter::once(container.image.as_str()).chain(running) {
        if digest_of(found) != Some(digest) {
            return Err(NotGenuine::AnotherImage {
                container: name.clone(),
                pinned: digest.to_string(),
                found: found.to_string(),
            });
        }
    }
    Ok(())
}

fn against_record(
    record: Option<&WorkloadFacts>,
    pod: &PodFacts,
    owner: &Owner,
) -> Result<Verdict, NotGenuine> {
    let Some(record) = record else {
        return Ok(Verdict::CannotSay);
    };
    if owner.kind != record.owner_kind || !names_its_workload(record, &owner.name) {
        return Err(NotGenuine::AnotherOwner {
            expected: format!("{:?}/{}", record.owner_kind, record.owner_name),
            found: format!("{:?}/{}", owner.kind, owner.name),
        });
    }
    if pod.service_account != record.service_account {
        return Err(NotGenuine::AnotherServiceAccount {
            expected: record.service_account.clone(),
            found: pod.service_account.clone(),
        });
    }
    let mut containers: Vec<&ContainerFacts> = pod.containers.iter().collect();
    containers.sort_by(|a, b| a.name.cmp(&b.name));
    for container in containers {
        if let Some(wanted) = record.hardening.get(&container.name) {
            let lacks = container.hardening.lacks(wanted);
            if !lacks.is_empty() {
                return Err(NotGenuine::Weakened {
                    container: container.name.clone(),
                    lacks: lacks.join(", "),
                });
            }
        }
    }
    Ok(Verdict::Genuine)
}

/// A harness run's Jobs are copies of the workload's, named after it (`infra/load-harness.nu`), so a Job is its workload's by
/// that prefix. A Deployment or a StatefulSet has the workload's own name.
fn names_its_workload(record: &WorkloadFacts, name: &str) -> bool {
    name == record.owner_name
        || (record.owner_kind == OwnerKind::Job
            && name
                .strip_prefix(record.owner_name.as_str())
                .is_some_and(|rest| rest.starts_with('-')))
}
