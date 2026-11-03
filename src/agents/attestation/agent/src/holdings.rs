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

//! What the attestation agent holds of the cluster, kept current by its watches, and the facts about a pod it reads from that
//! (docs/architecture/runtime-attestation.md, "Slice A"): an answer is read from here, not a call to the API. A platform's backend, in
//! the plan's terms: nothing Kubernetes-specific goes further than this file and the watches.

use attestation_common::{ContainerFacts, Deployed, Owner, OwnerKind, PodFacts};
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::{Pod, PodTemplateSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A change one watch saw. `watch` names it, and its namespace.
#[derive(Debug, Clone)]
pub enum Change {
    /// It is listing again: what it said before does not stand until it has finished.
    Relisting {
        watch: Watch,
    },
    /// It has finished listing.
    Listed {
        watch: Watch,
    },
    /// It lost the API, and will try again: what it said may be stale.
    Lost {
        watch: Watch,
    },
    Applied(Box<Object>),
    Deleted(Box<Object>),
}

/// One kind of object in one namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Watch {
    pub kind: Kind,
    pub namespace: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Pod,
    ReplicaSet,
    Deployment,
    StatefulSet,
    Job,
}

impl Kind {
    pub const ALL: [Kind; 5] = [
        Kind::Pod,
        Kind::ReplicaSet,
        Kind::Deployment,
        Kind::StatefulSet,
        Kind::Job,
    ];
}

/// An object a watch delivers.
#[derive(Debug, Clone)]
pub enum Object {
    Pod(Pod),
    ReplicaSet(ReplicaSet),
    Deployment(Deployment),
    StatefulSet(StatefulSet),
    Job(Job),
}

/// All of what it holds. It is `ready` only while every watch has listed and has not lost the API since: until then a pod it has not
/// seen may exist, so nothing it does not hold can be called absent.
#[derive(Debug, Default)]
pub struct Holdings {
    expected: BTreeSet<Watch>,
    listed: BTreeSet<Watch>,
    pods: HashMap<String, HeldPod>,
    owners: HashMap<(Kind, String, String), HeldOwner>,
}

#[derive(Debug, Clone)]
struct HeldPod {
    namespace: String,
    service_account: String,
    owner: Option<OwnerReference>,
    containers: Vec<ContainerFacts>,
    ephemeral: Vec<String>,
}

#[derive(Debug, Clone)]
struct HeldOwner {
    uid: String,
    /// A ReplicaSet's Deployment.
    parent: Option<OwnerReference>,
    pins: BTreeMap<String, String>,
}

impl Holdings {
    /// Holdings that expect a watch of every kind in each of `namespaces`.
    pub fn new(namespaces: &[String]) -> Self {
        let mut held = Holdings::default();
        for namespace in namespaces {
            for kind in Kind::ALL {
                held.expected.insert(Watch {
                    kind,
                    namespace: namespace.clone(),
                });
            }
        }
        held
    }

    pub fn ready(&self) -> bool {
        self.expected.is_subset(&self.listed)
    }

    pub fn apply(&mut self, change: Change) {
        match change {
            Change::Relisting { watch } => {
                self.listed.remove(&watch);
                self.forget(&watch);
            }
            Change::Listed { watch } => {
                self.listed.insert(watch);
            }
            Change::Lost { watch } => {
                self.listed.remove(&watch);
            }
            Change::Applied(object) => self.hold(*object),
            Change::Deleted(object) => self.release(&object),
        }
    }

    /// The facts about the pod with this UID, or None if it holds no such pod.
    pub fn facts_of(&self, uid: &str) -> Option<PodFacts> {
        let pod = self.pods.get(uid)?;
        Some(PodFacts {
            service_account: pod.service_account.clone(),
            owner: pod.owner.as_ref().and_then(|r| self.owner_of(pod, r)),
            containers: pod.containers.clone(),
            ephemeral: pod.ephemeral.clone(),
        })
    }

    /// What each Deployment and StatefulSet it holds pins, to hold to the record. A Job finishes and goes, so it is not among them.
    pub fn deployed(&self) -> Vec<Deployed> {
        self.owners
            .iter()
            .filter_map(|((kind, namespace, name), held)| {
                let kind = match kind {
                    Kind::Deployment => OwnerKind::Deployment,
                    Kind::StatefulSet => OwnerKind::StatefulSet,
                    _ => return None,
                };
                Some(Deployed {
                    kind,
                    namespace: namespace.clone(),
                    name: name.clone(),
                    pins: held.pins.clone(),
                })
            })
            .collect()
    }

    /// Follows a pod's owner up to the workload, each step by the UID the owner really has, since anyone who can make a pod can write a
    /// name into its `ownerReferences`. The pins are the nearest owner's.
    fn owner_of(&self, pod: &HeldPod, reference: &OwnerReference) -> Option<Owner> {
        let found = |kind, reference: &OwnerReference| {
            self.owners
                .get(&(kind, pod.namespace.clone(), reference.name.clone()))
                .filter(|held| held.uid == reference.uid)
        };
        let owner = |kind, reference: &OwnerReference, pins: &BTreeMap<String, String>| Owner {
            kind,
            name: reference.name.clone(),
            pins: pins.clone(),
        };
        match reference.kind.as_str() {
            "ReplicaSet" => {
                let replica_set = found(Kind::ReplicaSet, reference)?;
                let parent = replica_set
                    .parent
                    .as_ref()
                    .filter(|parent| parent.kind == "Deployment")?;
                found(Kind::Deployment, parent)?;
                Some(owner(OwnerKind::Deployment, parent, &replica_set.pins))
            }
            "StatefulSet" => found(Kind::StatefulSet, reference)
                .map(|held| owner(OwnerKind::StatefulSet, reference, &held.pins)),
            "Job" => {
                found(Kind::Job, reference).map(|held| owner(OwnerKind::Job, reference, &held.pins))
            }
            _ => None,
        }
    }

    fn hold(&mut self, object: Object) {
        match object {
            Object::Pod(pod) => {
                if let Some(uid) = pod.metadata.uid.clone() {
                    self.pods.insert(uid, held_pod(&pod));
                }
            }
            Object::ReplicaSet(o) => {
                let template = o.spec.as_ref().and_then(|s| s.template.as_ref());
                self.hold_owner(Kind::ReplicaSet, &o.metadata, template);
            }
            Object::Deployment(o) => {
                self.hold_owner(
                    Kind::Deployment,
                    &o.metadata,
                    o.spec.as_ref().map(|s| &s.template),
                );
            }
            Object::StatefulSet(o) => {
                self.hold_owner(
                    Kind::StatefulSet,
                    &o.metadata,
                    o.spec.as_ref().map(|s| &s.template),
                );
            }
            Object::Job(o) => {
                self.hold_owner(Kind::Job, &o.metadata, o.spec.as_ref().map(|s| &s.template));
            }
        }
    }

    fn hold_owner(
        &mut self,
        kind: Kind,
        metadata: &ObjectMeta,
        template: Option<&PodTemplateSpec>,
    ) {
        let (Some(namespace), Some(name), Some(uid)) =
            (&metadata.namespace, &metadata.name, &metadata.uid)
        else {
            return;
        };
        self.owners.insert(
            (kind, namespace.clone(), name.clone()),
            HeldOwner {
                uid: uid.clone(),
                parent: controller_of(metadata),
                pins: template.map(pins_of).unwrap_or_default(),
            },
        );
    }

    fn release(&mut self, object: &Object) {
        let (kind, metadata) = match object {
            Object::Pod(o) => {
                if let Some(uid) = &o.metadata.uid {
                    self.pods.remove(uid);
                }
                return;
            }
            Object::ReplicaSet(o) => (Kind::ReplicaSet, &o.metadata),
            Object::Deployment(o) => (Kind::Deployment, &o.metadata),
            Object::StatefulSet(o) => (Kind::StatefulSet, &o.metadata),
            Object::Job(o) => (Kind::Job, &o.metadata),
        };
        if let (Some(namespace), Some(name)) = (&metadata.namespace, &metadata.name) {
            self.owners.remove(&(kind, namespace.clone(), name.clone()));
        }
    }

    fn forget(&mut self, watch: &Watch) {
        if watch.kind == Kind::Pod {
            self.pods.retain(|_, pod| pod.namespace != watch.namespace);
        } else {
            self.owners.retain(|(kind, namespace, _), _| {
                (*kind, namespace) != (watch.kind, &watch.namespace)
            });
        }
    }
}

fn controller_of(metadata: &ObjectMeta) -> Option<OwnerReference> {
    metadata
        .owner_references
        .iter()
        .flatten()
        .find(|r| r.controller == Some(true))
        .cloned()
}

fn pins_of(template: &PodTemplateSpec) -> BTreeMap<String, String> {
    let Some(spec) = &template.spec else {
        return BTreeMap::new();
    };
    spec.init_containers
        .iter()
        .flatten()
        .chain(&spec.containers)
        .filter_map(|c| Some((c.name.clone(), c.image.clone()?)))
        .collect()
}

fn held_pod(pod: &Pod) -> HeldPod {
    let empty = Default::default();
    let spec = pod.spec.as_ref().unwrap_or(&empty);
    let statuses: HashMap<&str, &str> = pod
        .status
        .iter()
        .flat_map(|status| {
            status
                .init_container_statuses
                .iter()
                .flatten()
                .chain(status.container_statuses.iter().flatten())
        })
        .map(|c| (c.name.as_str(), c.image_id.as_str()))
        .collect();
    HeldPod {
        namespace: pod.metadata.namespace.clone().unwrap_or_default(),
        service_account: spec.service_account_name.clone().unwrap_or_default(),
        owner: controller_of(&pod.metadata),
        containers: spec
            .init_containers
            .iter()
            .flatten()
            .chain(&spec.containers)
            .map(|c| ContainerFacts {
                name: c.name.clone(),
                image: c.image.clone().unwrap_or_default(),
                // Kubernetes reports an empty imageID for a container that has not started.
                image_id: statuses
                    .get(c.name.as_str())
                    .filter(|id| !id.is_empty())
                    .map(|id| id.to_string()),
            })
            .collect(),
        ephemeral: spec
            .ephemeral_containers
            .iter()
            .flatten()
            .map(|c| c.name.clone())
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NS: &str = "polar";

    fn digest(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    fn image(c: char) -> String {
        format!("registry:5000/image:latest@{}", digest(c))
    }

    fn running(c: char) -> String {
        format!("registry:5000/image@{}", digest(c))
    }

    /// A template with a sidecar, polar-init and the workload.
    fn template(sidecar: char, init: char, main: char) -> serde_json::Value {
        json!({ "spec": {
            "initContainers": [
                { "name": "polar-custody", "image": image(sidecar), "restartPolicy": "Always" },
                { "name": "polar-init", "image": image(init) },
            ],
            "containers": [ { "name": "main", "image": image(main) } ],
        }})
    }

    fn replica_set(name: &str, uid: &str, deployment: &str, deployment_uid: &str) -> Object {
        Object::ReplicaSet(
            serde_json::from_value(json!({
                "metadata": {
                    "name": name, "namespace": NS, "uid": uid,
                    "ownerReferences": [{
                        "apiVersion": "apps/v1", "kind": "Deployment", "name": deployment, "uid": deployment_uid,
                        "controller": true,
                    }],
                },
                "spec": { "selector": {}, "template": template('a', 'b', 'c') },
            }))
            .unwrap(),
        )
    }

    fn deployment(name: &str, uid: &str) -> Object {
        Object::Deployment(
            serde_json::from_value(json!({
                "metadata": { "name": name, "namespace": NS, "uid": uid },
                "spec": { "selector": {}, "template": template('a', 'b', 'c') },
            }))
            .unwrap(),
        )
    }

    /// A pod of `owner_kind`/`owner_name`, still in polar-init: the workload's container has no imageID yet.
    fn pod(uid: &str, owner_kind: &str, owner_name: &str, owner_uid: &str) -> serde_json::Value {
        json!({
            "metadata": {
                "name": "the-pod", "namespace": NS, "uid": uid,
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": owner_kind, "name": owner_name, "uid": owner_uid, "controller": true,
                }],
            },
            "spec": {
                "serviceAccountName": "the-account",
                "initContainers": [
                    { "name": "polar-custody", "image": image('a') },
                    { "name": "polar-init", "image": image('b') },
                ],
                "containers": [ { "name": "main", "image": image('c') } ],
            },
            "status": {
                "initContainerStatuses": [
                    { "name": "polar-custody", "image": image('a'), "imageID": running('a'), "ready": true, "restartCount": 0 },
                    { "name": "polar-init", "image": image('b'), "imageID": running('b'), "ready": false, "restartCount": 0 },
                ],
                "containerStatuses": [
                    { "name": "main", "image": image('c'), "imageID": "", "ready": false, "restartCount": 0 },
                ],
            },
        })
    }

    fn pod_object(value: serde_json::Value) -> Object {
        Object::Pod(serde_json::from_value(value).unwrap())
    }

    fn holdings(objects: Vec<Object>) -> Holdings {
        let mut held = Holdings::new(&[NS.to_string()]);
        for object in objects {
            held.apply(Change::Applied(Box::new(object)));
        }
        held
    }

    #[test]
    fn what_is_deployed_is_its_deployments_and_not_what_they_roll_out_through() {
        let mut held = Holdings::default();
        held.apply(Change::Applied(Box::new(deployment("the-app", "d1"))));
        held.apply(Change::Applied(Box::new(replica_set(
            "the-app-1",
            "r1",
            "the-app",
            "d1",
        ))));
        let deployed = held.deployed();
        assert_eq!(deployed.len(), 1);
        assert_eq!(deployed[0].kind, OwnerKind::Deployment);
        assert_eq!(deployed[0].name, "the-app");
    }

    #[test]
    fn a_deployments_pod_is_followed_to_the_deployment_with_its_replica_sets_pins() {
        let held = holdings(vec![
            deployment("the-app", "d1"),
            replica_set("the-app-abc", "r1", "the-app", "d1"),
            pod_object(pod("p1", "ReplicaSet", "the-app-abc", "r1")),
        ]);
        let facts = held.facts_of("p1").unwrap();
        assert_eq!(facts.service_account, "the-account");
        let owner = facts.owner.unwrap();
        assert_eq!(owner.kind, OwnerKind::Deployment);
        assert_eq!(owner.name, "the-app");
        assert_eq!(owner.pins["polar-custody"], image('a'));
        assert_eq!(owner.pins["polar-init"], image('b'));
        assert_eq!(owner.pins["main"], image('c'));
    }

    #[test]
    fn every_container_is_there_and_one_that_has_not_started_has_no_image_id() {
        let held = holdings(vec![
            deployment("the-app", "d1"),
            replica_set("the-app-abc", "r1", "the-app", "d1"),
            pod_object(pod("p1", "ReplicaSet", "the-app-abc", "r1")),
        ]);
        let mut containers = held.facts_of("p1").unwrap().containers;
        containers.sort_by(|a, b| a.name.cmp(&b.name));
        let names: Vec<&str> = containers.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["main", "polar-custody", "polar-init"]);
        assert_eq!(containers[0].image_id, None, "an empty imageID is none");
        assert_eq!(containers[1].image_id, Some(running('a')));
    }

    #[test]
    fn a_replica_set_of_the_old_revision_gives_its_own_pins_while_the_deployment_has_moved_on() {
        let mut new = deployment("the-app", "d1");
        if let Object::Deployment(d) = &mut new {
            d.spec.as_mut().unwrap().template =
                serde_json::from_value(template('x', 'y', 'z')).unwrap();
        }
        let held = holdings(vec![
            new,
            replica_set("the-app-old", "r1", "the-app", "d1"),
            pod_object(pod("p1", "ReplicaSet", "the-app-old", "r1")),
        ]);
        assert_eq!(
            held.facts_of("p1").unwrap().owner.unwrap().pins["main"],
            image('c')
        );
    }

    #[test]
    fn an_owner_reference_with_another_uid_is_no_owner() {
        // Anyone who can make a pod can write a name into its ownerReferences; the UID is what the owner really has.
        let held = holdings(vec![
            deployment("the-app", "d1"),
            replica_set("the-app-abc", "r1", "the-app", "d1"),
            pod_object(pod("p1", "ReplicaSet", "the-app-abc", "forged")),
        ]);
        assert_eq!(held.facts_of("p1").unwrap().owner, None);
    }

    #[test]
    fn a_replica_set_no_deployment_owns_gives_no_owner() {
        let orphan = Object::ReplicaSet(
            serde_json::from_value(json!({
                "metadata": { "name": "by-hand", "namespace": NS, "uid": "r9" },
                "spec": { "selector": {}, "template": template('a', 'b', 'c') },
            }))
            .unwrap(),
        );
        let held = holdings(vec![
            orphan,
            pod_object(pod("p1", "ReplicaSet", "by-hand", "r9")),
        ]);
        assert_eq!(held.facts_of("p1").unwrap().owner, None);
    }

    #[test]
    fn a_pod_with_no_owner_has_none_and_an_unknown_uid_is_no_pod() {
        let mut bare = pod("p1", "ReplicaSet", "x", "y");
        bare["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("ownerReferences");
        let held = holdings(vec![pod_object(bare)]);
        assert_eq!(held.facts_of("p1").unwrap().owner, None);
        assert!(held.facts_of("nope").is_none());
    }

    #[test]
    fn a_statefulset_and_a_job_are_their_own_workloads() {
        let set = Object::StatefulSet(
            serde_json::from_value(json!({
                "metadata": { "name": "the-db", "namespace": NS, "uid": "s1" },
                "spec": { "selector": {}, "serviceName": "x", "template": template('a', 'b', 'c') },
            }))
            .unwrap(),
        );
        let job = Object::Job(
            serde_json::from_value(json!({
                "metadata": { "name": "the-job-1", "namespace": NS, "uid": "j1" },
                "spec": { "template": template('a', 'b', 'c') },
            }))
            .unwrap(),
        );
        let held = holdings(vec![
            set,
            job,
            pod_object(pod("p1", "StatefulSet", "the-db", "s1")),
            pod_object(pod("p2", "Job", "the-job-1", "j1")),
        ]);
        let first = held.facts_of("p1").unwrap().owner.unwrap();
        assert_eq!(
            (first.kind, first.name.as_str()),
            (OwnerKind::StatefulSet, "the-db")
        );
        let second = held.facts_of("p2").unwrap().owner.unwrap();
        assert_eq!(
            (second.kind, second.name.as_str()),
            (OwnerKind::Job, "the-job-1")
        );
    }

    #[test]
    fn an_owner_in_another_namespace_is_not_this_pods() {
        let held = holdings(vec![
            Object::Deployment(
                serde_json::from_value(json!({
                    "metadata": { "name": "the-app", "namespace": "elsewhere", "uid": "d1" },
                    "spec": { "selector": {}, "template": template('a', 'b', 'c') },
                }))
                .unwrap(),
            ),
            Object::ReplicaSet(
                serde_json::from_value(json!({
                    "metadata": {
                        "name": "the-app-abc", "namespace": "elsewhere", "uid": "r1",
                        "ownerReferences": [{
                            "apiVersion": "apps/v1", "kind": "Deployment", "name": "the-app", "uid": "d1", "controller": true,
                        }],
                    },
                    "spec": { "selector": {}, "template": template('a', 'b', 'c') },
                }))
                .unwrap(),
            ),
            pod_object(pod("p1", "ReplicaSet", "the-app-abc", "r1")),
        ]);
        assert_eq!(held.facts_of("p1").unwrap().owner, None);
    }

    #[test]
    fn an_ephemeral_container_is_seen() {
        let mut debugged = pod("p1", "ReplicaSet", "x", "y");
        debugged["spec"]["ephemeralContainers"] =
            json!([{ "name": "debugger", "image": "busybox" }]);
        let held = holdings(vec![pod_object(debugged)]);
        assert_eq!(held.facts_of("p1").unwrap().ephemeral, ["debugger"]);
    }

    #[test]
    fn a_deleted_pod_is_gone() {
        let mut held = holdings(vec![pod_object(pod("p1", "ReplicaSet", "x", "y"))]);
        held.apply(Change::Deleted(Box::new(pod_object(pod(
            "p1",
            "ReplicaSet",
            "x",
            "y",
        )))));
        assert!(held.facts_of("p1").is_none());
    }

    fn every_watch(namespaces: &[&str]) -> Vec<Watch> {
        namespaces
            .iter()
            .flat_map(|n| {
                Kind::ALL.map(|kind| Watch {
                    kind,
                    namespace: n.to_string(),
                })
            })
            .collect()
    }

    #[test]
    fn it_is_ready_only_when_every_watch_has_listed() {
        let namespaces = ["polar", "polar-graph"];
        let mut held = Holdings::new(&namespaces.map(String::from));
        assert!(!held.ready());
        let mut watches = every_watch(&namespaces);
        let last = watches.pop().unwrap();
        for watch in watches {
            held.apply(Change::Listed { watch });
            assert!(!held.ready());
        }
        held.apply(Change::Listed { watch: last });
        assert!(held.ready());
    }

    #[test]
    fn losing_the_api_or_listing_again_means_it_cannot_call_anything_absent() {
        let mut held = Holdings::new(&[NS.to_string()]);
        for watch in every_watch(&[NS]) {
            held.apply(Change::Listed { watch });
        }
        assert!(held.ready());
        let pods = Watch {
            kind: Kind::Pod,
            namespace: NS.to_string(),
        };
        held.apply(Change::Lost {
            watch: pods.clone(),
        });
        assert!(!held.ready());
        held.apply(Change::Listed {
            watch: pods.clone(),
        });
        assert!(held.ready());
        held.apply(Change::Relisting { watch: pods });
        assert!(!held.ready());
    }

    /// A pod deleted while the watch was away does not stay: a relist replaces what that watch held, and no other's.
    #[test]
    fn a_relist_forgets_what_that_watch_said_and_only_that() {
        let other = Object::Pod(
            serde_json::from_value({
                let mut p = pod("p2", "ReplicaSet", "x", "y");
                p["metadata"]["namespace"] = json!("polar-graph");
                p
            })
            .unwrap(),
        );
        let mut held = holdings(vec![
            deployment("the-app", "d1"),
            pod_object(pod("p1", "ReplicaSet", "x", "y")),
            other,
        ]);
        held.apply(Change::Relisting {
            watch: Watch {
                kind: Kind::Pod,
                namespace: NS.to_string(),
            },
        });
        assert!(held.facts_of("p1").is_none());
        assert!(held.facts_of("p2").is_some());
    }
}
