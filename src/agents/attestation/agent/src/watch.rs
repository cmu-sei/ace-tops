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

//! One watch of one kind in one namespace, as the operation the agent declares: its request and what it reads of each change. The stream is
//! the protocol handler's. Its ending or failing means what it said may be stale, so the supervisor marks that and asks again, and the
//! new one starts from a list, rather than assume a resumed stream missed nothing.

use crate::holdings::{Change, Kind, Object, Watch};
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Pod;
use polar_agent_builder::protocol::kubernetes::{self, Kubernetes, Resource};
use polar_agent_builder::protocol::{
    Access, Location, Operation, OperationDecl, ProtocolKind, ReadFailure, Verb,
};
use serde::Deserialize;
use serde_json::Value;

/// What the agent asks of the Kubernetes API.
pub const WATCH: OperationDecl = OperationDecl {
    name: "attestation.watch",
    doc: "the pods of Polar's namespaces and what owns them",
    protocol: ProtocolKind::KUBERNETES,
    location: Location::Cluster { access: &WATCHED },
};

/// What it may do: watch each kind it holds, and nothing else.
const WATCHED: [Access; Kind::ALL.len()] = {
    let mut watched = [resource_of(Kind::ALL[0]).access(Verb::Watch); Kind::ALL.len()];
    let mut i = 0;
    while i < Kind::ALL.len() {
        watched[i] = resource_of(Kind::ALL[i]).access(Verb::Watch);
        i += 1;
    }
    watched
};

/// A watch, as a request of the handler's.
pub struct Watching(pub Watch);

const fn resource_of(kind: Kind) -> Resource {
    match kind {
        Kind::Pod => Resource::of::<Pod>(),
        Kind::ReplicaSet => Resource::of::<ReplicaSet>(),
        Kind::Deployment => Resource::of::<Deployment>(),
        Kind::StatefulSet => Resource::of::<StatefulSet>(),
        Kind::Job => Resource::of::<Job>(),
    }
}

/// `value`, as the type it is of.
fn parsed<'a, K: Deserialize<'a>>(
    value: &'a Value,
    wrap: fn(K) -> Object,
) -> Result<Object, ReadFailure> {
    K::deserialize(value)
        .map(wrap)
        .map_err(|e| ReadFailure::Malformed(format!("an object does not read as its kind: {e}")))
}

fn object_of(kind: Kind, value: &Value) -> Result<Box<Object>, ReadFailure> {
    let object = match kind {
        Kind::Pod => parsed(value, Object::Pod),
        Kind::ReplicaSet => parsed(value, Object::ReplicaSet),
        Kind::Deployment => parsed(value, Object::Deployment),
        Kind::StatefulSet => parsed(value, Object::StatefulSet),
        Kind::Job => parsed(value, Object::Job),
    };
    object.map(Box::new)
}

impl Operation for Watching {
    type Protocol = Kubernetes;
    type Output = Change;
    const DECL: OperationDecl = WATCH;

    fn request(&self) -> kubernetes::Call {
        kubernetes::Watch::in_namespace(resource_of(self.0.kind), self.0.namespace.clone()).into()
    }

    fn read(&self, said: &kubernetes::Answer) -> Result<Change, ReadFailure> {
        let watch = self.0.clone();
        Ok(match said.change()? {
            kubernetes::Change::Listing => Change::Relisting { watch },
            kubernetes::Change::Listed => Change::Listed { watch },
            kubernetes::Change::Applied(value) => Change::Applied(object_of(watch.kind, value)?),
            kubernetes::Change::Deleted(value) => Change::Deleted(object_of(watch.kind, value)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::holdings::Holdings;

    /// Every kind it holds is one its operation declares, and nothing more.
    #[test]
    fn every_kind_it_holds_is_declared_and_nothing_more() {
        let declared: Vec<Access> = Kind::ALL
            .iter()
            .map(|k| resource_of(*k).access(Verb::Watch))
            .collect();
        assert_eq!(WATCHED.to_vec(), declared);
    }
    use polar_agent_builder::protocol::Delivery;
    use polar_agent_builder::protocol::testing::{KubeApi, kubernetes_handle};
    use proptest::prelude::*;
    use ractor::{Actor, ActorProcessingErr, ActorRef};
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn watch(kind: Kind) -> Watch {
        Watch {
            kind,
            namespace: "polar".to_string(),
        }
    }

    fn read(kind: Kind, said: kubernetes::Change) -> Result<Change, ReadFailure> {
        Watching(watch(kind)).read(&kubernetes::Answer::Change(said))
    }

    #[test]
    fn a_list_beginning_and_ending_is_said_of_this_watch() {
        assert!(matches!(
            read(Kind::Job, kubernetes::Change::Listing),
            Ok(Change::Relisting { watch: w }) if w == watch(Kind::Job)
        ));
        assert!(matches!(
            read(Kind::Pod, kubernetes::Change::Listed),
            Ok(Change::Listed { watch: w }) if w == watch(Kind::Pod)
        ));
    }

    #[test]
    fn each_kind_reads_as_its_own_type() {
        let cases = [
            (Kind::Pod, "v1", "Pod"),
            (Kind::ReplicaSet, "apps/v1", "ReplicaSet"),
            (Kind::Deployment, "apps/v1", "Deployment"),
            (Kind::StatefulSet, "apps/v1", "StatefulSet"),
            (Kind::Job, "batch/v1", "Job"),
        ];
        for (kind, api_version, name) in cases {
            let value = json!({"apiVersion": api_version, "kind": name, "metadata": {"name": "a"}});
            let Ok(Change::Applied(object)) =
                read(kind, kubernetes::Change::Applied(value.clone()))
            else {
                panic!("{name}");
            };
            let right = matches!(
                (kind, &*object),
                (Kind::Pod, Object::Pod(_))
                    | (Kind::ReplicaSet, Object::ReplicaSet(_))
                    | (Kind::Deployment, Object::Deployment(_))
                    | (Kind::StatefulSet, Object::StatefulSet(_))
                    | (Kind::Job, Object::Job(_))
            );
            assert!(right, "{name}: {object:?}");
            assert!(matches!(
                read(kind, kubernetes::Change::Deleted(value)),
                Ok(Change::Deleted(_))
            ));
            assert_eq!(resource_of(kind).kind, name);
        }
    }

    proptest! {
        /// What cannot be read is said to be: it is never taken for a change, which would leave what it holds with a gap.
        #[test]
        fn what_is_not_its_kind_is_malformed(kind in prop::sample::select(Kind::ALL.to_vec()), name in 0..1000u32) {
            let value = json!({"metadata": {"name": name}});
            prop_assert!(matches!(
                read(kind, kubernetes::Change::Applied(value)),
                Err(ReadFailure::Malformed(_))
            ));
        }
    }

    /// The domain as far as a watch goes: what it holds.
    struct Keeper;

    type Kept = Arc<Mutex<Holdings>>;

    #[ractor::async_trait]
    impl Actor for Keeper {
        type Msg = Delivery<Change>;
        type State = Kept;
        type Arguments = Kept;
        async fn pre_start(
            &self,
            _: ActorRef<Self::Msg>,
            kept: Kept,
        ) -> Result<Kept, ActorProcessingErr> {
            Ok(kept)
        }
        async fn handle(
            &self,
            _: ActorRef<Self::Msg>,
            message: Self::Msg,
            kept: &mut Kept,
        ) -> Result<(), ActorProcessingErr> {
            kept.lock().unwrap().apply(message.result.unwrap());
            Ok(())
        }
    }

    /// One run through the handler: every watch of the namespace lists, and what the API has is held, the pod with its owner.
    #[tokio::test]
    async fn what_the_api_has_is_held_once_every_watch_has_listed() {
        static OPERATIONS: [OperationDecl; 1] = [WATCH];
        let api = KubeApi::start().await;
        for path in [
            "/apis/apps/v1/namespaces/polar/replicasets",
            "/apis/apps/v1/namespaces/polar/deployments",
            "/apis/batch/v1/namespaces/polar/jobs",
        ] {
            api.holds(path, vec![]);
        }
        api.holds(
            "/apis/apps/v1/namespaces/polar/statefulsets",
            vec![json!({"metadata": {"name": "the-set", "namespace": "polar", "uid": "s1", "resourceVersion": "1"}})],
        );
        api.holds(
            "/api/v1/namespaces/polar/pods",
            vec![json!({"metadata": {
                "name": "the-set-0", "namespace": "polar", "uid": "p1", "resourceVersion": "2",
                "ownerReferences": [{
                    "apiVersion": "apps/v1", "kind": "StatefulSet", "name": "the-set", "uid": "s1", "controller": true,
                }],
            }})],
        );
        let site = kubernetes_handle(&OPERATIONS, &api).await;
        let kept: Kept = Arc::new(Mutex::new(Holdings::new(&["polar".to_string()])));
        let (keeper, _) = Actor::spawn(None, Keeper, kept.clone()).await.unwrap();
        let mut streams = Vec::new();
        for kind in Kind::ALL {
            streams.push(
                site.handle
                    .stream(Watching(watch(kind)), keeper.clone(), |delivery| delivery)
                    .unwrap(),
            );
        }
        for _ in 0..1000 {
            if kept.lock().unwrap().ready() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let held = kept.lock().unwrap();
        assert!(held.ready());
        let facts = held.facts_of("p1").expect("the pod");
        assert!(
            format!("{:?}", facts.owner).contains("the-set"),
            "{facts:?}"
        );
        assert_eq!(site.records.lock().unwrap().len(), Kind::ALL.len());
    }
}
