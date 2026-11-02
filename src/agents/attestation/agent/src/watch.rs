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

//! One watch of one kind in one namespace, handing each change to the supervisor. The Kubernetes API's stream ending or failing means
//! what it said may be stale, so the watch says so and starts again from a list, rather than assume a resumed stream missed nothing.

use crate::holdings::{Change, Kind, Object, Watch};
use futures::StreamExt;
use futures::stream::BoxStream;
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::Job;
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::warn;

/// How long a watch that lost the API waits before listing again.
const RETRY: Duration = Duration::from_secs(5);

/// A watch's changes, in the holdings' terms: an error ends the stream, after saying the API was lost.
fn changes<K>(api: Api<K>, watch: Watch, wrap: fn(K) -> Object) -> BoxStream<'static, Change>
where
    K: kube::Resource + Clone + std::fmt::Debug + serde::de::DeserializeOwned + Send + 'static,
    K::DynamicType: Default + Clone + Eq + std::hash::Hash,
{
    watcher::watcher(api, watcher::Config::default())
        .scan(false, move |lost, event| {
            let watch = watch.clone();
            let change = match event {
                _ if *lost => None,
                Ok(Event::Init) => Some(Change::Relisting { watch }),
                Ok(Event::InitDone) => Some(Change::Listed { watch }),
                Ok(Event::InitApply(o) | Event::Apply(o)) => {
                    Some(Change::Applied(Box::new(wrap(o))))
                }
                Ok(Event::Delete(o)) => Some(Change::Deleted(Box::new(wrap(o)))),
                Err(e) => {
                    warn!(?watch, "a watch lost the API: {e}");
                    *lost = true;
                    Some(Change::Lost { watch })
                }
            };
            futures::future::ready(change)
        })
        .boxed()
}

/// The stream of `watch`, from the API.
pub fn stream_of(client: &Client, watch: &Watch) -> BoxStream<'static, Change> {
    let client = client.clone();
    let namespace = watch.namespace.as_str();
    let watch = watch.clone();
    match watch.kind {
        Kind::Pod => changes(
            Api::<Pod>::namespaced(client, namespace),
            watch,
            Object::Pod,
        ),
        Kind::ReplicaSet => changes(
            Api::<ReplicaSet>::namespaced(client, namespace),
            watch,
            Object::ReplicaSet,
        ),
        Kind::Deployment => changes(
            Api::<Deployment>::namespaced(client, namespace),
            watch,
            Object::Deployment,
        ),
        Kind::StatefulSet => changes(
            Api::<StatefulSet>::namespaced(client, namespace),
            watch,
            Object::StatefulSet,
        ),
        Kind::Job => changes(
            Api::<Job>::namespaced(client, namespace),
            watch,
            Object::Job,
        ),
    }
}

/// What makes a watch's stream: called again each time it has to start over.
pub type Source = Arc<dyn Fn() -> BoxStream<'static, Change> + Send + Sync>;

pub struct WatchArgs<F> {
    pub source: Source,
    pub deliver: F,
}

pub struct WatchActor;

pub struct WatchState {
    task: JoinHandle<()>,
}

#[ractor::async_trait]
impl Actor for WatchActor {
    type Msg = ();
    type State = WatchState;
    type Arguments = WatchArgs<Arc<dyn Fn(Change) + Send + Sync>>;

    async fn pre_start(
        &self,
        _myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        let WatchArgs { source, deliver } = args;
        let task = tokio::spawn(async move {
            loop {
                let mut stream = source();
                while let Some(change) = stream.next().await {
                    deliver(change);
                }
                tokio::time::sleep(RETRY).await;
            }
        });
        Ok(WatchState { task })
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        state.task.abort();
        Ok(())
    }
}
