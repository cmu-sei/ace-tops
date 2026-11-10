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

//! What kube-observer is, as the infrastructure asks to be told: see `polar_agent_builder::PolarAgent`.

use crate::supervisor::{ClusterObserverSupervisor, SHUTDOWN_BUDGET};
use polar_agent_builder::protocol::OperationDecl;
use polar_agent_builder::{Capability, Cause, Configured, PolarAgent, Role, StartError, TopicDecl};
use ractor::Actor;
use std::time::Duration;

pub struct KubeObserver;

impl PolarAgent for KubeObserver {
    const NAME: &'static str = crate::TCP_CLIENT_NAME;
    const ROLE: Role = Role::Observer;
    const PURPOSE: &'static str =
        "Watches the Kubernetes API and publishes what it sees to Cassini";
    const NEEDS: &'static [Capability] = &[Capability::KubeApiRead];
    const SECTIONS: &'static [&'static polar_env::Section] = &[&crate::settings::SECTION];
    const OPERATIONS: &'static [OperationDecl] = &[crate::watches::IDENTIFY, crate::watches::WATCH];
    const SHUTDOWN_BUDGET: Duration = SHUTDOWN_BUDGET;
    const TOPICS: &'static [TopicDecl] = &[TopicDecl::publish(
        kube_common::KUBERNETES_CONSUMER,
        "every change it sees to a watched resource, of any kind, as a RawKubeEvent (JSON)",
    )
    .because(&[Cause::Outside("the Kubernetes API")])];
    const HELP: Option<&'static str> = Some(
        "kube-observer watches the cluster's resources through the Kubernetes API, with the \
         service account the deployment gives it (a ClusterRole computed from what it declares it \
         watches, never Secrets), and publishes each change on Cassini for kube-consumer to project into the graph. The \
         cluster API address and its token are the ones Kubernetes gives every pod. Its own \
         variables are how long a watch that ended waits before it is asked for again.",
    );

    async fn start(configured: Configured) -> Result<(), StartError> {
        configured.init_logging("kubernetes.cluster.observer.supervisor");

        let (_, handle) = Actor::spawn(
            Some("kubernetes.cluster.observer.supervisor".to_string()),
            ClusterObserverSupervisor,
            configured,
        )
        .await
        .map_err(|e| format!("kube-observer failed to start: {e}"))?;

        handle
            .await
            .map_err(|e| format!("kube-observer supervisor task failed: {e}"))?;

        // The supervisor stopping is never a success: an observer that is no longer observing
        // must be restarted. `run` exits non-zero so the Job does.
        Err("the kube-observer supervisor stopped".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    polar_agent_builder::polar_agent_tests!(KubeObserver);

    #[test]
    fn it_says_it_reads_the_cluster() {
        let scaffold = polar_agent_builder::agent::scaffold_document::<KubeObserver>();
        assert_eq!(scaffold.operations.len(), 2);
        for operation in &scaffold.operations {
            assert_eq!(operation.protocol, "kubernetes");
            assert_eq!(operation.location, "cluster");
        }
    }

    /// Its ClusterRole is what it watches, listed first, and the one get that names the cluster: no Secrets, no
    /// ConfigMaps, nothing it does not declare.
    #[test]
    fn its_role_is_what_it_watches_and_nothing_else() {
        let scaffold = polar_agent_builder::agent::scaffold_document::<KubeObserver>();
        let role = &scaffold.roles["kube-api-read"];
        let rules: Vec<(String, String, Vec<String>)> = role
            .iter()
            .map(|r| {
                (
                    r.api_groups.join(","),
                    r.resources.join(","),
                    r.verbs.clone(),
                )
            })
            .collect();
        let watched = |group: &str, resource: &str| {
            (
                group.to_string(),
                resource.to_string(),
                vec!["list".to_string(), "watch".to_string()],
            )
        };
        assert_eq!(
            rules,
            [
                (
                    String::new(),
                    "namespaces".to_string(),
                    vec!["get".to_string(), "list".to_string(), "watch".to_string()]
                ),
                watched("", "nodes"),
                watched("", "pods"),
                watched("apps", "deployments"),
                watched("apps", "replicasets"),
                watched("batch", "jobs"),
                watched("kustomize.toolkit.fluxcd.io", "kustomizations"),
                watched("source.toolkit.fluxcd.io", "ocirepositories"),
            ]
        );
        assert_eq!(scaffold.roles.len(), 1, "{:?}", scaffold.roles);
    }
}
