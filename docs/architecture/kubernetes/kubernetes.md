<!--
  ACE Tool

  Copyright 2026 Carnegie Mellon University.

  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
  FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
  EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
  MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
  TRADEMARK, OR COPYRIGHT INFRINGEMENT.

  Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu
  for full terms.

  [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
  distribution.  Please see Copyright notice for non-US Government use and distribution.

  This Software includes and/or makes use of Third-Party Software each subject to its own license.

  DM26-0670
-->

# Kubernetes Agent Design Document

## Overview
The Kubernetes Agent is designed to observe and report on the state of Kubernetes cluster resources for integration into a larger distributed data processing and analysis system. The agent is responsible for initial observation and continuous monitoring (via watchers) of Kubernetes resources, such as ConfigMaps, Pods, and Nodes, with the goal of capturing relevant metadata and relationships for downstream processing (e.g., graph database ingestion, lineage tracking, and security assurance).

## Key Design Decision So Far

### 1. **Hybrid Observation Model**
- **Decision**: Use a hybrid approach of initial listing (observation) followed by continuous watching for events, changes etc.
- **Rationale**: Some Kubernetes resources may already exist at agent startup, and only relying on a watcher would miss them. Listing all resources ensures full visibility from the start, while watchers capture ongoing changes.


### 2. **Concurrent Namespace-Specific Observers**
- **Decision**: The Cluster Observer Supervisor will spawn a separate set of observers per namespace for each observed resource.
- **Rationale**: This supports horizontal scalability and makes it easier to isolate logic or failures to specific namespaces.

### 3. **Eventual Consistency Between Resource Observers**
- **Decision**: Allow each resource observer (e.g., for Pods, ConfigMaps, Secrets) to operate independently, with the expectation that relationships (e.g., Pod references to Secrets) will be reconciled asynchronously.
- **Rationale**: Decouples observers and supports modular design. This approach also aligns with actor-based architectures (e.g., Ractor), where individual actors handle their own domains.

### 4. **Data Enrichment for Relationship Mapping**
- **Decision**: Enrich observed data with relevant contextual metadata (e.g., labels, annotations, image references). Many clusters in regulated environments mandate this through kyverno policies already.
- **Rationale**: Enables downstream systems to map resource relationships, such as linking Pods to container registries or ConfigMaps to services.

### 5. **Modular Expansion Strategy**
- **Decision**: Start with foundational resources (ConfigMaps, Pods, Nodes), and iteratively add observers for other relevant Kubernetes primitives (e.g., Secrets, Services, Volumes, Deployments).
- **Rationale**: Allows focused development and testing of each observer. It also aligns with evolving use cases without overwhelming the system early.

## Topology

TODO: Visual architecture diagram outlining cluster supervisor, and actors for various resources.

## Roles

**Cluster(Observer)Supervisor**
 - Spawns and monitors child actors.
 - Holds shared config and cluster context.
 - Can restart children or orchestrate data flow changes.

Configuration data will be provided by a **Configuration Agent** in the future, but for now, values are hard-coded.

Its supervisor could provide structured actor metadata via dhall configurations.
```dhall
let Actor =
      { cluster : Text
      , namespace : Text
      , role : Text
      , resource : Text
      }

in  [ { cluster = "prod-cluster", namespace = "default", role = "observer", resource = "pod" }
    , ...
    ]
```

The ClusterSupervisor watches all child actors and manages their lifecycles.

Should its children fail for some reason, it will likely restart them, depending on the cause.

In deployment, the container for the kube-observer will need to be able to authenticate with the kubernetes API server, to enable this, we have to specify
a ServiceAccount, a ClusterRole for that account that speicifies desired permissions, and a ClusterRoleBinding for that account. In the future, operators may desire more or less permissions than our standard, so we will aim to make this more configurable.

**Observers** (Kube.rs watchers)
 - Wraps a kube_runtime::watcher for a specific resource type.
 - Sends structured events (created, updated, deleted) to corresponding consumer agents.

**ConsumerSupervisor**
 - Similar to the observer cluster supervisor, the consumer has the simple task of lifecycle management for its child actors.

**Consumers**
 - Receive k8s data from observer actors corresponding to their resource.
 - Transforms data structures into queries to represent resources in the graph database.

## Current Resource Implementations

### Namespaces

Upon initialization, the cluster supervisor will try to discover all the namespaces it can so it can observe them. Once it has this list,
it will spin up additional PodObserver actors to read currently deployed pods and set up a "watcher" to listen for additional pods to come online.

### Nodes
TODO: My initial thoughts are that since nodes aren't namespaced, the supervisor or perhaps another actor shopuld watch them for real time changes. It'll be more valuable whenever we can observe cloud/on-prem machines to see how they look in the cluster.


### Pods

The PodObserver Lists all Pods in the specified namespaces. The datatype exposed by the k8s_openapi crate also contains attributes detailing resources used by the Pod, including volumes, configMaps, secrets, etc.
From there, consumers can extract more information about the relationship to other resources.
Once it reads all data, the observer watches for changes and prints update events.

It is planned to link images to container registry metadata.


### Node Types:

    Pod { name, namespace, serviceAccountName, ... }

    Volume { name } (some volumes will also have backing types)

    ConfigMap { name }

    Secret { name }

    PVC { name }

    ContainerImage { image } (optional, could just be a property)

Edge Types:

    (Pod)-[:USES_VOLUME]->(Volume)

    (Volume)-[:BACKED_BY]->(ConfigMap | Secret | PVC)

    (Pod)-[:USES_CONFIGMAP]->(ConfigMap) (for env vars)

    (Pod)-[:USES_SECRET]->(Secret) (for env vars)

    (Pod)-[:RUNS_IMAGE]->(ContainerImage)

Optional:

    (Pod)-[:RUNS_AS]->(ServiceAccount) (or just store as a property of the relationship)

## Messaging strategy

K8s observers and data processors share a single distinct message type that more or less mirrors kubernetes' events.
The design of our messaging system is driven by several key principles:

### 1. **Unified Abstraction**

By defining a central message type—a `KubeMessage` that wraps an enum of possible Kubernetes resources (e.g., Pod, Node, Deployment)—we create a single, unified abstraction that all parts of the system can rely on. This allows all watchers (the actors interfacing with the Kubernetes API) to output their events in a consistent format, which simplifies downstream routing and processing. In this way, each watcher doesn’t need to know the specifics of every processor; they all just send out an `KubeMessage`.

### 2. **Leverage Serde Serialization**

Since Kubernetes resource types provided by the `k8s-openapi` and `kube` crates are fully `serde`-serializable, we can directly embed these types in our messages. This not only simplifies our implementation by removing the need for manual data transformation but also allows flexibility:

* **Direct Use:** Processors can work with the raw, rich resource data.
* **Data Reduction:** Alternatively, we could extract only the relevant portions (e.g., metadata and status) if we need to optimize message size or processing speed.

### 3. **Decoupling and Loose Coupling**

Using a central routing mechanism (`DataRouter`) that receives all `KubeMessage` messages means the producers (watchers) and consumers (processors) are decoupled. This architecture supports:

* **Flexibility:** New processors can be added without changing the watchers.
* **Resilience:** Failures in one processor won’t necessarily impact the others.
* **Dynamic Routing:** The router can filter, duplicate, or transform messages as needed before sending them to the appropriate actor.

### 4. **Type Safety and Clear Intent**

By having a dedicated enum (`ObservedResource`) for the different resource types, we maintain type safety. Each variant clearly indicates which Kubernetes resource it represents. Additionally, including a `WatchAction` (Applied, Deleted, Restarted) alongside context (such as the cluster name, namespace, and a timestamp) gives every event a well-defined meaning, making the data more actionable for downstream processors.

### 5. **Extensibility**

This design lays a strong foundation for future growth:

* **Adding New Resources:** As you need to observe more resource types, you can simply add a new variant to `ObservedResource` and create the corresponding watcher.
* **Modular Processors:** Each processor (e.g., for metrics, logging, graph updates) can be implemented as an independent actor that subscribes only to the events it cares about.
* **Dynamic Scaling:** The supervision layer (like the `ClusterSupervisor`) can manage these actors independently, allowing you to scale or restart parts of the system without a complete overhaul.

### 6. **Actor Model Fit**

With the actor-based approach using the ractor framework:

* **Message Passing:** Our design naturally fits the message-passing paradigm of actors. Each event is self-contained, and the routing between actors happens via these messages.
* **Fault Isolation:** If a particular processor fails or experiences a surge of events, it doesn’t block or crash the entire system. The supervisor can intervene, and messages can be retried or rerouted as needed.
* **Concurrency:** Actors can process events concurrently, improving the responsiveness and throughput of your service in a dynamic cluster environment.

In summary, the reasoning behind this design is to create a robust, flexible, and scalable architecture that leverages Rust’s type safety and the power of actor-based concurrency. The use of serialization for Kubernetes types simplifies our workflow and ensures that we can easily transform and route the rich data provided by the cluster into actionable insights for visualization and metrics collection.

Does this cover your questions, or would you like to dive deeper into any particular aspect of the messaging system?

## Planned Enhancements
- **Inter-observer Communication**: Message passing between observers to verify resource references (e.g., Pod-to-Secret linkage).
- **Graph Building**: Emit messages representing resource relationships to a central processor or graph DB writer.
- **Security Auditing**: Track usage of sensitive resources like Secrets and ServiceAccounts.
- **Actor Model Integration**: Full integration with Ractor-based message-passing system.

## Conclusion
This design allows the Kubernetes Agent to flexibly and reliably observe resource states while providing a strong foundation for relationship mapping and security verification. It balances completeness, modularity, and extensibility to support evolving requirements across regulated and secure environments.

## Cluster-scoped identity and discovery (the port's area 3, planned 2026-11-09)

Vaughn's port carries public Polar's kube-agent work in one commit (`137438a6` on `ace-remote/port/public-polar-blitz-deploy`,
from cmu-sei/Polar `5bb6928`, `242d6d3`, `2a5e3f1`, `4466a03`, `8d0f058`, `09af243`; 20 files, +3,501/-1,864): `cluster_uid` (the
UID of `kube-system`) on every `KubeNodeKey`, stamped by the observer on every `RawKubeEvent`; Namespace and Node projected with their
states and a pod `RUNNING_ON` its node; the consumer split into a file per resource with its projection cache keyed by
`(kind, cluster_uid, uid)`; discovery (observers announce their cluster on a fixed topic and answer `discovery.query`, the consumer
records each as a `KubernetesCluster`); and `cluster_uid` on the resolver's `DiscoverySourceRef::KubernetesPodContainer`. It was
written against the kube agents before main moved them onto the protocol handlers (seven commits since the branch point, the
Kubernetes API as a stream, +1,341/-1,070 in 9 files), so it is a port onto main's code, not a merge.

**Read against main** (`lib/src/graph/nodes/kube.rs`): `KubeNodeKey` already has `Cluster { uid }` and a `Namespace` keyed by
`(name, cluster_uid)`. Every other key is the resource's own Kubernetes UID, a random UUID, unique across clusters in practice. So
`cluster_uid` belongs in the key of what is named rather than given a UID (a namespace, a node) and on every node as a property, to
group and to ask by, not in every key. That keeps most of the breaking change out: the nodes keyed by UID are the same nodes after
it. Vaughn's note, "a graph that holds kube nodes needs them observed again", holds only for the keys that change, and a node left
under the old key is not removed by observing again. **The migration it needs** (after 3.0.0 a breaking change needs one): a signed
migration (`polar-sign migration`) that, in a graph that has known one cluster (every Polar deployment so far), sets `cluster_uid`
on every kube node without one and re-keys the named ones, before the new consumer writes; the consumer's section names it, so the
consumer holds until it is applied.

**Decided (the maintainer, 2026-11-09): one cluster, for now.** Asked between one events topic and one per cluster, the
maintainer first chose one per cluster, then, with an observer per cluster meaning observers outside Polar's own cluster,
deferred the whole question: "The kubernetes question remains just one cluster for now." Why it waits, and what stands in
the way of an observer that runs anywhere (identity outside a ServiceAccount, the dropped domain, renewal, attestation):
`remote-observers.md`. The per-cluster topic, when it comes, is a family whose slot is the placement (that document, item 3).

**The bites, with one cluster** (decided here for review, 2026-11-09, by the rule that a change is made for what it serves
now): (C) Namespace and Node with their states, a pod `RUNNING_ON` its node, on main's keys as they are (`Namespace` is
already keyed by `(name, cluster_uid)`), is what area 3 takes. `cluster_uid` on every node and its migration (A), discovery
and `KubernetesCluster` nodes (B), and `cluster_uid` on the resolver's container reference (D) serve several clusters only,
so they wait with `remote-observers.md`; Vaughn's commit stays the reference for them. The consumer is split into a file per
resource only where C needs it. The kube consumer's open findings (`remaining-work.md`, K2 to K16) are not this area's, but
C touches the same projections, so it is read against them as it is written. Tests first, then live on u7c.

**Bite C, built (2026-11-09).** Decided for it (the maintainer): `Namespace` keeps main's key, `(name, cluster_uid)`, and the
observer says the cluster, the uid of `kube-system`, read once before it watches anything (its operation `kube.cluster`, a get
of that namespace) and stamped on every `RawKubeEvent` (`cluster_uid`; an event without one, from an older observer, is not
projected). What was built:
- *The observer* watches nodes across the cluster beside namespaces and Flux, and asks again for the cluster when the get
  fails, watching nothing until it has it (`kubernetes/observe/src/watches.rs`, `Identifying`, `WatcherMsg::Identify`).
  Found doing it: the Kubernetes handler made every call at a namespaced path, so a get of anything across the cluster went
  to a path that does not exist; a call with no namespace is now of an object across the cluster
  (`polar-agent-builder/src/protocol/kubernetes.rs`, `call`).
- *The consumer* projects `Namespace` with its phase as `NamespaceState` (Active from its `creationTimestamp`, Terminating
  from its `deletionTimestamp`, both the API's own times) and `Node`, by uid as before, with its conditions and cordon as
  `NodeState` (from the latest condition's `lastTransitionTime`, never the heartbeat; a change no condition attests, a
  cordon, from when it was observed, so it does not overwrite the state before it, finding K6). Both write a state only when
  it changed, through the `ProjectionCache` nothing used before (finding K7, not repeated here; the other kinds still have
  it). Every namespaced kind is `IN_NAMESPACE` its namespace, and a pod is `RUNNING_ON` the node it names, joined by the uid
  the node was seen with: a pod seen before its node waits for it, a deleted node's name joins nothing, and a node made
  again under the name is another node. The `todo!("Nodes")` panic (finding K12) is gone (`kubernetes/consume/src/lib.rs`,
  `supervisor.rs`, `handle_kube_event`).
- *Not done, by the order of work:* the nodes and edges are new, so nothing already in a graph changes and no migration is
  needed. The cache lives in memory: a consumer that restarts writes each namespace's and node's current state once more,
  and a pod whose node it has not seen since waits for the node's next event.

