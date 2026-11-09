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

# Remote observers

Status, 2026-11-09: **findings only, deferred** (the maintainer: "write up our findings on the problems we have for
remote observers and punt on it for now"). Until it is taken up, Polar observes one Kubernetes cluster, its own, and every
agent runs in it.

## Where it came from

Area 3 of Vaughn's port (`kubernetes/kubernetes.md`, "Cluster-scoped identity and discovery") carries upstream's
multi-cluster kube agents, where an observer runs in each cluster and publishes on a topic of that cluster's own. Asked
which topic shape to take, the maintainer chose one topic per cluster, and then, on hearing that Polar's observers can
only run in its own cluster: "There should be a way for an Observer to live anywhere, they're low-trust, by design."
And more generally: a Jira observer on another network that Polar cannot reach into, but that can reach out with
observations, should not have to present a Kubernetes cluster at all.

An observer is the low-trust side by design: it receives from an untrusted world and decides nothing
(`credentials-agent-architecture.md`, "Observer (low-trust)"; `placement.md`, the `observers` pool). So the idea fits the
role. What follows is what stands in the way, read 2026-11-09.

## What is already there

- **cert-issuer trusts several token issuers.** Its validator is keyed by each token's `iss`, each issuer with its own
  audience, keys, claims and identity strategy (`cert-issuer/server/src/oidc.rs`, `Validator`). `sandbox-local` configures
  two: the cluster's own ServiceAccount tokens, and Keycloak for people (`infra/targets/sandbox-local/config.nuon`,
  `CERT_ISSUER_ISSUERS`).
- **The Kubernetes strategy takes a cluster domain per issuer,** and its comment already expects more than one cluster:
  "if this cert-issuer is ever configured to trust more than one Kubernetes cluster, each one's own domain is what
  actually keeps their identities from colliding" (`cert-issuer/common/src/identity.rs`, `KubernetesServiceAccount`).
- **A strategy for issuers that are not Kubernetes,** `SuffixedClaim`: a bare identity claim and a scope claim from the
  same token, `<claim>.<scope>` (same file).
- **Attestation's protocol is platform-neutral.** Everything Kubernetes-specific is a backend of the attestation agent;
  "a bare-metal backend (TPM, SPIRE) would replace the backend, not the protocol" (`runtime-attestation.md`, "Decisions").
- **Signed configuration travels over the observer's own broker session,** so an observer that can only dial out still
  receives it: nothing has to reach in.

## What stands in the way

1. **A workload means a Kubernetes ServiceAccount.** `workload_of` reads a workload only from
   `<workload>.<namespace>.serviceaccount.<domain>` (`identity.rs`). Any other identity has none, and is treated as a
   person's: no implied topics, no signed documents addressed to it, no place in the catalog (`policy-enforcement.md`:
   "an identity that maps to no workload (a person's) has no implied floor"). An observer vouched for by any other issuer
   cannot be an agent.

2. **The cluster's domain is dropped where an identity is joined to its workload.** `workload_of` and
   `kubernetes_subject_of` both ignore `<domain>`, so once a second Kubernetes issuer is trusted, its `kube-observer` is the
   local `kube-observer` to everything keyed by workload: implied topics, documents addressed to the workload, and grants,
   which are written under the subject `system:serviceaccount:<namespace>:<workload>`. Not reachable today (one Kubernetes
   issuer), and it must be fixed before a second is trusted.

3. **The catalog does not say where a workload runs or who vouches for it.** It would need, per placement: the issuer and
   its keys, the domain or scope, and the topics that placement gets. Applying the catalog would then be the sign-off for
   trusting that issuer (`policy-enforcement.md`, "Decisions"). Topics stay exact: a topic per placement would be a family
   whose slot is the placement, where today a family's slot is always a workload (`polar-agent-builder/src/topics.rs`,
   `FamilyDecl`), and the certificate issued to each placement would carry only its own (`p:pub:<topic>`).

4. **Renewal is Kubernetes'.** A certificate is renewed by the pod restarting and `polar-init` fetching a new one
   (`cert-issuer-architecture.md`, "Renewal is restart-driven"). Off Kubernetes, the agent renews in-process, the option that
   document already names for agents that cannot restart cheaply.

5. **Reaching in from outside.** A remote observer must reach cert-issuer, or the credentials agent's observer, and the
   broker, from outside Polar's cluster. How either is exposed beyond the cluster has not been checked.

6. **Attestation has nothing to read.** Both parts of it rest on Polar's trust base: the instance check asks Polar's
   Kubernetes API about the pod (owner, service account, `imageID` against the signed lock), and the node sensor reads the
   process from outside (`runtime-attestation.md`). Neither exists for a remote observer, and what a process says about
   itself is worthless as evidence (same document). Three ways, none chosen:
   - *Another cluster:* take that cluster's control plane into the trust base. The attestation agent gets a backend that
     reads its API, and the sensor runs there as a DaemonSet and reports back. Trusting another control plane is the
     maintainer's decision, not a detail; trusting its token issuer for identity (item 3) already goes part of the way.
   - *No cluster, a hardware root:* a TPM quote over measured boot with IMA measuring the binary at load, against the hash
     the build computes and the signed record carries (the static binary's code hashes the same in memory as on disk,
     `runtime-attestation.md`, "What remains, worked through"); or a confidential VM's attestation report (SEV-SNP, TDX),
     which proves to a remote verifier which image was launched. That document set confidential computing aside because it
     does not stop code inside the workload; on a host Polar does not own, the host is the new threat, which is what it is
     for. SPIRE could be the backend for either (its node attestors include TPMs and cloud instance identity). None tried.
   - *None:* run unattested, and say so. What it publishes stands as its own word, checked against the consumer's
     invariants; Cedar confines it to its topic; it holds no graph password and decides nothing.

7. **Rejuvenation does not evict a foothold there.** An hour-long certificate bounds a foothold to the hour because
   re-issuance needs what an attacker in the process cannot present: an attested pod. A remote observer renews with an
   identity provider's token or an enrolled key, which whoever holds that host can go on presenting. And detection, which
   Polar wants first (`runtime-attestation.md`, "What an attacker is assumed to want"), is blind there: no sensor, and a
   crash is reported only if the observer chooses to.

## Recommended, when it is taken up (not decided)

- Fix item 2 first: the domain counts wherever an identity is joined to its workload.
- The catalog states each placement's issuer and its attestation: Polar's own cluster, another cluster's backend,
  hardware, or none.
- The attestation level travels with the identity (a name in the certificate), so Cedar policy can treat an unattested
  observer differently.
- "None" is allowed for the `Observer` role only; hardware is the upgrade path for a host Polar does not own.

## Found doing this, for now, not only for remote observers

**A person's identity can take a workload's form.** `SuffixedClaim` makes `<claim>.<scope>` with each part only required
to be DNS-safe (`identity.rs`, `normalize_identity`), and `verify_identity` compares the CSR's name with that string
(`cert-issuer/server/src/csr.rs`). So a Keycloak token whose `preferred_username` is `credentials-agent` and whose
`identity_scope` is `polar.serviceaccount.cluster.local` normalizes to `credentials-agent.polar.serviceaccount.cluster.local`,
which `workload_of` reads as the credentials agent. Nothing read refuses it; whether anything does further on (the
credentials agent's people path) was not checked, nor where the realm's `identity_scope` mapper is set and whether a
person can change their own (it is not in this repository). To check, and if it holds, to fix at the cause: an identity
from a non-Kubernetes issuer never takes the `.serviceaccount.` form.
