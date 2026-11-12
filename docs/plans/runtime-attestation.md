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

# Runtime attestation: Polar knows its pods are what it signed

> **This document has a twin.** [`runtime-attestation.claude.md`](runtime-attestation.claude.md) says the same thing,
> written for Claude to keep its understanding in the fewest words. This one is written for people. They are two sides
> of one plan, and they are changed together.
>
> A **capability-level plan**: the intent, and every feature it needs, with where each stands. Each remaining feature
> gets a plan of its own in [`runtime-attestation/`](runtime-attestation/). It describes Polar's `main` as it is. The
> design's full history is in [`../architecture/runtime-attestation.md`](../architecture/runtime-attestation.md).

**Status: partly built.** Judging pods and watching them are done. The hardening, taking git out of every agent, and
each agent's locks are built. Network enforcement, the node sensor and binding sessions to a pod's address are next.

## 1. The need

Polar hands certificates to the workloads in its cluster, and those certificates are what every other part of Polar
trusts. So Polar needs to know, continually, that each pod holding one is the pod it signed for. That means the image
it signed, run the way the signed record says, and not altered since.

The threat it is built for is a **foothold**: an attacker who gets code running in a pod and tries to stay. Polar
wants three things against that:

- to make it hard;
- to **detect** it, a crash by signal being the most valuable evidence there is;
- to **keep operating through it** and shut it down at its own choosing, rather than fall over.

**Kubernetes is the trust base.** Its control plane, cert-issuer's CA key, the signed deployment, the attestation
agent and the node sensor are trusted. Polar does not defend against what is already inside them.

## 2. How the need was found

- **From the design work** recorded in `runtime-attestation.md`: what an attacker could do in a pod, and what would
  see it.
- **From building the certificate path.** A pod's token proves only whose workload it is, not that the pod is the one
  that was signed for.
- **From looking at the pods themselves on Polar's clusters.** No container ran read-only or under a seccomp profile,
  and the attestation agent checked none of it. Closing that gap became the hardening below.
- **From reviewing the build orchestrator.** A build pod running someone else's code could reach every
  service in the cluster and the internet.

## 3. The plan

An **attestation agent** judges every Polar pod against the **signed deployment record**, which says what should run
and how. It watches for anything that drifts. Around it, each agent is made harder to subvert, and the cluster is made
to enforce what each pod may reach.

| Feature | What it gives | Status |
|---|---|---|
| **Judging each pod** | the signed record; the credentials agent asks before issuing whether the pod is genuine, and refuses if not | done |
| **Watching** | altered pods and crashes reported, acting on nothing | done |
| **Hardening held to the record** | every Polar container read-only, no privilege escalation, under the runtime's seccomp profile, and held to it | done, seen working on u7c |
| **No agent runs git or holds a key file** | git's protocol in the git server's own process; agents read through it over Cassini; up.nu copies the deployment; the egress probe | built; not yet seen working on u7c from `main` |
| **Each agent locks itself** | at start, seccomp refuses new programs, debugging and executable memory; Landlock limits the files to what its build declares | built; not yet seen working on u7c from `main` |
| **Network enforcement** | Polar's own enforcer, on every node, enforces what each pod may reach, starting with builds of foreign code; a canary proves it does | planned: [`runtime-attestation/network-enforcement.md`](runtime-attestation/network-enforcement.md) |
| **The node sensor** | a read-only reporter on every node: processes in each Polar container that are not its agent, and each agent's locks, read from outside the process | outlined, plan not yet written |
| **Sessions bound to the pod's address** | a certificate carries its pod's address, and Cassini refuses a session from anywhere else | outlined, plan not yet written |

## 4. Alternatives considered

- **Attesting by a challenge to the running process,** asking it to prove its code. Rejected: a process that has
  been taken over answers whatever it likes, so the verdict comes from the API and the sensor.
- **Reading process memory to hash running code.** That would make the sensor able to read any process's memory, the
  custody daemon's keys among them. It is set aside as a decision of its own, later.
- **Kubernetes' own controls alone** (Pod Security admission, a cluster's own policies). Polar accepts Kubernetes'
  limits but does not hand its security decisions to a Kubernetes feature where it can make them better itself.
- **Acting on what it finds.** Rejected: watching reports and acts on nothing, so that Polar keeps operating through
  a compromise and shuts it down at its own choosing.

## 5. Why this plan

- Each feature closes a way a foothold could be made or kept.
- Each falls back plainly where a cluster cannot give it: Polar runs, reports what is missing, and a cluster's signed
  policy may refuse a pod without the protection.
- Each is seen working on u7c before the next starts.

## 6. How much of the need is met now

- **Judged and watched.** Every Polar pod is judged before it gets a certificate and watched afterwards.
- **Hardened.** Every container is hardened and held to it.
- **Locked.** Every agent locks itself at start, with seccomp and Landlock.
- **No agent runs git or holds a key file.**

Not yet met:

- **The network.** Nothing stops a pod reaching any other, or the internet. Polar's development clusters run no
  engine that enforces NetworkPolicy, and Polar renders no policy for its own namespaces.
- **Processes in a pod.** Nothing sees a second process in a pod, such as a shell opened with `kubectl exec`.
- **Where a session comes from.** Nothing ties a Cassini session to where it comes from.
- **Seen working from `main`.** Taking git out of the agents, and their locks, have been seen working on u7c, but not
  yet as `main` builds them.

## 7. What is left before this is a capability

- **Network enforcement,** the next feature, with a plan of its own.
- **The node sensor,** then **sessions bound to the pod's address,** each planned as it is reached.
- **A capability document,** saying what runtime attestation is, why it exists and how it is used, once the last
  feature is in.
