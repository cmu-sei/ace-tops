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

# Runtime attestation

Status, 2026-10-26: the shape, decided with the maintainer. Built so far: slice A's agent and its signed record; no one asks it yet. 2026-10-28: the plan, for review
("The plan"). What Polar already had on the topic
(the original Attestation Service, cert-issuer's deferred "v2" items, the image attestation ladder) is in
`core-restarts.md`, question 1, "Runtime attestation: what Polar has on it".

Diagrams: [the instance check](sequences/general/attestation_instance_check.svg) (slice A),
[watching what was attested](sequences/general/attestation_watching.svg) (slice B), [the process](sequences/general/attestation_process.svg) (slice C).
The [original design](sequences/general/attestation_and_issuance.svg) is what these replace in mechanism.

## Why

The floor signs the core's own identities on a token alone, and the decided fix for the credentials agent's restart
(`core-restarts.md`, question 1: a handover ticket for rejuvenation, a narrow window for a crash) only decides *when*
that entry is open. Inside the window, any pod running as the service account could get there before the real one
(the token names the account and a pod UID, and nothing says which UID is the real successor). The same gap, smaller,
is in every certificate the credentials agent vouches for: it vouches on a verified token, not on the pod.

The maintainer (2026-10-26) wants both:
- **an instance check at issuance:** a certificate goes only to the instance the deployment made, running what the
  deployment names;
- **runtime attestation of the process:** the instance that was attested is still that, while it runs.

## Decisions (the maintainer, 2026-10-26)

- **One agent: the attestation agent.** It takes over the pod observer's role in `pod-reaper.md`, since both need the
  same rights over pods (get, list and watch, in Polar's namespaces): one agent rather than two holding the same
  permission. It sees and reports; it never acts. The Reaper stays a separate agent that only deletes, and stays for
  clusters older than the in-place restarts the Deployments below rely on.
- **Kubernetes stays inside it.** Everything Kubernetes-specific is a platform backend of the attestation agent. The
  rest of Polar speaks a platform-neutral protocol to it over Cassini ("is this instance genuine?", "this instance has
  lapsed"). A bare-metal backend (TPM, SPIRE) would replace the backend, not the protocol.
- **It is not in the core.** It is among the first things to start after the core.
- **A node sensor, read-only, on every node** (below): exec sessions and the process's own locks are verified from
  outside the process, not taken on its word.
- **The sensor is built with the attestation agent, and deployed apart from it.** One domain, as `kubernetes/` keeps
  `observe` and `consume`: `attestation/agent` (the attestor, one per cluster, holding the Kubernetes credential),
  `attestation/sensor` (one per node, a DaemonSet, host PID visibility only, no Kubernetes credential) and
  `attestation/common` (the protocol both speak over Cassini). Two identities, each with its own certificate. Why not
  one workload: the sensor must be one per node, since it sees only its own node's processes, and merging would either
  leave the attestor blind to other nodes or put the cluster credential on every node; and one compromise would then
  hold both a read view of every pod in the cluster and every process on a node. Each identity holds only what it needs:
  the Reaper's principle, applied here to two kinds of seeing rather than to seeing and acting. Only the attestation
  agent gives verdicts; the sensor gives evidence.
- **The trust base is written down, and the regress stops there.** The Kubernetes control plane (its signed tokens and
  its API), cert-issuer's CA key, the signed deployment (`provenance.json` and the image lock), the attestation agent,
  and the node sensor (nothing else sees its node). Everything else is attested against these. "Who attests the attestor" is not asked again; the maintainer:
  it is "like mixing your own silicon and baking your own semiconductors to solve the hardware supply chain issue".
  Two attestation agent instances attesting each other's successor is noted as optional hardening, not planned.

## The instance check at issuance

The request carries the pod UID its token is bound to (the instance binding, `instance_binding_claim`,
`cert-issuer/server/src/config.rs:93`). The attestation agent answers whether:
- the pod exists and has that UID;
- its owner is the workload the catalog says this identity runs as (its Job, or its Deployment's ReplicaSet);
- it runs as the expected service account;
- each container's `imageID` is the digest its Deployment pins, which is checked continually against the signed record ("What the images
  are checked against", below; the Kubernetes consumer's "attestation ladder": the kubelet's `imageID`, never the spec's tag,
  `kubernetes/consume/src/lib.rs`).

Who asks:
- **the credentials agent,** before it vouches for any workload;
- **cert-issuer,** for a token-only request in one of the core's windows (the ticket, the crash window, Cassini's
  route). The window decides when the entry is open; the attestation decides who gets through it.

**Bootstrap is attested after the fact.** The core's first certificates come from the floor before anything can attest
them. Every entry in cert-issuer's record carries its pod UID, so once the attestation agent is up it attests the
running core pods against the record, and reports any that fail. The same pattern as the record itself: the body guard
learns as soon as it can. Optional for now, not planned: "Optional features", below.

## Runtime attestation of the process

A builder actor in every agent, beside the health actor, answers the attestation agent's challenges on a schedule. The
rule that decides what counts: **what a process says about itself is worthless against an attacker running code inside
it**, who can read its memory, sign with its key and answer any challenge. So evidence comes from what the attacker does
not control, or the process submits to restrictions that are verified from outside. Self-measurement (hashing
`/proc/self/exe` from inside) is not evidence, and is dropped.

| What the attacker does | What stops it or shows it | Seen by |
|---|---|---|
| An impostor pod with a stolen token | The instance check: owner, service account, `imageID` against the signed deployment | the API |
| Copies the certificate key out, to use elsewhere | The private key is held by the pod's custody daemon, usable through its socket but not readable (`key-custody.md`). Not in the kernel keyring as first written here: no kernel holds or signs with a P-256 key (`key-custody.md`, "The process keyring, probed"), so it is in the daemon's locked memory, which root on the node could read. Cassini binds each session to the attested pod's address | the custody daemon, Cassini |
| Replaces the binary, or drops a new one | `readOnlyRootFilesystem` and digest pinning, verified in the pod spec (slice C's C1, below) | the API |
| `kubectl debug` | An ephemeral container in the pod's status | the API |
| `kubectl exec`, or a spawned shell | A process in the container's cgroup that is not the agent | the node sensor |
| Code injected into the live process | The builder locks the process before it parses any untrusted input, irreversibly: seccomp (no `execve`, `ptrace`, `memfd_create`, no new executable memory) and Landlock (no file access beyond what it opened); `Seccomp: 2` and `NoNewPrivs: 1` verified in `/proc/<pid>/status` | the node sensor |
| Uses the agent's rights for its own ends | Every refused publish and subscribe is a signal; Cedar and the topic gate already cap what it can do | Cassini |
| Stops answering, or answers late | A fresh challenge each round; a missed or stale answer lapses | the attestation agent |

**What remains:** an attacker who injects code into memory, spawns nothing, touches nothing outside the lock, and
behaves exactly as the agent does. Nothing above tells it from the agent. It cannot persist (read-only root, no writable
executable mount), cannot leave (the key cannot be extracted, the session is bound to the pod's address), and dies at the
next rejuvenation, within the hour.

**What remains, worked through (2026-11-03, open, for slice C's plan).** This first said only a hardware root closes it, through a TPM quote over IMA or confidential containers. That was wrong: IMA measures files as they are loaded, and its maintainer calls memory attacks out of its scope; confidential containers, as understood here and not checked, protect a workload from its host, not from code running inside it. So the gap is not one to leave to hardware, and it comes apart into what an attacker has to do:

- *Getting in makes noise.* A failed exploit crashes, and Scudo aborts on heap corruption (ASLR is on: `randomize_va_space` 2 on u7s). A seccomp filter that kills gives a blocked syscall away as `SIGSYS`. It needs no sensor: a crash by signal is evidence, to be explained and not retried past, and the attestation agent now reports it ("Slice B", below).
- *Running new code can be measured from outside.* From the node, each of the four agents checked had two executable mappings, the binary and `[vdso]`, none anonymous, and the 19 to 22 MB of its code read from `/proc/<pid>/mem` hashed the same as the file (u7s, as root in the node's user namespace, not yet from a pod with `hostPID`). A static binary's code does not change once loaded, so the expected hash can be a fact the build computes and the signed record carries. With the lock forbidding new executable memory, and Landlock keeping the process from opening `/proc/self/mem`, which on a default kernel can write through page protections, a new mapping or changed code is something the sensor can see. On u7s's kernel that write was refused from outside too (`EIO`), so the hash has not yet been seen to change. What is left is reuse of the code already there.
- *Code reuse has no good answer yet.* Shadow stacks are the direct one. Linux has them for user space, but musl's are a proposed patch series, off by default (August and September 2026), and Rust's flag was unstable when last read. Until then, `/proc/<pid>/syscall` gives a thread's stack pointer and program counter from outside, and a stack pointer outside its stack would show a pivot. That is untried, and only a sample.
- *Lying through its own rights is how to reason about what is left (the maintainer).* Eliminate the classes of attack that should not be possible in this architecture, and what remains is code that is Polar's own, whose invariants have either been modelled or have not. So false observations are not a gap for attestation to close: they are what the invariants are for.

**What an attacker is assumed to want, and what Polar wants (the maintainer, 2026-11-03).** Not exfiltration first: IO is to go through a callback registered at load that is hard to change at run time, which makes that difficult. Assume something worse: a long-term foothold. What Polar wants most is to detect an attack, and to go on operating through a compromise, knowing it is happening, able to shut it down at will and at its own choosing. So:

- *A captured crash is the most valuable thing here.* A container that dies by `SIGSEGV`, `SIGABRT`, `SIGSYS`, `SIGILL`, `SIGBUS` or `SIGFPE` is an event, kept, not a restart to look past. Built: "Slice B", below, with what it cannot see.
- *A foothold has to live outside the process.* The process dies within the hour, on a read-only root, with no writable executable mount. So it has to come back through what an agent reads when it starts: its volumes, its configuration, the graph, its upstream sources, or another agent's messages.
- *Against code reuse, take away the payoff.* Data is already not executable, and a ROP chain does not execute data: it uses the stack as a list of addresses in existing code. seccomp does not stop the chain running. It decides what the chain can reach: no `execve`, no `ptrace`, no executable memory. It can do more than the first design says, since a filter installed at run time knows where the binary was loaded, and can see a syscall's arguments and the address it was made from. So it could refuse any `mprotect` inside the binary's own image, which the callback above depends on, since read-only data stays read-only only if nothing can change that. Untried.
- *Turn on what the compiler allows (the maintainer).* See "Hardening the binaries", below.

**Hardening the binaries (read 2026-11-03).** `jira-observer` as shipped, on u7s: a static PIE, stack not executable, full RELRO with `BIND_NOW`, no shadow stack or IBT marking. The workspace sets only `+crt-static`, and no `[profile]`, so there is no LTO and arithmetic overflow goes unchecked. The toolchain is nightly (`workspace.nix`), so nightly's flags are open to it:

| Flag | What it adds | Note |
|---|---|---|
| `-Z stack-protector=all` | A canary, against the linear overflow that starts many chains | |
| `-Z sanitizer=safestack` (x86_64), `shadow-call-stack` (aarch64) | Return addresses out of reach: the part aimed at ROP itself | |
| `-Z sanitizer=cfi` | Indirect calls checked: jump-oriented reuse, not ROP | Needs LTO, and a rebuilt standard library to cover it |
| `-Z cf-protection=full` (x86_64) | Marks the binary for shadow stacks and IBT | Enforcing them needs musl's patches, not merged |
| `-Z branch-protection=bti,pac-ret` (aarch64) | Hardware checks of indirect branches and returns | Cannot be measured here |
| `-C overflow-checks=on` | Arithmetic overflow panics instead of wrapping | |
| `-C lto=fat`, `-C codegen-units=1` | Required by CFI | Long builds |

None of these has been tried on the static musl target, where some may not work. musl and Scudo are not Rust and need their own flags. Each costs something, to be measured in release with the Cassini harness.

*The cost:* reading code from `/proc/<pid>/mem` means the sensor can read any process's memory, the custody daemon's keys among them. It would no longer be the read-only reporter described below, though root on the node can do the same already. For the maintainer, with slice C's plan.

*Sources, read 2026-11-03:* [IMA and memory attacks](https://kernsec.org/pipermail/linux-security-module-archive/2019-April/012221.html); [musl's shadow stack patches](https://www.openwall.com/lists/musl/2026/09/20/1); [Rust's flag, a 2023 report](https://bugzilla.redhat.com/show_bug.cgi?id=2196282); [what a seccomp W^X filter can do](https://www.lkml.org/lkml/2022/4/20/1052); [rustc's exploit mitigations](https://doc.rust-lang.org/rustc/exploit-mitigations.html).

**A verdict is the attestation agent's; acting on it is the credentials agent's.** A lapsed or failed attestation is
published; the credentials agent, as body guard, stops renewing (the certificate is dead within the hour), and Cedar and
the broker may act sooner.

## The node sensor

`attestation/sensor`: one per node, a DaemonSet, read-only, with host PID visibility and no Kubernetes credential. For
each container of a Polar pod on its node it reports the processes in the container's cgroup, and for the agent's
process its `Seccomp` and `NoNewPrivs` state, to the attestation agent over Cassini. It acts on nothing and gives no
verdict. Its own pod is attested through the API like any other; what it reports of its own node is taken as part of
the trust base. It is Linux-specific, not Kubernetes-specific; on another platform its backend changes with the
attestation agent's.

## Deployments, next (the maintainer, 2026-10-26)

The maintainer plans to make the agents Deployments again instead of Jobs, now that Kubernetes 1.36 and later can run a
pod's init containers again when its workload container restarts, in place. A pod restarted in place keeps its UID
(`polar-init`, `898120b9`). So a rejuvenating credentials agent's successor is the same pod: the handover ticket can name
its UID, and the race in `core-restarts.md`, question 1, is left only for a pod that is really replaced (deleted,
evicted, or lost with its node). With in-place restarts the Reaper is mostly obsolete; it stays for older clusters. To be
taken up after this document.

**Checked (2026-10-27).** The feature is KEP-5532, "restart all containers on container exits": a container restart
rule whose action is `RestartAllContainers` restarts the whole pod in place, init containers (which must be reentrant)
and sidecars included, keeping its sandbox, UID, network namespace, IP and every volume, `emptyDir` included; restart
counts rise, and the pod carries an `AllContainersRestarting` condition while it restarts. Alpha in 1.35 (gate
`RestartAllContainersOnContainerExits`, on the API server and the kubelet), beta and on by default in 1.36, on top of
container restart rules (KEP-5307, beta in 1.35). On sandbox-local (v1.37.1) the API server accepted the action although
`kubectl explain` still describes `Restart` as the only one, and a pod (`restartPolicy: Always`, its container
`restartPolicy: Always` with a rule `RestartAllContainers` on exit code 1) whose workload exited every 8 s ran its init
container again each time (four runs, appended to one `emptyDir` file), under one UID and one IP. What it means here,
to be settled before the move:
- *The renewal rule meets the same UID.* The credentials agent refuses a second certificate of a type to a pod
  instance while the first is valid (`AlreadyHasValidCertificate`), and so does the held-request voucher; a pod restarted
  in place is the same instance, asking again before its certificate expires, which is why it rejuvenates. That rule is
  what makes rejuvenation need a new pod today, so changing it is a decision, not a detail. *Settled and built
  2026-10-27* (`deployments.md`, "The renewal rule"): a pod restarted in place is issued again, at most one certificate
  of a type in five minutes, and `AlreadyHasValidCertificate` is no longer given.
- *Kept bundles.* The `emptyDir` survives, so `polar-init` finds the last bundle (`keeps_existing_bundle`) and would keep
  it while it is valid, which at rejuvenation it still is.
- *Rollouts.* A Deployment's rolling update starts the new pod before the old one ends; a credentials agent (one ledger)
  wants `Recreate`, and the ledger lock is the backstop either way.
- *Init containers must be reentrant*: `polar-init` and the escrow bootstrap, run again in the same pod.

The plan for the move, with these settled one at a time: `deployments.md`.

## The plan (2026-10-28, for review)

Cleared to build, 2026-11-02 (the maintainer): slices A and B next, slice C once the OpenAPI and GitLab agents are on the builder (`remaining-work.md`, "The order of work").

Built in three slices, each tested and seen on a cluster before the next. This plans the first in full; the other two are
outlined, to be planned when the first is built.

### What was read for it

- *What it attests against:* a pod's owner chain and service account (the API); its containers' digests, the kubelet's
  `imageID` (`kubernetes/consume/src/lib.rs`, the attestation ladder: never the spec's tag); and the signed deployment's
  image lock (`infra/images.lock.nuon`, written into the signed `provenance.json` the deployment repository holds,
  `infra/deploy-repo.nu:407`). `sandbox-local` pins its images by digest (`pin_images`); it is the only target since 2026-11-02.
- *Who would ask, and where:* the credentials agent in its three vouching paths (workload issuance, between the renewal
  rule and the signing, `credentials-agent/consume/src/issuance.rs` steps 5 and 6; the held-request voucher,
  `held_voucher.rs`, `decide`; a custodian's fetches, `custodian.rs`, `handle`), and cert-issuer in its gate, for a
  ticket or a window (`cert-issuer/server/src/handler.rs`, `gate_on_token`).
- *How Kubernetes is read today:* kube-observer's `cluster_roles` capability grants get, list and watch on everything
  (`infra/config/capabilities.nuon:129`); the attestation agent needs far less (pods, and the ReplicaSets and Deployments
  that own them, in Polar's namespaces).
- *How a question is asked over Cassini:* request and reply topics with a correlation id, as the credentials agent's own
  are (`cassini-request-reply-protocol.md`).

### Not a gap: a token Kubernetes signs for the real pod

Raised in planning and set aside (the maintainer, 2026-10-28): a token minted for the real pod through the API
(`serviceaccounts/token`, bound to its name and UID) passes the instance check, since the check confirms the pod a token
names, not where the request came from. That is not Polar's to defend. Polar binds its root of trust to the platform it
runs on: the Kubernetes control plane, its signed tokens and its API, is the first item of the trust base above, and
whoever can make the API sign a token is already inside it. "What do you really expect me to do to defend against
that?" So no request is checked against its pod's address for this, and the ticket's note in `core-restarts.md` is
read the same way.

### Slice A, the plan: the attestor and the instance check at issuance

1. *The attestation agent* (`attestation/agent`, with `attestation/common` for the protocol): a catalog `agent`, not in the
   core, started after it. It watches the pods of Polar's namespaces and the ReplicaSets and Deployments that own them
   (a Role in each: get, list, watch, nothing else), so an answer is read from what it already holds, not a call to the API.
2. *The question and its answer,* over Cassini (`attestation-instance-requests`, `attestation-instance-replies`, a
   correlation id): the identity and the pod UID the token was bound to; the answer `Genuine`, or `NotGenuine` with why:
   no such pod, another owner than the catalog's for that identity, another service account, a container whose digest
   its Deployment does not pin, or an ephemeral container.
3. *The askers:* the credentials agent in its three paths, before it vouches; cert-issuer in its gate, before a ticket or
   a window admits. A `NotGenuine` is a refusal, recorded and logged.
4. *After the fact:* once up, the attestation agent attests every running pod against cert-issuer's record (each entry
   carries its pod UID), and reports any that fail: the bootstrap's certificates, and anything signed while it was away. Optional for now, not planned: "Optional features", below.
5. *Tests first,* as everywhere: the verdict a pure function of the pod, its owners, the catalog and the lock (a property
   over pods that differ from the genuine one in each way, and only those genuine pass); the askers refusing on
   `NotGenuine`; on the cluster, a pod of another image or owner running as a workload's service account, refused.

### What the images are checked against (the maintainer, 2026-11-02)

The plan above said "the digest the signed deployment pins" and not how the attestation agent learns it. Its nearest precedent, a section signed at
`up.nu`'s seed step, cannot be what issuance waits on: the seed runs after Flux has replaced the pods. Nor can anything delivered, alone: Flux may replace the scheduler
observer first, its new pod needs a certificate, the attestation agent does not know the new digest yet, and only that observer could tell it. So there are two
checks, with different jobs.

- **At issuance, the pod against its Deployment.** Each container's `imageID` (the kubelet's) is the digest its owning Deployment pins. It is immediate, and it cannot
  deadlock a rollout. Flux applied that Deployment from the signed commit, and whoever can change it is inside the trust base.
- **Continually, the Deployments against the signed record.** `deploy-repo.nu publish` writes the deployment's facts into the commit as a signed document. The configuration agent
  reads it from the deployment repository on Polar's own git server (`deployment_record.rs`) every 30 s and publishes it as it is on a topic of its own, again each time, so an agent that has just
  started hears it. It does not go down the configuration path: nothing there may verify a document against another CA, and adding that for one section would be the first special case
  of many (for review). The attestation agent compares every Deployment and StatefulSet with it each minute, and logs an ERROR for a difference that has lasted ten minutes, since a record and
  what Flux applies from the same commit do not arrive together. A pin changed behind Flux gets a certificate first and is caught here: "attested after the fact", as cert-issuer's entries are.
  Until the copy reaches Polar's git server there is no record, so every identity is answered `CannotSay`, and the first document attests what is running.
- **What is under test, said apart** (2026-11-07, `configurations-under-test.md`, CT2). The record is schema 2: each workload says `under_test`, true for what a
  configuration under test's layer holds (`deploy-objects.nu` `deployment_facts`, from the `layers/under-test-*` files). The agent reads schemas 1 and 2, and refuses a
  schema 1 that marks anything (`attestation/common/src/record.rs`). A lasting difference about a workload under test is logged at WARN with `under_test`, the rest
  at ERROR; a report on `attestation-reports` carries `under_test`, true when the record claims its pod, by namespace and service account and for one workload alone,
  for a workload it marks (`report.rs` `findings`); the credentials agent records it in the ledger's `AttestationReported` (an entry recorded before reads as
  not under test) and logs it at WARN. Verdicts are not marked: a pod under test is held to the record as any other.

*The document.* A `polar-signing` document in a signing domain of its own, signed by the `pipeline` certificate (P-256 since 2026-11-02, so it can be), chaining to the deployment CA and not Polar's. The configuration agent
is not trusted: the attestation agent verifies the document itself, and trusts the deployment CA for this section alone, so the deployment PKI gains no authority over anything else. The CA's
certificate reaches the agent through the signed render. Its version is a counter in the record, which moves only when its facts do (`next_record`, for review; this first said the commit's height): a height would change with every publish, so publishing the same render could never leave the repository as it was.

*Built (2026-11-02):* `deploy-repo.nu publish` writes it to `deployment-record.json`, signed by `polar-sign record` in the domain `polar-deployment-record-v1`. The attestation agent believes it only if it verifies for that domain, its signer is `pipeline` (Flux's certificate is under the same CA), and its version is not older than the one held (`attestation/agent/src/record.rs`). What differs is `Drift` (`attestation/common/src/record.rs`). Run on u7s and u7c: on u7c, an image changed by hand with Flux suspended was reported after ten minutes, and as gone a minute after Flux put it back.

*To decide later:* the report is a log line, and slice B is what acts on it. The agent holds its record in memory, so a restarted agent can be sent an older signed record once, by whoever can publish on that topic. That is `CannotSay` or a stale comparison until the next delivery, and not a way past the instance check, which holds a pod to its owner regardless.

*What it says (proposed by the agent that wrote this, for review).* For each workload: its identity, its owner's kind and name, its service account, and each container's digest.
These are the same facts the instance check needs for "the workload the catalog says this identity runs as", so one document carries them, computed from the rendered manifests
by `publish`, in line with "applying the catalog is the sign-off". An identity no document names yet is answered as if the agent could not be asked: issued, recorded as made
without attestation, and attested once the document arrives. An identity it names, on the wrong owner or service account, is `NotGenuine`.

### Slice A, the askers: the plan (2026-11-02, for review)

What makes a `NotGenuine` refuse a certificate. Built: the shadow commit (1, below) ran first, then the agent proving itself (`attestation-when-it-cannot-answer.md`), then refusing.

**Where the questions go in.** Item 3 above says three paths in the credentials agent. Reading the code, there are four entries, and cert-issuer:

| Who | Where | What it asks about |
|---|---|---|
| Credentials agent | `IssuanceHandler::handle` (`issuance.rs`), which the sealed route (`workload_issuance.rs`) comes through too, for a Kubernetes credential. An IdP's is a person's, with no pod behind it to ask about | the token's identity and pod |
| Credentials agent | `custodian.rs` | the pod the custodian's certificate names |
| Credentials agent | `agent_escrow_issuance.rs` | the same |
| Credentials agent | `HeldVoucher::decide` (`held_voucher.rs`), for what cert-issuer holds | the offer's identity and pod |
| cert-issuer | `gate_on_token` (`handler.rs`), when it admits on a token: `Gated::Token` and `Gated::Ticketed`. Not `Gated::Vouched`, which the credentials agent has judged | the claims' identity and pod |

A custodian's identity is asked about as its service's (`custodian_of`), since the record names the service, and the custodian runs in its pod.

**Before the renewal rule.** The diagram has the renewal rule first. It has to be after: `LedgerMessage::Admit` records, so a refused pod would have used up its type for five minutes. `HeldVoucher::decide` already asks it last for that reason.

**One way of asking.** An `InstanceAsker` actor in each asker (`attestation/common/src/asker.rs`), with a reply topic of its own, says `Genuine`, `NotGenuine(why)` or `CouldNotAsk`:
- A reply is taken only from the attestation agent's identity as the broker stamped it, with the question's correlation id.
- `CouldNotAsk` is at once if the Cassini session is down, and otherwise after a wait of 2 s. So a first bring-up, when nothing can be asked, does not wait: cert-issuer signs the core as it does now. `CannotSay` is treated the same.
- `CouldNotAsk` issues, as the maintainer decided (item 3 of "For the maintainer"), and records that it did: `IssuedUnattested` in the credentials agent's ledger, and `unattested` in cert-issuer's record entry. Both are additions, so an existing log still reads. Nothing reads them: they are an audit trail, and attesting afterwards is optional ("Optional features", below).
- `NotGenuine` is a refusal with its own reason (`IssuanceRefusalReason::NotGenuine`, `AgentEscrowIssuanceRefusalReason::NotGenuine`, a refused held request, or cert-issuer's `CallerNotAuthorized`), logged and in the ledger (`InstanceRefused`) where the credentials agent is the one asking. A ticket that admitted it is given back, since nothing was signed against it. `polar-init` stops on a refusal, and the pod restarts in place and asks again.

**Shadow first.** A false `NotGenuine` is the failure to fear: pods replace themselves hourly, so a wrong rule would take the cluster down within the hour. So it goes in two commits, with no switch left behind:
1. The askers ask, log the verdict, and act on nothing. It runs on u7s and u7c through a full rollout, each core member killed in turn, and `kubectl debug` on a pod. Every `NotGenuine` and `CouldNotAsk` is read. (Done: "What the shadow run found", below.)
2. Then they refuse, with a pod of another image running as a workload's service account refused on the cluster.

**What is known already.** Measured 2026-11-02 on both clusters: every one of the 122 running containers has an `imageID` with the digest its spec pins, and no pod has an ephemeral container.

**What the shadow run found** (`6d2ed6d6`, release images, 2026-11-03; u7s single-node, u7c with node pools). Each cluster: a rollout of every agent that is not core, each core member killed in turn, a rollout with the attestation agent scaled to nothing, then an hour and more of pods restarting in place, with `kubectl debug` on one pod.

| | u7s | u7c |
|---|---|---|
| Asks | 112 | 93 |
| `Genuine` | 92 | 75 |
| `NotGenuine` | 2 | 2 |
| `CouldNotAsk` | 18 | 16 |
| Answer, median and slowest | 48 ms, 83 ms | 80 ms, 83 ms |

- *`NotGenuine`.* All four are the pod with the debug container, `EphemeralContainer`, at its next renewal, and it went on running since this is shadow. No genuine pod was called anything else.
- *`NoSuchPod` while the agent is ready.* Not seen, so the second ask this first proposed is not built.
- *`CouldNotAsk`.* Each lines up with something being down: Cassini (`NoSession`, answered in 0 ms), the attestation agent's own two certificates each time it starts, since it cannot answer for itself, and the rollout with it scaled down. Two more were cert-issuer's on the first rollout: the agent it replaced answered on a family over kinds `agent` and `run`, and cert-issuer is kind `ca`, so it could not be answered, as the code reads (not tested separately). It has been answered since.
- *The 2 s wait.* Well over the slowest answer. With the agent down it costs 2 s for each of a pod's two certificates, which added about 5 s to a rollout (57 s against 52 s), so nothing shortens it.
- *Not run live.* `agent_escrow_issuance.rs` asked nothing on either cluster: it runs only at a workload's first escrow certificate, and both clusters already had theirs. Its unit test covers it; a clean install would run it.

**What refusing found, on u7s and u7c (`84237da6`, 2026-11-03).** Each cluster: a rollout of every agent with refusing on, each core member killed in turn, a rollout with the attestation agent scaled to nothing. All pods came back, and no genuine pod was refused, on either cluster. Run on purpose:

- *A pod of another image, as `jira-observer`'s service account, with no owner:* refused, `NoOwner`, and it sat in `Init:Error` with no certificate (u7s).
- *The same, with the agent restarted and no record to be had (the configuration agent stopped):* refused the same, on both; a genuine pod in that window went ahead, `CannotSay`, and was recorded as unattested.
- *A real pod's image patched in place:* refused at its next ask, `AnotherImage`, naming the digest its owner pins (u7s).
- *A real pod given a debug container:* refused at its next renewal, `EphemeralContainer`, within the hour, and replacing it cleared it (u7s).
- *A debug container on the agent's own pod:* within 30 s it logged `NotGenuineItself` and answered `CannotSay`, so the intruder above was given a certificate, recorded as unattested, as decided; replacing the agent brought refusing back (u7s).
- *The agent down while the credentials agent restarted:* cert-issuer signed on the token and its record says `unattested` (u7c).

Read on disk: the ledger held `InstanceRefused` and `IssuedUnattested`, each of the latter with its serial, and two tampered pods among 24 did not make the agent doubt itself.

**What refusing will do to a debugged pod.** A `kubectl debug` marks a pod for the rest of its life. With refusing on, it runs until its next renewal, within the hour, then its `polar-init` is refused, and it restarts in place and is refused again until someone replaces it. So debugging a pod costs that pod, with no more warning than the hour, and it was seen to on u7s. That is the verdict's intent and slice B's direction, but it should be said where an operator will read it, and whether the Reaper replaces such a pod is open.

**The topics are named.** This first said the agent answers on a family over every served workload. Only those who vouch ask, so that family put a publish for every other agent in the attestation agent's certificate that nobody hears, each one-sided in the catalog's cross-check. The agent declares `attestation-instance-replies.cert-issuer` and `attestation-instance-replies.credentials-agent`, and an asker added later adds its name.

**Why `CouldNotAsk` issues (the maintainer, 2026-11-03).** Refusing when the agent cannot be asked is how an admission webhook takes down the cluster it guards, and here it would deadlock, since the attestation agent needs a certificate itself. Failing open answers only the agent being unreachable: an agent that is up and wrongly says no is what the shadow run is for. `attestation-when-it-cannot-answer.md` has how Kubernetes, Gatekeeper, Kyverno, Anchore and Sigstore handle this, why there is no setting for the other answer, and how the agent proves itself before its verdicts are believed.

**What it does not change.** The floor's rules still apply to what the agent says is genuine, and a compromised attestation agent can refuse but cannot admit. Stopping the attestation agent turns the check off, recorded as unattested, which is the decision's cost and also the way out of a wrong verdict: whoever can do that is inside the trust base.

**Pod-less requests.** What an account's path issues (`account.rs`) has no pod and does not come through here. A Kubernetes token with no pod claim is refused earlier, so what reaches the check always names one.

**After it:** attesting what was signed while the agent was away was to come next, and is now optional ("Optional features", below).

### Optional features (the maintainer, 2026-11-03)

Ideas worth keeping, none of them planned. Polar builds for the happy path and lets things fail, so these wait until something shows they are needed. Read on u7s, 2026-11-03.

- **Attesting after the fact.** A pod signed while the attestation agent could not answer is judged only at its next renewal, within the hour, so nothing checks it until then. The shape that fits best: the attestation agent asks the credentials agent which pods hold in-date certificates, judges them, and publishes any that are not genuine, for the credentials agent to log and record. Each agent keeps what it owns, cert-issuer does not change, and it costs named topics for the question, the answer and the failures. A pod already gone is not a failure, since a certificate outlives its pod after every rollout. To check first: that the ledger can answer this cleanly, and that cert-issuer's record holds every certificate it signs.
- **Other shapes of it, set aside.** The attestation agent reading cert-issuer's record itself, as item 4 of slice A and the instance-check diagram's DESIGNED box still say: cert-issuer answers only the credentials agent (`record.rs`), its answers go out on one topic, and that request is also the credentials agent's presence, which keeps the crash window shut. The credentials agent doing the asking, with a durable list of what is open: it widens the credentials agent's role, and a bug in it would go unnoticed. The credentials agent broadcasting the list: a question and answer is what agents already do for this.
- **Revoking on a failure found afterwards.** Reporting leaves a bad pod its certificate until it expires, up to an hour. Revoking at once only here would treat a pod caught this way more harshly than one debugged after it was attested, so it belongs with whatever slice B does about a lapse.
- **What the markers miss, if something comes to read them.** A record entry's `unattested` is not copied into the ledger (`ReportedCertificate` has no such field), and cert-issuer's own client certificate is never marked, since it is signed with nobody to ask. On u7s the ledger held 108 `IssuedUnattested` entries, 34 of them on pods still running; 25 of cert-issuer's own entries named a pod.

### Slice B: watching, report only

A pod that changes after it was attested: an ephemeral container added (`kubectl debug`), a container restarted on another
digest. And a container that dies by a signal ("What an attacker is assumed to want", above). The attestation agent reports it, and the credentials agent, as body guard, logs and records it.

**Built (`45cdb0eb`, seen on u7s only, 2026-11-03).** The attestation agent holds every pod to its owner, needing no identity, and reads how each container ended. It publishes on `attestation-reports`. The credentials agent takes a report only from the agent as the broker stamped it, logs it, and records one `AttestationReported` in its ledger. A crash goes at once, even while the agent doubts itself, since the platform saw it and it is no judgement of the agent's. A pod's watch and its owner's are separate streams, so a new pod can come before the owner that explains it, and an alteration has to stand at two checks running, a minute apart. What stands goes again each minute, and the ledger keeps one of each.

*Run on purpose:* the anonymous writable memory of a running `jira-observer` overwritten from the node, as corruption would: it died by `SIGSEGV`, and the report was in the ledger within a second. `kubectl debug` on `jira-processor`: `Altered(EphemeralContainer)` recorded 92 s later. Then a rollout of every agent not in the core, which Flux undid in a second rollout, with the credentials agent replaced between them: all 20 pods came back and nothing else was reported, and each report was recorded once. No pod was refused. Those rollouts issued 71 certificates unattested (53 `CannotSay`, 18 `NoAnswer`), since each replaced the attestation agent.

*What it found, and what it cannot see:*
- *Kubernetes does not keep the crash.* A container's death makes the pod restart all its containers, and seconds later its `lastState` says exit 137, `RestartingAllContainers`. The report caught it only by seeing the moment between. So a crash while the attestation agent is down, or in the moment its watch has lost the API, is gone for good, and exit 137 in a pod's history says nothing either way.
- *A musl `abort()` as PID 1 exits 139, not 134.* Every agent is PID 1 in its container, where the signal is ignored and musl falls through to a fault (a static musl test as namespace init: `SIGSEGV` 139, `abort` 139, `SIGILL` 132, a seccomp kill 159). So a Scudo abort should read as `SIGSEGV`: caught, and mislabelled. No Scudo abort has been seen for certain, since the corruption above left nothing in the log to say which it was.
- *A Rust panic is not a signal.* ractor catches it in an actor, so a tripped bounds check is not seen here and needs a route of its own.
- *The credentials agent's restart with a report standing* has only its unit test: the rollout had already replaced the pods reported.

**Report only (the maintainer, 2026-11-03).** This first said the credentials agent stops renewing and may revoke. Polar wants to go on operating through a compromise and shut it down at its own choosing, so the report acts on nothing. Refusing at renewal stays as it is, so a tampered pod is still refused within the hour, and a faster shutdown is a signed revocation, by choice.

### Slice C, outlined: the node sensor and the process

`attestation/sensor` (a DaemonSet, host PID visibility, no Kubernetes credential), the runtime challenges answered by a
builder actor, the builder's seccomp and Landlock lock, and Cassini binding each session to the attested pod's address,
as the sections above describe.

**Found planning it (2026-11-10, on u7c).** The table above claimed more than there is. No Polar container sets
`readOnlyRootFilesystem` or `allowPrivilegeEscalation: false`, none runs under a seccomp profile (an agent's `/proc/1/status`
reads `Seccomp: 0`, `NoNewPrivs: 0`), and the attestation agent checks none of it. Two agents run a program: polar-git-server
and polar-scheduler-observer run `git`.

**Decided (the maintainer, 2026-11-10):**
- *No code hash in slice C.* The sensor runs as uid 1000 with no capability and reads `/proc/<pid>/status` and `maps`: a
  process in the container that is not the agent, the agent's `Seccomp` and `NoNewPrivs`, and an anonymous executable
  mapping, which is what injected code looks like once the lock forbids new executable memory. It cannot read the custody
  daemon (another uid, not dumpable). Reading code from `/proc/<pid>/mem` needs `CAP_SYS_PTRACE`, which reads any process on
  the node: a decision of its own, later.
- *No agent runs a program.* polar-git-server and polar-scheduler-observer move to git in process first, so every agent
  gets the one lock with `execve` refused.
- *No runtime challenges.* What a process says about itself is worthless against code inside it, and an answer shows only
  that something holding the session is alive, which the health actor and the sensor show already. The verdict on a running
  pod comes from the API and the sensor.
- *A session is bound to its pod's address through the certificate.* At issuance, once the instance check has the pod, its
  address is written into the certificate beside its name, and Cassini refuses a session from any other.
- *Canal with the sensor.* Enforcing NetworkPolicy on u7c (`build-orchestrator.md`, the network step, N3: Flannel and Calico's
  nftables dataplane, rootless, IPv4) is done beside the sensor, both being node work in `nix-usernetes`, and the builds'
  policy and canary (N1, N2) follow it.

**When a node cannot give a protection (decided, the maintainer, 2026-11-10: "run, report, policy may require").** Nothing
here is assumed of a node: each protection is probed where it is used, an agent runs with what its node gives, says exactly what
it lacks, and attestation records that per pod, so a gap is visible and never pretended. A cluster's signed policy may require a
protection, and then a pod without it is refused its certificate. Probed on whitey, 2026-11-10: kernel 7.3, Landlock ABI 11
(`lsm=landlock,yama,bpf`), seccomp available; u7c's nodes share that kernel.

| Bite | Needs of the node | How its absence is found | Then |
|---|---|---|---|
| C1 | a runtime that supports seccomp profiles (a read-only root and no new privileges are core) | the pod does not start under the profile, or reads `Seccomp: 0` | it runs unconfined, recorded as a named gap, not as a tampered pod |
| C2 | nothing | | |
| C3 | seccomp filters (Linux 3.5); Landlock (5.13, enabled among the LSMs), by ABI version | probed at start: seccomp's action check, Landlock's ABI | the lock is as much as the kernel offers; the agent says which (seccomp, Landlock ABI n or none) in its health answer and to the sensor; attestation records it |
| C4, Canal | a cluster whose CNI Polar chooses (true of `nix-usernetes`, not of most managed clusters) | the canary (N2) | standard NetworkPolicy, so any enforcing CNI serves; where none enforces, the canary says so, builds of foreign code are refused (N2), and the cluster's status names it |
| C4, the sensor | pods allowed `hostPID` (Pod Security `privileged` for its namespace; refused on some managed clusters) | the DaemonSet's pod does not run, or a node sends no report | that node's pods are recorded as having no process evidence; the API's checks stand |
| N1, N2 | an enforcing CNI | the canary | as decided: no build of foreign code where enforcement is not proved |
| C5 | pod addresses reaching Cassini unchanged (no SNAT, no mesh rewriting the source) | a canary session at bring-up; Cassini counting mismatches | the binding is turned off for that cluster by a signed setting, never silently, and the record says so |

**The bites, each seen on u7c before the next:**
1. *C1, the pod hardened and checked.* Every Polar container gets a read-only root, `allowPrivilegeEscalation: false` and
   the runtime's default seccomp profile, what an agent writes on volumes; the attestation agent holds a pod to them as it
   holds it to its owner. **Built 2026-11-10, and seen live on u7c the same day** (below). The render (`7332f2b2`): `HardenedSecurityContext` on every
   agent, polar-init, the custody daemon and cert-issuer; read on u7c first, none writes to its root but the `/etc` files the
   runtime mounts, so none needed a volume (the third-party images do write, and come later). The check (decided while
   building, for review): the signed deployment record, schema 3, says how each container was rendered to run
   (`hardening`: `read_only_root`, `no_privilege_escalation`, `confined_seccomp`, from `deploy-objects.nu` `hardening_of`), and
   the attestation agent holds both a pod (`NotGenuine::Weakened` at issuance) and a Deployment's or StatefulSet's template
   (`Drift::Weakened` while watching) to it, reading them as Kubernetes does (`holdings.rs` `hardening_by_container`). So a node
   that cannot give a setting is a target rendered without it, named in its signed record (the fallback above), and anything
   less than what was signed is an alteration. A record before schema 3 says nothing, and holds nothing to it.
   *Seen live on u7c, 2026-11-10 (agentic-control-plane, by its session):* all 70 of Polar's own containers run with a
   read-only root, `allowPrivilegeEscalation: false` and `RuntimeDefault`; every agent up; the deployment record is schema
   3, with hardening for each container (72 fully hardened; the 14 not are third-party containers and polar-builds' `fetch`
   and `pipeline`, whose roots are writable); the attestation agent holds the record, 32 pods judged, none condemned, no
   `Weakened` drift. One agent failed at first: the build orchestrator's worker locked itself with seccomp's strict mode,
   which the kernel refuses under a filter, and `RuntimeDefault` is one; its lock is now a filter allowing what strict mode
   allows (`385c6f21`, `build-orchestrator.md`), seen with no restart past five minutes, the agent at `Seccomp: 2` with
   one filter and its worker with two.
2. *C2, git in process* for polar-git-server and polar-scheduler-observer.
3. *C3, the builder's lock*, installed in `run` before the runtime starts: seccomp refusing `execve`, `ptrace`,
   `memfd_create`, new executable memory, `bpf` and module loading, by killing (a `SIGSYS` slice B catches); Landlock
   allowing only the paths the agent's build declares (its document, certificates, the custody socket, its volumes, what
   name resolution reads), printed in its scaffold so applying the catalog signs them off. In two bites (the maintainer,
   2026-11-11): seccomp first, then Landlock after a short plan of its own (which variables are paths, the platform's
   fixed paths, what the scaffold prints), since nothing says yet which of an agent's variables name files.
   - *C3a, seccomp.* **Built and seen live on u7c 2026-11-11** (`polar-agent-builder/src/lock.rs`). *Live:* `up.nu` brought
     every pod up, and each of the 24 builder agents (cassini and cert-issuer among them) said `locked: seccomp refuses …`
     as it started, none `not locked`; after fifteen minutes no container had restarted or ended, the attestation agent
     had found nothing, there was no warning event, and the egress probe still reached the outside.
     Read for it: no builder agent runs a program (every `Command::new` outside the CLI tools is in a test), workers
     already lock themselves further, and slice B already reports `SIGSYS` as a crash (`report.rs`, `CrashSignal::Sys`).
     The filter kills `execve`, `execveat`, `ptrace`, `memfd_create`, `bpf`, `init_module`, `finit_module`,
     `delete_module`, and `mmap`, `mprotect` and `pkey_mprotect` asking for `PROT_EXEC`; a call of another architecture,
     or with x86-64's x32 bit, is killed too, as the worker's filter does (an x32 number carries the same architecture,
     the classic way round a deny list). Everything else passes to the runtime's own filter. `run` installs it, with no
     new privileges and `TSYNC`, once the workers are forked and before the runtime, and says so on standard error;
     `run_with`, which tests use to run agents in their own process, does not. A kernel that will not take it leaves the
     agent running and saying so ("run, report, policy may require"); the sensor reads `Seccomp` from `/proc` itself (C4).
     *Decided while building, for review:* `process_vm_readv` and `process_vm_writev` are refused with `ptrace`, being
     its way of reading and writing another process's memory; the health answer does not carry the lock's state, since
     the sensor reads it and a field would change the health report's wire type. *Tests:* the filter run through an
     interpreter of its own instructions, for any architecture, call and arguments, kills exactly what its rule refuses
     (a property); in child processes, under the real lock, each refused call dies by `SIGSYS`, and an agent's ordinary
     work (threads, a runtime, a connection, a name resolved, files, memory) goes on, with `Seccomp: 2` and
     `NoNewPrivs: 1` in its status.
4. *C4, Canal and the node sensor*: a spike of Canal rootless, then enforcement on u7c, and the sensor (a DaemonSet, a kind
   the catalog gains), its traffic limited by policy to Cassini. *Kept as planned (the maintainer, 2026-11-11)*, when asked
   whether Canal still belonged here given that Polar should take on no more dependencies on Kubernetes. The other option
   was Landlock's port rules, which the builder could compute per agent with no Kubernetes involved but which say only
   ports, not destinations.
5. *N1 and N2*, the builds' policy and its canary.
6. *C5, the session bound to the pod's address* through its certificate.

### The witness of the store's logs: the plan (2026-11-11, cleared as written by the maintainer the same day)

The record store's bite 5 (`record-store.md`, decision 6 and "Bite 5, the witness: the plan", which is the store's
side and the co-signature's form; this is the witness's). The attestation agent co-signs each checkpoint of each of the
store's logs, so a store that rewrites, forks or rolls back a log is caught by a second party and not only by a
reader who happens to compare. Read: C2SP tlog-witness, tlog-cosignature and signed-note (the editor's copies,
2026-11-11). *Decided (the maintainer, 2026-11-11):* the co-signature is P-256, outside C2SP's two algorithms, so only
Polar's code checks it; the store makes a checkpoint at its start and at most once a second while entries arrive;
readers require the witness's co-signature; the witness's key is a file on a volume of the agent's own; plan, then build.

**It reads no entries.** The store brings it each checkpoint as tlog-witness's `add-checkpoint`, and it checks a
proof, keeps a size and signs. What a log holds is a monitor's to check, a later bite.

**What it is.** A domain actor of the attestation agent, the witness, beside the supervisor: its held checkpoints are
its own state, which nothing outside reads (`soft-state.md`, "Self-state and introspection"). One request at a time,
so its check and its write are one step, as tlog-witness requires (two requests overlapping must never roll the held
size back).

**Over Cassini.** The store asks on `attestation-witness-requests` and is answered on its own topic,
`attestation-witness-replies.polar-git-server`, named for it as the instance check's askers' are
(`attestation_common::protocol`); both in `attestation-common`, rkyv in the shared envelope. A request is
`AddCheckpoint { old, proof, checkpoint }`: the size the store believes the witness holds, the consistency proof from
it, and the signed checkpoint as a note. The answer names the checkpoint's origin and size, so the store matches it to
what it asked, and is one of: `Cosigned(line)`; `Conflict(size)` (409: the size the witness holds); `Refused(why)`, with
tlog-witness's reasons, `Malformed` (400: `old` beyond the checkpoint's size), `Untrusted` (403: no verifying signature
from the store's pinned key), `UnknownOrigin` (404: an origin not under the pinned store's name) and `Inconsistent`
(422: the proof fails, two roots for one size, a proof from size 0, an empty tree whose root is not the empty one). A
request whose sender the broker did not stamp, or stamped as another identity than the store's, is dropped with a
warning, as an unverified question is (`supervisor.rs`, `reply_topic_for`).

**The checks, in tlog-witness's order**: the checkpoint verifies under the store's pinned key; `old` is at most its
size; `old` is the size held for that origin (none held: 0); an empty tree has the empty root; the proof is empty from
0 and holds otherwise; equal sizes have equal roots. Then the new checkpoint is kept, and only then signed and answered.
Every origin under the store's name is witnessed, each on its own; the first submission for one is from 0.

**Its key and what it holds**, on a claim of its own (`persistent-data`, `/var/lib/attestation-agent/witness`; one pod,
replaced by `Recreate`, as `rules.nu` requires of a claim):
- *The key*: P-256, `witness-key.pem`, 0600, made at its first start and never replaced, as the store's
  `checkpoint-key.pem` is. *On main* the crypto actor makes and holds it (`POLAR_WITNESS_COSIGNING_KEY`, the `keys`
  section) and the witness co-signs through its `CosignHandle`, so the domain holds no key. Named `<identity>/witness`, its identity from its certificate, as
  the store's key is `<origin>/checkpoint`. It signs co-signatures and nothing else; the agent's evidence records are
  signed in custody, by a key per pod (`key-custody.md`, "Workload signing keys"), which readers could not pin.
- *What it holds*: one file of every origin's last co-signed checkpoint and its time, written whole to a new file,
  synced, renamed over, the directory synced, before the answer goes. The key and the file are made together: a key
  with no file, or a file that does not read or whose checkpoints its own key did not sign, is damage, and the witness
  answers nothing and says so (held, never started again from 0, which would co-sign whatever came next). A lost claim
  loses the key with the state, so readers, who pin the key, refuse what a new witness signs until a person pins it
  again: losing its memory can never pass for consistency.
- *Its time*, T in each co-signature: its clock in seconds, never before the last T it signed for that origin, as the
  store's admission time never goes back. A reader refusing a T a minute in its future is the store's plan's.
- *Signing*: with polar-log's co-signature code (`0xff` and `polar.dev/cosignature/p256/v1`, the store's plan), never
  one of its own.

**Whom it witnesses.** The store's verifier key, in the agent's section as a `Dynamic` variable
(`POLAR_ATTESTATION_WITNESSED_STORE`), set by a signed runtime section via polar-schedules, the design principle for what
an agent must know of another; until the credentials agent certifies the store's key and the witness's (decision 5).
Unset, it refuses every request as `UnknownOrigin` and says so once. The store learns the witness's key the same way
(its plan). So a first deployment has one step for a person: both start and log their verifier keys, and an
administrator signs the update that pins each in the other. *Decided (the maintainer, 2026-11-11): up.nu does it, on
any target, as the `--user` who runs it:* it waits for both keys to be logged and signs the update, which is the
record, as it would be by hand.

**What it does with misbehaviour.** It sees and reports; it never acts. A conflict alone (409) is not misbehaviour (an
answer lost, a store restored from its own last co-signed checkpoint) and is said at info. A checkpoint the store's key
signed that cannot follow what the witness co-signed is: an inconsistent one (422), or one smaller than the size held
(a signed rollback, answered 400 after the store's 409 retry). For those it signs nothing, logs an error, publishes a
finding on `attestation-reports` (a new `Finding::LogInconsistent`, carrying the origin, the held size and root, and the
offered ones) and records it as an `attestation-report`, a type its certificate names already. The record goes
through the store it reports on, which may drop it; the report and the log line do not. *The new finding changes the
report's wire type, which the credentials agent decodes: both are built from one tree and deployed together.*

**Tests first.** Each check and its answer, by example; the key and the file made together, and each damage refusing;
the write before the answer (an answer is never sent for a checkpoint a restart would not find). Properties, as a
state machine: for any sequence of submissions, honest, forked, rolled back, repeated or out of order, the witness never
co-signs two checkpoints of one origin that are not consistent, its co-signed size and T never go back, and a restart
between any two changes neither. Live on u7c, after the store's side: the pin step, a co-signed checkpoint served,
`polar-eden fetch-log` holding both keys, and the agent's pod deleted and replaced, its key and held sizes the same and
the next checkpoint co-signed.

*Built (2026-11-11), the witness's side; live on u7c waits for the store's:* `attestation_common::witness`, the wire
form; `attestation-agent`'s `witness.rs`, the judgement (`judge`), what it keeps (`Kept`: the holding made first, then
the key; either alone is damage), its co-signature through polar-log's `Cosigner`, each held checkpoint's line checked
against its own key at start (`check_holding`), and the actor, one request at a time, which follows
`POLAR_ATTESTATION_WITNESSED_STORE` from its own start; the supervisor hands it what arrives on
`attestation-witness-requests` and turns its misbehaviour into a `LogInconsistent` report of the store's pod, published
and recorded as the agent's other findings are. The catalog gives the agent `persistent-data` and
`POLAR_ATTESTATION_WITNESS_ROOT`. *Decided while building, for review:* a pin naming another store than the one the
agent's own certificate implies (`polar_agent_builder::recorder::server_identity`) is said and not taken, so a signed
section cannot point the witness at another workload's key; a pin that is a witness's key named like a store's is
refused, since only a key of type `0x02` signs checkpoints; a co-signature that could not be kept is not sent, and the
store asks again at its next checkpoint; with what it keeps damaged the agent runs on without its witness, and says so
once a checkpoint arrives, rather than holding its other work. *Tests:* each check and its answer; a co-signature
verified by a reader holding both keys, with the witness's time; the store alone answered; a fork refused and handed
on; a pin of another store not taken; a misbehaviour said of the store's pod alone; the state-machine property above,
which fails with the consistency check removed or the time taken from the clock alone.

*The pins, in up.nu's seed (2026-11-11):* `seed_witness_pins` reads each key where its owner logs it at start (the store's
"the store's logs are open", the witness's "the witness of the store's logs is ready", each a `key` field), waiting up to
three minutes for each, and signs it as the other agent's first settings (`permanent/<agent>/configuration.dhall`) as
the one who runs up.nu, in the seed's commit. *Decided while building, for review:* a pin is signed only when the agent
has no settings yet, and is left as it is otherwise, said: pinning again on every run would let a witness (or a store)
that lost its key and memory pass for the one readers trust, which the plan makes a person's step; a key not said in
time is noted, and the next run pins it. *Tests* (`infra/tests/seed.nu`): the key read from a coloured line, the last
said, and no other field; each pin the other's key; only a missing one signed.

*Live on u7c (2026-11-11, agentic-control-plane 4af66add, a whole up.nu run, before the witness came to main).* The attestation agent's claim was made
and its witness key with it; the seed read both keys from the two logs and signed both pins as djshepard ("pinned in
attestation-agent", "pinned in polar-git-server"); each agent took its pin as a signed update (`witnessing=true`,
`pinned=true`). The store submitted the evidence log, 13 leaves, from 0; the witness co-signed it, and
`polar-eden fetch-log` with both keys fetched it, the checkpoint carrying both signatures, and held it to the checkpoint
remembered from the day before. After the attestation agent's pod was deleted and replaced, its key was the same, it held
the evidence log at 13, took its pin again on start, and co-signed the next checkpoint (14 leaves), which `fetch-log`
read. 26 pods running, no restarts, no attestation findings, no warning from either side's witness actor but the store's
one before the pins.

*On main (2026-11-14, the record store's bite 2, `docs/plans/record-store/to-main.md`).* The witness as built above, with
its key the crypto actor's: the actor makes `witness-key.pem` under `POLAR_WITNESS_COSIGNING_KEY` (the catalog sets it
to `<POLAR_ATTESTATION_WITNESS_ROOT>/witness-key.pem`, where acp made it, so the pins on u7c hold), follows
`POLAR_ATTESTATION_WITNESSED_STORE` itself and refuses to co-sign for any other store, and gives each co-signature's T
from its clock. The pin is declared once, by the `keys` section, not by the agent's own. Since the witness no longer
makes the key, "a key with no file" cannot be judged by the file's presence: the holding (`witnessed.json`) now
records the verifier key it was made under, `{ key, origins }`, and a holding recorded under another key than
`CosignHandle::key()` is damage. A holding in the earlier form (the origins alone) is taken once every line in it
verifies under the actor's key, and written again with the key. A T that would go back on what is held for an origin
is neither kept nor sent. *The gap (for review):* a holding lost while the key survives (the file deleted, the volume
kept) now starts empty under the same key, which the domain cannot tell from a first start; the actor would have to
make the key and the holding together for the witness to refuse it.

### For the maintainer

1. *The address check.* Raised and set aside: a token the API signs is inside the trust base ("Not a gap", above).
   **Decided (the maintainer, 2026-10-28): not Polar's to defend.**
2. *What the images are checked against on a target with no signed deployment.* `sandbox-local` has the signed lock;
   `local-minimal` has none and runs `latest`. *Options:* (a) on such a target, check owner, account and no ephemeral
   container, and report the images as not attested, without refusing; (b) refuse attestation on such a target
   (so nothing there is issued once the attestation agent runs); (c) give `local-minimal` a lock too. *Recommendation:*
   (a): a development target stays usable, and says what it does not check.
   **Decided (the maintainer, 2026-11-02): none of these. `local` and `local-minimal` are retired, and every deployment goes through
   Flux and the signed deployment repository, on one node or many, so every target has the signed lock.**
3. *When the attestation agent cannot be asked* (not yet up, restarting, Cassini down). Question 2's decision for
   cert-issuer was "whenever it is reachable" (`core-restarts.md`, question 2, B): sign without it, and attest after the
   fact. *Recommendation:* the same for the credentials agent's paths, every issuance made without it recorded as such
   and attested once it is back (item 4). *Or:* once it has been heard, its absence holds requests, as a held request
   waits for the credentials agent.
   **Decided (the maintainer, 2026-11-02): the same as cert-issuer's.**
4. *Its pool* on a cluster that places workloads (`placement.md`). It holds a read view of every Polar pod. *Recommendation:*
   `core`, beside the identities it guards; `observers` is the low-trust side. (The sensor of slice C runs on every node,
   tolerating every pool's taint.)
   **Decided (the maintainer, 2026-11-02): `core`.**

## Open, to be settled when it is built

- The two workloads' names in the catalog, their capabilities (`Capability` in `polar-agent-builder`), the
  attestation agent's Role (which `pod-reaper.md` already describes for the pod observer), and what the sensor's pod
  spec needs beyond `hostPID` (a read-only view of the host's cgroup tree; whether reading another user's
  `/proc/<pid>/status` needs any capability on the node's kernel).
- The protocol's topics and messages, and how often an agent is challenged.
- How cert-issuer hears the attestation agent while Cassini is down (Cassini's own restart): a direct mTLS path, with
  `core-restarts.md`, question 2.
- The mTLS key in the kernel keyring: done otherwise (2026-10-27/28): the pod's custody daemon holds the mTLS keys and
  the escrow key, and the workload signs and unwraps through its socket (`key-custody.md`); no kernel keyring.
- Cassini's binding of a session to the attested pod's address.
- The seccomp and Landlock profiles the builder applies, and which agents need more (the nushell agents run other
  programs).
