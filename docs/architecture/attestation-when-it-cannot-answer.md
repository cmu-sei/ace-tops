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

# When the check cannot answer, or answers wrongly

The instance check at issuance (`runtime-attestation.md`, "Slice A, the askers") can refuse a certificate, and a refused certificate stops a pod. So it is the same kind of thing as a Kubernetes admission webhook: a check that was added for safety, and that can take down what it guards. This page records how others handle that, read on 2026-11-03, what Polar decided from it, and a proposal that came out of it.

## Three failures, not one

Discussion of "fail open or fail closed" usually means only the first of these. Each needs its own answer.

1. **The check cannot be reached.** It is down, restarting, or the path to it is. This is what a `failurePolicy` decides.
2. **The check is up and cannot tell.** It is running, but what it depends on is not. `failurePolicy` does not cover this: the webhook call succeeded, and what it answers is the check's own decision.
3. **The check is up and wrong.** A bad rule, or an environment that differs from what the rule assumes. No failure policy helps, since a wrong "no" is a successful call. It is only found by watching what the check would do before believing it.

## What others do

| | Cannot be reached | Up, but cannot tell | Watching without blocking | Getting out |
|---|---|---|---|---|
| **Kubernetes webhooks** | Rejected: `failurePolicy` defaults to `Fail` | The webhook's own decision | None of its own | Delete the webhook configuration, which does not itself pass through admission webhooks |
| **Gatekeeper** | Admitted: defaults to `Ignore`, and its audit is expected to catch what got in | | | Documents the risks of `Fail`, with deleting the configuration as the recovery |
| **Kyverno** | Rejected: defaults to `Fail` "to be more secure by default"; `--forceFailurePolicyIgnore` changes it | | | Excludes its own and `kube-system` namespaces by default |
| **Anchore** | Admitted: the current chart sets `failurePolicy: Ignore` (a 2019 Anchore post showed `Fail`) | Denied, in the modes that gate | A passive mode triggers analysis and blocks nothing | Break-glass mode, chosen by a label, admits without checking; a namespace label exempts a namespace |
| **Sigstore policy-controller** | Its overview does not say | | A policy's `mode: warn` admits with a warning | Namespaces opt in, by default |

A blank cell is one the page read does not address, not a claim that the product has nothing there.

**What the Kubernetes documentation warns of.** "A webhook running inside the cluster might cause deadlocks for its own deployment if it is configured to intercept resources required to start its own Pods." It recommends excluding the webhook's own namespace and avoiding `kube-system`, and warns of two webhooks that check each other's pods.

**What Gatekeeper warns of,** on failing closed: an admission deadlock, where every node is gone and adding one needs the webhook; the control plane's availability depending on the webhook's; exemptions that are hard to get right, since something as minor as a ConfigMap for a leader election may be critical; and replicas that share a failure domain.

**Anchore, in detail.** `failurePolicy` covers only the call to the webhook. In the controller's policy and analysis modes, an error reaching Anchore's API, or having no client for it, gives `IsValid: false` (`validation/analysis.go`, `validation/policy.go`), and `Allowed` is `IsValid` (`admission/response.go`). So with the controller running and Anchore's API down, as those paths read, pods those modes select are denied whatever the chart's `failurePolicy` says. This is a reading of the public controller and chart, which Anchore's documentation points to for its licensed add-on. Whether Anchore Enterprise's own build behaves the same has not been checked, and no such outage has been run.

**How it goes wrong in production.** One first-hand account: a Kubernetes upgrade from 1.32 to 1.34 left the API server in a crash loop, because Kyverno's `Fail` webhook intercepted the `ServiceCIDR` the server creates at first boot, and the webhook could not be reached until that object existed. It was broken by starting the API server with `--disable-admission-plugins=ValidatingAdmissionWebhook`, and fixed for good with `matchConditions` excluding those objects. Other reports of the same shape exist, a cluster frozen overnight and clusters that could not restart, but they were seen only as search summaries of wikis and forums and not read, so they are weak evidence. No formal postmortem was found.

## What Polar decided

**It issues, and records that it did** (the maintainer, 2026-11-02, and again 2026-11-03: refusing when it cannot ask would be "insane" as a default). Polar's position is closest to Gatekeeper's: admit when the check is unavailable, and catch it afterwards. It differs from Anchore's chart default in also covering the second failure: `CouldNotAsk` includes the agent being down, Cassini being down, and the agent's own `CannotSay` when it does not hold what it needs.

- **Failing closed would deadlock here.** The attestation agent needs a certificate to run, as does Cassini, which it is reached through. That is the Kubernetes documentation's own warning, with the certificate in place of the pod.
- **Failing open is not left silent.** A fail-open with nothing watching is a bypass. Each unattested issuance is recorded, and item 4 of the plan attests them once the agent is back.
- **The damage is smaller, but not small.** A bad webhook can block every API request it matches, the fix for it included. A wrong verdict refuses one pod's certificate, and the API, the running pods and the way out all still work. But pods replace themselves hourly, so a bad rule would still spread across the cluster within the hour.
- **The way out is stopping the agent.** Whoever can do that is inside the trust base. It is the same exit as Kubernetes' deleting the configuration, and it needs no break-glass label for a pod to set on itself.

**No setting for the other answer yet.** A deployment that must fail closed would need more than a flag: the core and the attestation agent's own certificate cannot wait on an agent that cannot start without them, so it would be "once it has been heard, its absence holds requests" (`runtime-attestation.md`, "For the maintainer", item 3), with what a wedged cluster does about it worked out first. A setting that decides this is a security control, so it would travel signed.

**The third failure is what the shadow run is for** (`runtime-attestation.md`, "Shadow first"), the same idea as Anchore's passive mode and Sigstore's `warn`. But a shadow run proves only the code that ran in it, which leads to the proposal below.

## Proposed: the agent proves itself each time it changes (for review, nothing built)

Raised by the maintainer, 2026-11-03: some validation run whenever the attestation agent changes, cross-checking that it is healthy and in the environment it expects.

**Why the shadow run is not enough.** It is done once. After refusing is turned on, a later image of the agent carries a new rule straight into refusing, with no shadow in front of it. And the environment moves under an unchanged agent: a Kubernetes upgrade, another container runtime writing `imageID` differently, a Role lost for one namespace. Each would read as `AnotherImage` or `NoSuchPod`, which is a false refusal.

**Where it runs: at every start, not in the pipeline.** A changed agent is a new pod, so "every change" is covered without knowing what changed, and it also catches the environment moving, which no pipeline sees. It is one path with no version comparison in it.

**What it checks, before the agent's `NotGenuine` is believed:**

1. *It holds what it needs.* Every watch has listed and the signed record has verified, as `ready()` and `read_record` already say.
2. *It is where it expects to be.* Its own pod is genuine by its own judgement, its image being the digest the signed record names for it. Nothing else proves a judgement works on this cluster's real data as directly.
3. *It does not condemn what is running.* It judges every running pod the record names. Most of the deployment found not genuine at once says more about the agent than about the deployment.
4. *It can still say no.* Passing the checks above proves nothing about an agent that says `Genuine` to everything. So each real pod's facts, altered in each way the verdict knows (another image, owner, service account, an added ephemeral container), must come back `NotGenuine`. It needs no bad pod on the cluster, and it runs on this cluster's real `imageID`s and not a fixture's.

**What failing does.** The agent answers `CannotSay` to everything and logs an ERROR saying which check failed, so the askers issue and record it as unattested. It fails open, as everything else here does. It does not end the agent: an agent that cannot pass would restart forever, and a loop says less than the ERROR.

**To decide:**

- *How much condemnation is "most"?* It must not let one real tampered pod switch the check off for everything. A majority of the deployment, or any core member? *Recommendation:* a majority: below that, the verdicts stand and each is reported as usual. Someone who could tamper with a majority of the Deployments is inside the trust base already.
- *Is a passed check a one-time gate or a standing one?* A Kubernetes upgrade happens under a running agent. *Recommendation:* repeat checks 3 and 4 on the existing one-minute comparison, since they read only what it holds.
- *Does `up.nu` read the result?* So a bring-up says the agent came up doubting itself, and does not leave it to a log line. *Recommendation:* yes, as a report that does not stop the run.
- *When it lands.* *Recommendation:* with the commit that turns refusing on, since that is when an unproved agent starts being able to do harm.

**What it does not do.** A compromised agent can pass all of this, and can refuse but cannot admit. It finds an agent that is wrong, not one that lies.

## Sources

Read 2026-11-03.

- Kubernetes: [admission webhook good practices](https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/), [dynamic admission control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)
- Gatekeeper: [failing closed](https://open-policy-agent.github.io/gatekeeper/website/docs/failing-closed/)
- Kyverno: [customization](https://kyverno.io/docs/installation/customization/)
- Anchore: [admission controller documentation](https://docs.anchore.com/current/docs/integration/kubernetes/admission/), [chart](https://github.com/anchore/anchore-charts/tree/main/stable/anchore-admission-controller), [controller source](https://github.com/anchore/kubernetes-admission-controller), [2019 post](https://anchore.com/kubernetes/dynamic-policy-mappings-and-modes-in-the-anchore-kubernetes-admission-controller/)
- Sigstore: [policy-controller overview](https://docs.sigstore.dev/policy-controller/overview/)
- The incident: [Kyverno killed my API server, again](https://blog.zwindler.fr/en/2026/02/26/kyverno-killed-my-api-server.-again.)
- Seen only as search summaries: [street ops wiki](https://grokdatum.github.io/grokdevops-wiki/library/topics/policy-engines/street_ops), [AKS question](https://learn.microsoft.com/en-us/answers/questions/2128966/cluster-restart-issues-w-kyverno-installed)
