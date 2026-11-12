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

# deployer — Claude's side

PAIR: `deployer.md` (people). Same plan, two forms; change together. This side: dense, for Claude's reload.
LEVEL: capability. Features: `deployer/<feature>.{md,claude.md}`.
AS-OF: main 1dd68a49 (2026-11-12) + this doc. Re-verify `file:line` before relying; lines drift.
STATUS: proposal; nothing built; maintainer has not decided build vs gateway vs keep-Flux.

## INTENT
reconcile desired→deployed (maintainer 2026-11-02, verbatim: "Ultimately, what I want from a 'gitops' service is to
reconcile a state, from desired -> to deployed."). desired = one pipeline-signed commit read as facts + dep graph.
deployed = observed (k8s objects + registrations, health/holds, sessions, certs, digests). done = invariants hold.

## DECISIONS (maintainer, dated)
- 2026-11-02 the need list (x509 verify, no Secret credential, identity/custody/attestation, Polar decides prune).
- 2026-11-02 speed is a requirement ("horribly slow").
- 2026-11-02 order from agents' declared deps, "no need for shit like layers".
- 2026-11-02 readiness: core watched via k8s API; after Cassini, told over Cassini ("not ... general purpose").
- 2026-11-02 fidelity: enforce Polar invariants above Flux's Ready.
- 2026-11-02 graph includes what a workload requires (Secrets, CMs, claims, SA, roles, images); controller enforces
  catalog intent.
- 2026-11-02 deletion of claims/namespaces needs "explicit instruction".
- lifecycle.md decision 5: order = lifecycle doc+reader → state agent derives schema/agents → catalog split →
  controller "reshaped around phases". remaining-work.md order step 10 (:53-56); DR step 12 waits on controller (:88-102).
- 2026-11-12 docs: this two-form, capability/feature format; describe main as is.
- NOT decided: build at all; gateway vs full; everything marked open below.

## FACTS@main (verified 2026-11-12 unless marked)
- Flux 2.9.6, only source+kustomize controllers: infra/flux.nu:37-38,:91; images flux-controllers.yaml:2637,:3564.
- install: flux.nu:301-349 (verify head once via gpgsm fetch_verified :285-299, then apply). flux layer in
  BOOTSTRAP_LAYERS, never published: deploy-objects.nu:31-37. up.nu runs flux,flux-wait every gitops run (plan.nu:127-128).
- REQUEUE_DEPENDENCY="5s" flux.nu:61 (comment :59-60: 183s→77s on u7c). GitRepository interval 1m
  deploy-objects.nu:154,:172. Kustomization interval/timeout 10m, retry 1m, prune:true :127-131.
- stale health-wait workaround: STALE_AFTER 15s, MAX_RESTARTS 3 flux.nu:143-144; restart :383-391. Gate
  CancelHealthCheckOnNewRevision NOT set anywhere.
- credential: pre-hand-off Secret deploy-repo-auth (deploy-objects.nu:40; made flux.nu:332-337); post Secret
  deployment-auth (deploy-objects.nu:163; flux.nu:223-229), identity deployment:flux (tls.rs:83, git-server.nuon:52).
  Never renewed; re-applied from same files each run; reissued only on DNS-name change (deploy-repo.nu:223-227).
- deployment PKI: P-256 (deploy-repo.nu:193), RSA refused (:196-200,:212-214). ~/.config/polar-deploy/<target>/
  (:74-76) holds ca.key beside pipeline.key. Leaves 365d (:232), CA 3650d (:216). pipeline EKU clientAuth only
  (cert_plan :86-92, ext_text :181-184). No expiry warning anywhere (remaining-work.md:1273 open item).
- verify_commit(raw,trust,signer,now)->SignerInfo polar-signing/src/commit.rs:86-91; checks digest, chain at now,
  CN==signer, KU digitalSignature if present, P-256, ECDSA. No EKU check. Returns no parsed commit.
- push-time check: polar-git-server signed.rs check_push :101-113 (every new commit + every ref head; head at now,
  older at committer time :188-193); repo opts in via signed_by (git-server.nuon:52).
- apply-time check: NONE. GitRepository has no verify (deploy-objects.nu:148-178).
- provenance.json: schema 1; target, sources, published_by, cluster_inputs{cluster_ca_sha256,...}, image_lock,
  flux_controllers, deployment_ca_sha256, signer; per-layer files[{path,sha256,rendered_sha256}], depends_on
  (deploy-repo.nu:449-451,463-475,606-616). No Provenance-Sha256 trailer (commit msg :654).
- hand-off: cluster-bootstrap.md:124-130; up.nu step_handoff :659-672. Flux URL after:
  https://polar-git-server.polar.svc.cluster.local:8443/deployment.git. is_handed_off by URL suffix
  (deploy-objects.nu:181).
- way back: up.nu --bootstrap-again (:1142,:1182; plan.nu:140-145; way-back.nu:55-68); live u7c 2026-11-11
  (cluster-bootstrap.md:191-203).
- layers: hand-kept infra/targets/sandbox-local/target.nu:36-171; 7 incl. flux (platform→flux→cert-issuer→data→
  cassini→identity→agents), 6 published (deploy-objects.nu:44-55) + under-test-<name> (under-test.nu:232-247).
  INFRA.md:1203 says should be derived. has_job→force path still present (deploy-objects.nu:65-68,:138;
  deploy-repo.nu:440-441). No prune annotations anywhere.
- no workload dep graph: NEEDS are capabilities (polar-agent-builder/src/lib.rs:384-407); capabilities.nuon
  `dependency` feeds health deps only (resolve.nu:506-516). remaining-work.md:1262-1263 open item.
- attestation record: deployment-record.json signed by pipeline, domain DEPLOYMENT_RECORD (deploy-repo.nu:547-560,
  :641-643); schema 3 with hardening (deploy-objects.nu:225-269); read by polar-scheduler-observer over Cassini
  (deployment_record.rs:23-27), topic attestation-deployment-record; attestation verifies, signer pipeline, refuses
  older (attestation/agent/src/record.rs:37-67). Verified at now ⇒ expired pipeline cert ⇒ new records refused
  (inferred).
- kube-consumer records FluxKustomization(+State), FluxOCIRepository; GitRepository NOT recorded
  (kubernetes/consume/src/lib.rs:1553-1700,:1610-1611).
- Flux footprint: placement.md:103-108 "about 2 GB for Flux, the deployment git server and the resolver" (2026-11-02).

## DOC DRIFT found (fix when those docs are reached; not this doc's job)
- git-server.md on main lacks "Inside the boundary" (maintainer 2026-11-09: agents reach Polar services via Cassini,
  never direct). Main code cites it: polar-git-server common lib.rs:55, server agent.rs:90, read.rs:24, store.rs:25;
  cluster-bootstrap.md:226. Text only on agentic-control-plane (git-server.md:167). Left out by the back-to-main port.
- cluster-bootstrap.md:261 says push verification "not built"; :218-222 and remaining-work.md:1265 say built.
- runtime-attestation.md:257-258, polar-scheduler/common/src/lib.rs:30 say configuration agent reads record; it is
  the scheduler observer.
- record-store.md is on main (came with the ledger port) but is agentic-control-plane's design; cites the deployer
  (:84,:222,:256). Pending the maintainer's docs decision.

## FEATURES (capability → feature plans)
| id | feature | status | plan |
|---|---|---|---|
| F1 | verified before applied | planned, first | deployer/verified-before-applied.{md,claude.md} |
| F2 | attestation told first (intent before apply) | outline only | — |
| F3 | identity like any agent (late identity, no Secret) | outline only | — |
| F4 | told not polling (speed) | outline only; Flux requeue 5s done | — |
| F5 | order from declared deps | outline only | — |
| F6 | done when invariants hold; drift | outline only | — |
| F7 | safe deletion | outline only | — |
| F8 | bootstrap+recovery w/o credential (seed) | outline only | — |
| F9 | shadow → takeover per layer → Flux out | outline only | — |

## ALTERNATIVES
keep Flux+fixes | Flux spec.verify (impossible: OpenPGP/SSH only, review K5) | verifying gateway (F1+F2, ~1/4 work)
| full deployer. REC: shadow first (= gateway's first half); decide with shadow numbers.

## STOP CONDITIONS (from proposal §18)
git-server compromise judged acceptable | shadow never converges | one data-losing bug in takeover | render grows
(Helm/CRDs/tenants) | no owner | Flux gains x509 + file credentials.

## OPEN (ask one at a time, when reached; REC = recommendation)
- Q1 gateway vs full → REC M1 shadow first, decide after.
- Q2 seed CM vs bootstrap server for bootstrap+recovery → REC seed; note --bootstrap-again now exists (bootstrap server).
- Q3 (old) record as commit+trailer vs polar-signing doc: RSA objection OBSOLETE (PKI is P-256); record already a
  polar-signing doc signed by pipeline. Re-ask only if the trailer is needed for the record too.
- Q4 deployment facts in provenance.json (schema 2) vs own file → REC in it.
- Q5 deleting claims/namespaces: person vs signed retire list → REC person.
- Q6 rolling update for deployer vs one-pod-per-identity rule → REC allow via instances:many + fence.
- Q7 late identity by container restart (exit 75) vs in-process → REC restart.
- Q8 drift: correct vs report → REC correct named fields, report others.
- Q9 layer gate: Available vs agent health over Cassini → REC Available through takeover, then health.
- Q11 CA key beside pipeline key on operator machine → REC accept now, move before non-dev.
- Q12 shadow exit 14 days/20 commits per layer → REC floor.
- Q13 namespace rule (refuse objects outside tree's namespaces) → REC yes.
- NEW: reshape around lifecycle phases (lifecycle.md decision 5) — not designed.
- NEW: the deployer's reads go over Cassini (inside-the-boundary rule) — the old proposal's mTLS+custody git handler
  is superseded; record-store.md decision 11 (agentic-control-plane only) has it read the store.

## MAP: old proposal (gitops-controller.md at f1946b43, branch gitops-proposal/worktree-agent-a7c38f...) → here
§1-2 need,findings→1,2,6 | §2 cheap Flux fixes→6 + F4/F7 | speed→F4 | ordering→F5 | fidelity→F6 | §3-5 shape→3 |
§6 trust→F1 | §7 sources→F1,F8 | §8 apply→F9 + core | §9 prune→F7 | §10 identity→F3 | §11 attestation→F2 |
§12 privilege→F3 | §13 self-update→F9 | §14 reporting→core | §15 handlers→superseded by Cassini reads |
§16 shadow→F9 | §17 takeover→F9 | §18 costs→4,5 | §19 tests→each feature | §20 milestones→3 | §21 size→
(guess: 8-10k lines; gateway ~1/4) | §22 open→OPEN | §23 not checked→each feature.

## EVIDENCE
deployer/flux-review.md (was gitops-controller-edge-cases.md; 2026-11-02 at eada654b; codes A1..M*, e.g. E6 layer
move recreates, C1 force deletes on 422, B1 typed drop, E1 empty layer pruned whole, K5 spec.verify formats, H13 cert
age). Cited lines are at eada654b, not current.

## NOT CHECKED
nothing ran; k8s behaviours from memory (CM size, dry-run authz, request.dryRun); kube crate SSA API; Flux partly
read; restart rule NotIn [75] untried.
