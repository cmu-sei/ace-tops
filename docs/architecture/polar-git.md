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

# polar-git: source code, hosted for people

Status, 2026-11-11: built on agentic-control-plane, not yet deployed. Decided by the maintainer the same day
(`record-store.md`, "Revised (the maintainer, 2026-11-11)"): source code goes to a service of its own; the store keeps
the records and takes no direct connections. What below is this session's, by the design principles, is marked *(for
review)*.

## What it is

An ordinary git server for people's repositories, and **the one service inside Polar's boundary that takes direct
connections**: git is a protocol Cassini cannot carry without breaking every git client. Its edge therefore does what the
broker does for everything else:

- **Who.** Every connection presents a Polar certificate; the identity is its first DNS name, as everywhere in Polar
  (`polar_git_server::tls`, shared with the store).
- **What they may do.** Each git operation is a Cedar action on `Repository::"<name>"` (`polar_policy::git`): `git-read`
  (fetch, clone, seeing a repository's refs), `git-push` (making a branch or moving one forward), `git-force-push`
  (moving a branch to a commit it does not lead to), `git-delete` (deleting a branch), `git-tag` (any change to a tag),
  `git-create` (making a repository). A repository's `owner`, the identity that made it, is its attribute, so a rule
  can speak of "its owner". Only an allow allows: where policy is silent a certificate would decide, and a certificate
  names no git rights, so silence refuses.
- **What it did.** Every fetch, every repository made, every push (each ref it moved, from and to which commit, and the
  action asked), and every refusal (what was asked, and why) is published on `polar-git-events` with who did it
  (`polar_git::events`), and logged. Nothing in an event is secret: names and object ids.

**The first policy** (`infra/seeds/signed/policy.cedar`) gives the group `repo-developers` making repositories, and
reading, pushing and tagging in any; and a repository's owner rewriting and deleting branches in it besides. The first
administrator is in `repo-developers` (`infra/seeds/signed/groups.json`). A policy update changes any of it with no new
certificate, as for every other Polar right.

## How a request is judged (`polar_git::http`)

- `info/refs` for a fetch, and `git-upload-pack`: `git-read`.
- `info/refs` for a push to a repository that is not there: `git-create`, and it is made, owned by the pusher (push to
  create, as many git servers do). Then `git-read` to see its refs, for a push as for a fetch.
- `git-receive-pack`: each ref update, judged in the push's quarantine (`polar_git::edge::classify`): under
  `refs/tags/`, `git-tag`; under `refs/heads/`, deleting is `git-delete`, making or moving forward is `git-push`, and
  anything else is `git-force-push`; any other ref is refused, since a git server keeps its own. One refused refuses
  the push, and nothing of it is kept.
- A refusal is said (403, and an event) before whether the repository exists, so nobody learns of one they may not read.

A repository is held to git's own rules and no more: it is made without the record rules
(`receive.denyNonFastForwards`, `receive.denyDeletes`) that the store's repositories carry, its owner in its own git
configuration (`polar.owner`, `RepoStore::create_owned`). *(for review: the owner in git's own configuration, beside the
repository, rather than a list of its own.)*

## The Polar git client (`git-remote-polar`)

A git remote helper, so plain git works: `git clone polar://tools`, `git push`, `git fetch`, branches and tags. git
runs it for a `polar://` URL; it names polar-git's HTTPS address, gives git the person's Polar certificate, key and CA
(from `~/.config/polar-admin`, as `polar-sign` finds them), and hands over to git's own HTTPS transport: git reads the
key, and the helper never opens it, so it has no TLS or crypto actor of its own. What it takes: who (`POLAR_USER` or `git config polar.user`), where (`polar://host:port/repo`,
`POLAR_GIT_HOST` or `polar.host`, else `polar-git.polar.svc.cluster.local:8443`), and a way through a forward
(`POLAR_GIT_RESOLVE` or `polar.resolve`, curl's `host:port:address`). Tested with plain git against a real polar-git
(`git-remote-polar/tests/clone.rs`).

## How it relates to the rest

- **The code it shares** with the store (`polar-git-server`, as a library): git's smart protocol in process (gix-serve),
  the TLS listener, the repository store. *(for review: a library of the store's crate, not one of its own yet.)*
- **The records stay the store's**: evidence, schedules, the deployment. A record about code names a commit by its digest;
  nothing is copied between the two.
- **Agents still use Cassini**, for everything, reading source included; this exception is for people's git.
- **Not yet:** the git processor reading `polar-git-events` into the graph (its topic says it waits for that), and
  traces beyond the log.

## Built (2026-11-11)

`polar-policy` (the schema's `Repository` and git actions; `git.rs`), `polar-git` (lib and agent), `git-remote-polar`,
and in the store's crate the owned repositories, the peer's certificate beside its identity, and the transport helpers
made public. Tests: each ref update's action; the policy's rules for a repo developer, an owner and someone it says
nothing of; and end to end with real git over mTLS under the first policy, push to create, clone, push forward, tag,
branch, a force push and a deletion refused to a developer and taken from the owner, everything refused to someone policy
says nothing of with the same answer whether the repository is there, and every event.

## On main (2026-11-14, the record store's bite 5, `docs/plans/record-store/to-main.md`)

As built above, with its TLS its crypto actor's: polar-git's server certificate and key are `TLS_SERVER_CERT_CHAIN`
and `TLS_SERVER_KEY`, which the crypto actor's `keys` section declares as every server's on `main` are, in place of the
other branch's `POLAR_GIT_CERT` and `POLAR_GIT_KEY`; its listener takes its configuration from the actor's `TlsHandle`,
and its own section requires only that it is given a server certificate. The helper's three lines of git configuration
are its own, not the other branch's `polar-git-push`, which stays there with `polar-eden`. The seed's policy carries
the git rules beside the rules for people on Cassini.

## Live on u7c (2026-11-11, agentic-control-plane 2cfc9fa2)

- **Its start**: polar-git came up under the builder's lock, granted no file but its repositories
  (`/var/lib/polar-git/repos`, written), its certificates (`/etc/tls/polar-git`) and the custody socket, and joined
  Cassini.
- **The policy**: the seed signs only what a cluster lacks, so u7c's policy was version 2. djshepard signed policy
  version 3 (version 2 and the first policy's git rules) and groups version 2 (themselves in `repo-developers`), and
  pushed both to polar-schedules. Through the schedules log the credentials agent applied both within two seconds and
  published them, and polar-git took them.
- **Plain git, through `git-remote-polar`** and the `polar-git` forward, as djshepard: `git push polar://tools HEAD:main`
  made the repository, theirs; `git clone polar://tools`; a push forward, a tag, a branch, a forced push and a branch
  deletion, the last two as its owner. Each was published on `polar-git-events` with the action Cedar was asked
  (`git-push`, `git-tag`, `git-force-push`, `git-delete`), and every fetch as a read.
- **Found, and changed after**: an event named a person by their account's identity, a UUID; people read usernames
  ("Names, not UUIDs, for people"). An event now carries `name`, the `uid` in their certificate's Subject, beside the
  identity policy judges by, and a refusal names them the same way.
