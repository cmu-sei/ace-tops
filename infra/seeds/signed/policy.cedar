// ACE Tool
//
// Copyright 2026 Carnegie Mellon University.
//
// NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
// FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
// EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
// PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
// MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
// TRADEMARK, OR COPYRIGHT INFRINGEMENT.
//
// Licensed under a MIT (SEI)-style license, please see license.txt or contact
// permission@sei.cmu.edu for full terms.
//
// [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
// distribution.  Please see Copyright notice for non-US Government use and distribution.
//
// This Software includes and/or makes use of Third-Party Software each subject to its own license.
//
// DM26-0670

// The first policy of a cluster (docs/architecture/credentials-policy.md, "The first policy").
//
// An identity may retrieve a secret it escrowed itself. The owner is the ledger's record of who stored the
// secret; no document can set it.
permit (principal, action == Action::"retrieve", resource)
when { resource has owner && resource.owner == principal };

// Incident freeze: a secret labelled frozen is retrievable by nobody, whatever else permits it.
forbid (principal, action, resource)
when { resource has frozen && resource.frozen };

// Who may read what an agent has in force, and who may change it (docs/architecture/dynamic-settings.md, "Asking an agent
// what is in force"). Membership is the signed groups document's, and config-writers is in config-readers. A person's
// certificate names no topics, so the two topic rules are what lets one ask at all; the agent then judges the question
// itself, by action "read-configuration".
permit (principal in Group::"config-readers", action == Action::"publish", resource == Topic::"polar-running-configuration-questions");
permit (principal in Group::"config-readers", action == Action::"subscribe", resource == Topic::"polar-running-configuration-answers");
permit (principal in Group::"config-readers", action == Action::"read-configuration", resource);
permit (principal in Group::"config-writers", action == Action::"update-configuration", resource);

// People on Cassini (docs/architecture/record-store.md, "People's tools over Cassini"): a topic whose name ends with a
// person's identity is addressed to them (`context.addressed`, which the broker computes from the name). They may hear
// it, and nobody else may; the store, which answers people's requests, may publish it.
permit (principal, action == Action::"subscribe", resource)
when { context has addressed && context.addressed == principal };
permit (principal, action == Action::"publish", resource)
when { context has addressed && principal has workload && principal.workload == "polar-git-server" };

// Source code on polar-git (docs/architecture/polar-git.md). A repo developer makes repositories, and reads, pushes and
// tags in any; the owner of a repository, who made it, may also rewrite and delete branches in it. Where policy is silent
// polar-git refuses, since a certificate names no git rights.
permit (principal in Group::"repo-developers", action in [Action::"git-create", Action::"git-read", Action::"git-push", Action::"git-tag"], resource);
permit (principal, action in [Action::"git-read", Action::"git-push", Action::"git-tag", Action::"git-force-push", Action::"git-delete"], resource)
when { resource has owner && resource.owner == principal };
