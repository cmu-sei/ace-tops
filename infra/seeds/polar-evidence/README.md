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

# polar-evidence

Evidence records: what a collector found, signed by the collector, one JSON file per record. A record names what it is
true of by digest (a mapping, a scaffold, samples, the tool's version) and says the result. It is signed in the
evidence domain (`polar-evidence-record-v1`), so it is never taken for a configuration document, and nothing here is
read as an order. `polar-sign verify --evidence <file>` checks one.

`projection-test/<agent>/<section>/<sha256>.json` holds what `polar-sign projection test` found of a deployment's
mapping, named by the digest of the signed record, so a new record never replaces another.

This directory is the first commit of the repository, made once by the Polar git server when it finds the repository
empty. Like every repository on the server, it refuses a deleted branch and a rewritten history; a commit that removes
or changes a record is not refused yet, and neither is an unsigned commit, since each record carries its own signature.
Design: `docs/architecture/http-observers.md`, "Evidence".
