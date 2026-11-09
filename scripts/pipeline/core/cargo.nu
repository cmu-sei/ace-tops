# ACE Tool
#
# Copyright 2026 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
# FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
# EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
# MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
# TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see license.txt or contact permission@sei.cmu.edu
# for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
# distribution.  Please see Copyright notice for non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject to its own license.
#
# DM26-0670

# The repository these scripts are part of: three up from `scripts/pipeline/core`. Found from where they sit and not by
# asking git, since a build's source is an archive with no `.git` (docs/architecture/build-orchestrator.md, D4).
const REPOSITORY = path self ../../..

export def workspace-root [--manifest-path: string = ""]: nothing -> string {
    if ($manifest_path | is-not-empty) {
        return ($manifest_path | path dirname)
    }
    let default_manifest = $REPOSITORY | path join "src/agents/Cargo.toml"
    if ($default_manifest | path exists) {
        $REPOSITORY | path join "src/agents"
    } else {
        error make {msg: $"could not find Cargo.toml at ($default_manifest)"}
    }
}

# The commit the build is of: the one the orchestrator names (`CI_COMMIT_SHA`), git asked only when it names none, as in a
# checkout run by hand. A build's source has no `.git`, and `default` would ask git even when the name is set.
export def source-commit []: nothing -> string {
    let named = ($env.CI_COMMIT_SHA? | default "")
    if ($named | is-not-empty) { $named } else { ^git rev-parse HEAD | str trim }
}
