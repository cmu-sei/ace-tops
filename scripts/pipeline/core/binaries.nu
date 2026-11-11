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

# scripts/pipeline/core/binaries.nu
#
# What a binary's build says of it (build-inspect-ship, S2). A binary is built by Nix, from its crane derivation, which
# keeps cargo's JSON log of the build as its `cargolog` output. This module reads that log: which binaries the build
# linked, and the package each belongs to, by its id. Pure: no file is read and nothing is run.

# The package a cargo package id names. Written in S2a.
export def package-of-id [id: string]: nothing -> record {
    {name: "", version: ""}
}

# The binaries a build linked, from its cargo log's lines. Written in S2a.
export def linked-binaries [log: list<string>]: nothing -> list<record> {
    []
}
