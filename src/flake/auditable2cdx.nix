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

# src/flake/auditable2cdx.nix
#
# auditable2cdx, from the cargo-auditable project (github.com/rust-secure-code/cargo-auditable): reads the dependency
# record `cargo auditable` embeds in a binary and writes it as a CycloneDX document. The pipeline uses it to take a
# binary's own SBOM out of the binary (build-inspect-ship, S2), beside the workspace's SBOM from cargo-cyclonedx.
#
# Pinned: version 0.1.0 from crates.io, the crate by its hash, each dependency by the sha256 its Cargo.lock records.
# This nixpkgs has no fetchCargoVendor, so the dependencies come through importCargoLock (`cargoLock.lockFile`), one
# fixed-output fetch per crate, with no network at build time beyond those. The lock is the crate's own, kept beside
# this file so that reading it needs no import from a derivation; the build refuses to run if the two differ.
#
# What it reads: auditable-info 0.9.0 with auditable-serde 0.8.0, which reads the format cargo-auditable 0.6.x writes
# (format 0, no `format` field) and ignores the `format` field 0.7.x adds. To bump it, change the version and the hash,
# and replace auditable2cdx.Cargo.lock with the new crate's.
{ pkgs }:
pkgs.rustPlatform.buildRustPackage rec {
  pname = "auditable2cdx";
  version = "0.1.0";

  src = pkgs.fetchCrate {
    inherit pname version;
    hash = "sha256-36XZHa4sHfVoWNu3n3qE8ViZVYnx5v8jBIbUsqxCxMA=";
  };

  cargoLock.lockFile = ./auditable2cdx.Cargo.lock;

  postPatch = ''
    if ! cmp -s ${./auditable2cdx.Cargo.lock} Cargo.lock; then
      echo "auditable2cdx.Cargo.lock is not the crate's own Cargo.lock: replace it with the crate's" >&2
      exit 1
    fi
  '';

  meta = {
    description = "Recovers cargo auditable's dependency record from a binary as a CycloneDX document";
    homepage = "https://github.com/rust-secure-code/cargo-auditable";
    license = with pkgs.lib.licenses; [ mit asl20 ];
    mainProgram = "auditable2cdx";
  };
}
