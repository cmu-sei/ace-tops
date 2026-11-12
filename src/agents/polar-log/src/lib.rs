/*
   ACE Tool

   Copyright 2026 Carnegie Mellon University.

   NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
   FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
   EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
   PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL. CARNEGIE
   MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
   TRADEMARK, OR COPYRIGHT INFRINGEMENT.

   Licensed under a MIT (SEI)-style license, please see license.txt or contact
   permission@sei.cmu.edu for full terms.

   [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited
   distribution.  Please see Copyright notice for non-US Government use and distribution.

   This Software includes and/or makes use of Third-Party Software each subject to its own license.

   DM26-0670
*/

//! Polar's signed, append-only logs (docs/architecture/record-store.md, cleared 2026-11-10): the entry envelope and
//! leaf in deterministic CBOR ([`entry`], over [`cbor`]), the RFC 9162 Merkle tree and its proofs ([`merkle`]),
//! checkpoints in C2SP signed notes ([`checkpoint`]), the C2SP tiles a reader outside Cassini fetches a log as
//! ([`tiles`]), and a log kept in a file on an agent's own volume ([`file`]). The
//! store serves its logs over Cassini and as git; the credentials agent keeps its ledger in a [`file::FileLog`].

pub mod cbor;
pub mod checkpoint;
pub mod entry;
pub mod file;
pub mod merkle;
pub mod tiles;
