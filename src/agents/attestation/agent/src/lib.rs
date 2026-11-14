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

//! The attestation agent (docs/architecture/runtime-attestation.md, "Slice A"): it sees the pods of Polar's namespaces, and answers
//! whether an instance is what the deployment made. It sees and reports; it never acts.
//!
//! - [`holdings`]: what it holds of the cluster, and the facts it reads from that;
//! - [`watch`]: one watch of one kind in one namespace, as an operation of the protocol handler's;
//! - [`supervisor`]: the input and output around the judgement, which is `attestation_common::judge`.

#![deny(clippy::disallowed_methods)]

pub mod agent;
pub mod evidence;
pub mod holdings;
pub mod record;
pub mod settings;
pub mod supervisor;
pub mod watch;
pub mod witness;
