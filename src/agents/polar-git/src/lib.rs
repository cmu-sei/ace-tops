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

//! polar-git: source code, hosted for people (docs/architecture/polar-git.md). An ordinary git server, the one service
//! inside Polar's boundary that takes direct connections, since git is a protocol Cassini cannot carry without breaking
//! every git client. Its edge does what the broker does for everything else: a Polar certificate says who is asking
//! (`polar_git_server::tls`), Cedar decides each git operation ([`edge`]), and everything it does, refusals included, is
//! reported over Cassini ([`events`]). The records (evidence, schedules, the deployment) are not here: they are the
//! store's (record-store.md).

pub mod agent;
pub mod edge;
pub mod events;
pub mod http;
pub mod settings;
pub mod supervisor;
