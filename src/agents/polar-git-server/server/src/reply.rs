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

//! Who the store answers on Cassini, and by what name: a workload by its workload's name, a person by their account's
//! identity (docs/architecture/record-store.md, "People's tools over Cassini"), each on topics named for them that the
//! broker lets nobody else hear. Anyone else is not answered.

/// The name answers to `sender` (the identity the broker stamped) go out under; none for a sender that is neither a
/// workload nor a person.
pub fn answered_as(sender: &str) -> Option<&str> {
    cert_issuer_common::identity::workload_of(sender)
        .or_else(|| polar_git_server_common::is_person(sender).then_some(sender))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_workload_is_answered_by_its_name_a_person_by_their_identity_and_nobody_else_at_all() {
        assert_eq!(
            answered_as("attestation-agent.polar.serviceaccount.cluster.local"),
            Some("attestation-agent")
        );
        assert_eq!(
            answered_as("15ab472c-cdd3-4b24-948f-30f9ca5f8cc9"),
            Some("15ab472c-cdd3-4b24-948f-30f9ca5f8cc9")
        );
        for nobody in [
            "attestation-agent",
            "custody.x.polar.serviceaccount.cluster.local",
            "",
        ] {
            assert_eq!(answered_as(nobody), None, "{nobody}");
        }
    }
}
