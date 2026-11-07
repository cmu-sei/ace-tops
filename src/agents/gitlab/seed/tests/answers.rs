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

//! Real answers from the test GitLab kept as the pair's samples (`gitlab-seed answers`, G4d): each query asked, a follow-up for an item the
//! seed filled, the test GitLab's host replaced by the samples' so a sample says nothing of where it was read.

use gitlab_seed::answers::{SAMPLE_HOST, mask, variables_for};
use proptest::prelude::*;
use serde_json::{Value, json};

const HOST: &str = "gitlab.gitlab-test.svc.cluster.local";

fn tree() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        "[a-z/:.]{0,12}".prop_map(Value::String),
        "[a-z/]{0,6}".prop_map(|s| Value::String(format!("https://{HOST}/{s}"))),
        any::<u32>().prop_map(|n| json!(n)),
        Just(Value::Null),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("[a-z]{1,4}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

proptest! {
    /// Masked, an answer names the test GitLab nowhere, and is otherwise the answer it was: every value without the host as it was.
    #[test]
    fn a_masked_answer_names_the_test_gitlab_nowhere_and_is_otherwise_as_it_was(answer in tree()) {
        let masked = mask(&answer, HOST);
        prop_assert!(!masked.to_string().contains(HOST));
        prop_assert_eq!(mask(&masked, HOST), masked.clone(), "masking twice changes nothing");
        let back = masked.to_string().replace(SAMPLE_HOST, HOST);
        prop_assert_eq!(serde_json::from_str::<Value>(&back).unwrap(), answer);
    }
}

#[test]
fn each_follow_up_is_asked_of_an_item_the_seed_filled_and_a_page_of_none() {
    for q in ["metadata", "projects", "users", "groups", "runners"] {
        assert_eq!(variables_for(q), Some(json!({})), "{q}");
    }
    assert_eq!(
        variables_for("project-pipelines").unwrap()["fullPath"],
        "polar-seed/project-01"
    );
    assert_eq!(
        variables_for("project-jobs").unwrap()["fullPath"],
        "polar-seed/project-01"
    );
    assert_eq!(
        variables_for("project-container-repositories").unwrap()["fullPath"],
        "polar-seed/platform/project-02"
    );
    assert_eq!(
        variables_for("project-packages").unwrap()["fullPath"],
        "polar-seed/platform/agents/project-03"
    );
    assert_eq!(
        variables_for("group-members").unwrap()["fullPath"],
        "polar-seed"
    );
    assert_eq!(variables_for("nothing-like-it"), None);
}
