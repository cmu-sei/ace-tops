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

//! Real answers from the test GitLab, kept as the GitLab pair's samples (`gitlab-seed answers`, G4d): each query of
//! `src/agents/gitlab-http/queries` asked once, a follow-up of an item the seed filled, and the test GitLab's host replaced by the
//! samples' everywhere it is named, so a sample says nothing of where it was read and reads as the hand-written ones do.

use crate::dataset::{Size, TOP, dataset};
use serde_json::{Value, json};

/// The host every sample is read at (`polar_projection`'s `SAMPLE_ORIGIN`, https://samples.example).
pub const SAMPLE_HOST: &str = "samples.example";

/// `answer` with `host` replaced by [`SAMPLE_HOST`] in every string.
pub fn mask(answer: &Value, host: &str) -> Value {
    match answer {
        Value::String(s) => Value::String(s.replace(host, SAMPLE_HOST)),
        Value::Array(items) => Value::Array(items.iter().map(|v| mask(v, host)).collect()),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), mask(v, host)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The variables a query is asked with: none for one of the instance's lists, and for a follow-up the full path of the item the seed
/// filled for it (the first project, whose CI the runner ran; the image's project; the package's; the top group). None for a query
/// this does not know.
pub fn variables_for(query: &str) -> Option<Value> {
    let d = dataset(&Size::default());
    let with_ci = d
        .projects
        .iter()
        .find(|p| p.ci.is_some())
        .map(|p| p.full_path.clone())
        .unwrap_or_default();
    let path = match query {
        "metadata" | "projects" | "users" | "groups" | "runners" => return Some(json!({})),
        "project-pipelines" | "project-jobs" => with_ci,
        "project-container-repositories" => d.image.project.clone(),
        "project-packages" => d.package.project.clone(),
        "group-members" => TOP.to_string(),
        _ => return None,
    };
    Some(json!({ "fullPath": path }))
}
