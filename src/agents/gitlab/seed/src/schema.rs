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

//! GitLab's schema from a GitLab (`gitlab-seed schema`): the introspection query, and the file it becomes.

use cynic_introspection::{IntrospectionQuery, SpecificationVersion};
use serde_json::Value;

/// The introspection asked for, as the JSON body POSTed to GitLab's GraphQL endpoint: everything the October 2021 specification lets
/// a schema say.
pub fn introspection_body() -> Value {
    let operation =
        IntrospectionQuery::with_capabilities(SpecificationVersion::October2021.capabilities());
    serde_json::to_value(&operation).expect("an operation serializes")
}

/// The SDL of GitLab's answer to [`introspection_body`] (its `data`).
pub fn sdl_of(data: Value) -> anyhow::Result<String> {
    let query: IntrospectionQuery = serde_json::from_value(data)?;
    Ok(query.into_schema()?.to_sdl())
}

const BANNER: &str = "\
# ACE Tool
#
# Copyright 2026 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING INSTITUTE MATERIAL IS
# FURNISHED ON AN \"AS-IS\" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER
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
";

/// The file: the license banner, where it came from, and the schema.
pub fn schema_file(version: &str, revision: &str, sdl: &str) -> String {
    format!(
        "{BANNER}\n\n# GitLab {version} ({revision}), by introspection of the test GitLab (gitlab-seed schema): what the GitLab pair's queries and\n# samples are held to (docs/architecture/http-observers.md, G3 and G4d). Generated; refresh it, do not edit it.\n\n{sdl}"
    )
}
