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

//! The `sources` runtime section: what an observer reads, and how often. A pure reading of a body; nothing here touches a
//! network or the clock.

use polar_agent_builder::RuntimeSection;
use polar_agent_builder::runtime::SectionAuthority;
use serde_json::Value;
use std::collections::BTreeSet;

/// What the section is called in a document.
pub const SECTION_NAME: &str = "sources";
/// Most sources one version may name.
pub const MAX_SOURCES: usize = 500;
/// Longest name, and longest address.
pub const MAX_NAME: usize = 128;
pub const MAX_URL: usize = 2048;
/// The shortest time between two reads of a source, in seconds, and the longest.
pub const MIN_INTERVAL_SECS: u64 = 60;
pub const MAX_INTERVAL_SECS: u64 = 7 * 24 * 3600;

pub static SOURCES: RuntimeSection = RuntimeSection {
    authority: SectionAuthority::Runtime,
    name: SECTION_NAME,
    doc: "What this observer reads, and how often. Replaced whole by each version, so a source left out is no longer read.",
    body: r#"{"sources": {"list_of": {"name": {"type": "text", "required": true, "doc": "what identifies this source in the graph; changing it makes new nodes"}, "url": {"type": "http or https URL of a host name", "required": true, "doc": "what is read, with a GET and no credential"}, "interval_secs": {"type": "whole number of seconds", "required": true, "doc": "how long between reads, 60 to 604800"}}, "required": true, "doc": "the sources; an empty list reads nothing"}}"#,
    validate,
};

/// Something to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub name: String,
    pub url: String,
    pub interval_secs: u64,
}

fn validate(body: &Value) -> Result<(), Vec<String>> {
    parse(body).map(|_| ())
}

/// Whether an address can be read: http or https, which the parser holds to a host, and nothing that could be a secret in
/// what is logged and kept.
fn url_problem(url: &str) -> Option<String> {
    if url.len() > MAX_URL {
        return Some(format!("is longer than {MAX_URL} characters"));
    }
    let Ok(parsed) = url::Url::parse(url) else {
        return Some("is not a URL".to_string());
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return Some("is neither http nor https".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Some("carries a user or a password".to_string());
    }
    None
}

/// The sources a body describes, or every problem with it. A problem names the field and never repeats the address.
pub fn parse(body: &Value) -> Result<Vec<Source>, Vec<String>> {
    let Some(object) = body.as_object() else {
        return Err(vec!["the body must be an object".to_string()]);
    };
    let mut problems: Vec<String> = object
        .keys()
        .filter(|k| k.as_str() != SECTION_NAME)
        .map(|k| format!("`{k}` is not a field of this section"))
        .collect();
    let Some(list) = object.get(SECTION_NAME).and_then(Value::as_array) else {
        problems.push("`sources` must be a list of entries".to_string());
        return Err(problems);
    };
    if list.len() > MAX_SOURCES {
        problems.push(format!(
            "`sources` has {} entries, and at most {MAX_SOURCES} are taken",
            list.len()
        ));
    }
    let mut seen = BTreeSet::new();
    let mut sources = Vec::with_capacity(list.len());
    for (i, entry) in list.iter().enumerate() {
        let at = format!("`sources[{i}]`");
        let Some(entry) = entry.as_object() else {
            problems.push(format!("{at} must be an object"));
            continue;
        };
        problems.extend(
            entry
                .keys()
                .filter(|k| !["name", "url", "interval_secs"].contains(&k.as_str()))
                .map(|k| format!("{at}: `{k}` is not a field")),
        );
        let name = entry.get("name").and_then(Value::as_str);
        match name {
            Some(name)
                if !name.is_empty()
                    && name.len() <= MAX_NAME
                    && !name.chars().any(char::is_control) =>
            {
                if !seen.insert(name) {
                    problems.push(format!("{at}: another source is named `{name}`"));
                }
            }
            _ => problems.push(format!(
                "{at}: `name` must be 1 to {MAX_NAME} characters with no control characters"
            )),
        }
        let url = entry.get("url").and_then(Value::as_str);
        match url {
            None => problems.push(format!("{at}: `url` must be text")),
            Some(url) => {
                if let Some(problem) = url_problem(url) {
                    problems.push(format!("{at}: `url` {problem}"));
                }
            }
        }
        let interval = entry.get("interval_secs").and_then(Value::as_u64);
        match interval {
            Some(secs) if (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&secs) => {}
            _ => problems.push(format!(
                "{at}: `interval_secs` must be from {MIN_INTERVAL_SECS} to {MAX_INTERVAL_SECS}"
            )),
        }
        if let (Some(name), Some(url), Some(interval_secs)) = (name, url, interval) {
            sources.push(Source {
                name: name.to_string(),
                url: url.to_string(),
                interval_secs,
            });
        }
    }
    if problems.is_empty() {
        Ok(sources)
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn entry(name: &str, url: &str, secs: u64) -> Value {
        json!({ "name": name, "url": url, "interval_secs": secs })
    }

    #[test]
    fn a_sound_list_is_read_as_it_says() {
        let body = json!({ "sources": [entry("shop", "https://shop.example/openapi.json", 900)] });
        assert_eq!(
            parse(&body).unwrap(),
            vec![Source {
                name: "shop".to_string(),
                url: "https://shop.example/openapi.json".to_string(),
                interval_secs: 900,
            }]
        );
        assert!(parse(&json!({ "sources": [] })).unwrap().is_empty());
    }

    #[test]
    fn what_cannot_be_read_is_refused_by_field() {
        for (bad, says) in [
            (entry("a", "ftp://h/x", 60), "neither http nor https"),
            (
                entry("a", "file:///etc/passwd", 60),
                "neither http nor https",
            ),
            (entry("a", "not a url", 60), "not a URL"),
            (entry("a", "https://user:pw@h/x", 60), "user or a password"),
            (entry("a", "https://user@h/x", 60), "user or a password"),
            (entry("", "https://h/x", 60), "`name`"),
            (entry("a\nb", "https://h/x", 60), "`name`"),
            (entry("a", "https://h/x", 59), "`interval_secs`"),
            (
                entry("a", "https://h/x", MAX_INTERVAL_SECS + 1),
                "`interval_secs`",
            ),
            (
                json!({ "name": "a", "url": "https://h/x" }),
                "`interval_secs`",
            ),
            (json!({ "name": "a", "interval_secs": 60 }), "`url`"),
            (
                json!({ "url": "https://h/x", "interval_secs": 60 }),
                "`name`",
            ),
            (
                json!({ "name": "a", "url": "https://h/x", "interval_secs": 60, "topic": "t" }),
                "not a field",
            ),
            (json!("x"), "must be an object"),
        ] {
            let problems = parse(&json!({ "sources": [bad] })).unwrap_err();
            assert!(
                problems.iter().any(|p| p.contains(says)),
                "{says}: {problems:?}"
            );
        }
        assert!(parse(&json!({ "sources": 1 })).is_err());
        assert!(parse(&json!({ "sources": [], "extra": 1 })).is_err());
        assert!(parse(&json!([])).is_err());
    }

    #[test]
    fn two_sources_cannot_share_a_name_since_the_name_identifies_them_in_the_graph() {
        let body =
            json!({ "sources": [entry("a", "https://h/1", 60), entry("a", "https://h/2", 60)] });
        assert!(parse(&body).unwrap_err()[0].contains("another source"));
    }

    #[test]
    fn a_refusal_does_not_repeat_an_address_which_may_hold_a_secret() {
        let body = json!({ "sources": [entry("a", "https://user:hunter2@h/x?token=hunter2", 60)] });
        assert!(
            parse(&body)
                .unwrap_err()
                .iter()
                .all(|p| !p.contains("hunter2"))
        );
    }

    #[test]
    fn too_many_sources_are_refused() {
        let many: Vec<Value> = (0..=MAX_SOURCES)
            .map(|i| entry(&format!("s{i}"), "https://h/x", 60))
            .collect();
        assert!(parse(&json!({ "sources": many })).unwrap_err()[0].contains("at most"));
    }

    proptest! {
        #[test]
        fn any_address_that_passes_can_be_read(url in "[ -~]{0,32}|https?://[a-z.]{1,12}/[a-z]{0,8}") {
            if url_problem(&url).is_none() {
                let parsed = url::Url::parse(&url).unwrap();
                prop_assert!(matches!(parsed.scheme(), "http" | "https"));
                prop_assert!(parsed.host_str().is_some());
                prop_assert!(parsed.username().is_empty() && parsed.password().is_none());
            }
        }

        #[test]
        fn only_an_interval_in_its_bounds_passes(secs in any::<u64>()) {
            let body = json!({ "sources": [entry("a", "https://h/x", secs)] });
            prop_assert_eq!(parse(&body).is_ok(), (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&secs));
        }
    }
}
