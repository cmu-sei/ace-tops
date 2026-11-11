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

//! The `mappings` runtime section: which repositories are built, and with what (docs/architecture/build-orchestrator.md,
//! decision 4). A pure reading of a body; nothing here touches a network, a credential or the clock.
//!
//! A signed document, authored with `polar-sign` and carried by the scheduler, replaces it whole. It is the one place a
//! build's pipeline image, command and privileges come from: never a build request, never the template. Nothing secret
//! is in it: a mapping names the credential its source is fetched with, if it needs one, and the `credentials` section holds
//! it. No credential reaches a build's pod (decision 1), so the fetch is all a mapping names one for.

use git_agent_common::remote::{credential_name_problem, repo_id_of, repository_host};
use orchestrator_core::types::{Privileges, pinned_by_digest};
use polar::graph::nodes::git::RepoId;
use polar_agent_builder::RuntimeSection;
use polar_agent_builder::runtime::SectionAuthority;
use serde_json::{Map, Value};

/// What the section is called in a document.
pub const SECTION_NAME: &str = "mappings";
/// Most repositories one version may map.
pub const MAX_ENTRIES: usize = 500;
/// Longest repository URL, as the git controller takes one.
pub const MAX_URL: usize = 2048;
/// Most words in a command, and the longest one.
pub const MAX_COMMAND: usize = 64;
pub const MAX_WORD: usize = 4096;
/// Most locks a mapping names.
pub const MAX_LOCKS: usize = 16;
/// Most capabilities a mapping adds: more than Linux has.
pub const MAX_CAPABILITIES: usize = 64;
/// Most facts a mapping allows, and the longest name.
pub const MAX_FACTS: usize = 64;
pub const MAX_FACT: usize = 128;

const FIELDS: [&str; 7] = [
    "url",
    "pipeline_image",
    "command",
    "privileges",
    "credential",
    "locks",
    "facts",
];
const PRIVILEGES: [&str; 3] = [
    "run_as_root",
    "allow_privilege_escalation",
    "add_capabilities",
];

pub static MAPPINGS: RuntimeSection = RuntimeSection {
    authority: SectionAuthority::Runtime,
    name: SECTION_NAME,
    doc: "The repositories build-orchestrator builds, and with what. Replaced whole by each version.",
    body: r#"{"repositories": {"list_of": {"url": {"type": "https URL of a host name, or an ssh URL of a host name or an address with a credential", "required": true, "doc": "the key of the entry: the URL the git controller observes it at, with no login in it; over ssh only with a credential, an ssh key that pins the server's host key"}, "pipeline_image": {"type": "image reference pinned by digest", "required": true, "doc": "what the build's pipeline runs in"}, "command": {"type": "list of text", "required": false, "doc": "the pipeline's command; left out, the orchestrator's default command"}, "privileges": {"type": "object", "required": false, "doc": "what the pipeline may do beyond running hardened; left out, nothing", "fields": {"run_as_root": {"type": "true or false", "default": false}, "allow_privilege_escalation": {"type": "true or false", "default": false}, "add_capabilities": {"type": "list of Kubernetes capability names, such as SETUID", "default": []}}}, "credential": {"type": "name of a credential", "required": false, "doc": "what its source is fetched with, by name: one the credentials section binds to its host; left out, it is fetched with none"}, "locks": {"type": "list of paths in the repository, each ending in Cargo.lock", "required": false, "doc": "the Cargo locks whose dependencies the build is given by digest, fetched by the orchestrator; left out, none, and the build has nothing but its source"}, "facts": {"type": "list of fact names, each a namespace and a name in lower case, such as polar.image/found-at", "required": false, "doc": "the facts its builds may report, by name: a fact named otherwise is refused; left out, none"}}}}"#,
    validate,
};

/// What one repository's builds run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    /// The repository's URL, as the entry gives it.
    pub url: String,
    /// The repository as the git observer names it in a ref update.
    pub repo: RepoId,
    /// The pipeline's image, pinned by digest.
    pub pipeline_image: String,
    /// The pipeline's command; `None`, the orchestrator's default.
    pub command: Option<Vec<String>>,
    pub privileges: Privileges,
    /// The credential its source is fetched with, by name; `None`, it is fetched with none.
    pub credential: Option<String>,
    /// The Cargo locks in its tree whose dependencies its builds are given, by digest.
    pub locks: Vec<String>,
    /// The names of the facts its builds may report (`polar.image/found-at`): a fact named otherwise is refused.
    pub facts: Vec<String>,
}

fn validate(body: &Value) -> Result<(), Vec<String>> {
    parse(body).map(|_| ())
}

/// The mappings a body describes, or every problem with it. A problem names the entry and the field, and never a value.
pub fn parse(body: &Value) -> Result<Vec<Mapping>, Vec<String>> {
    let Some(object) = body.as_object() else {
        return Err(vec!["the body must be an object".to_string()]);
    };
    let mut problems: Vec<String> = object
        .keys()
        .filter(|k| k.as_str() != "repositories")
        .map(|k| format!("`{}` is not a field of this section", shown(k)))
        .collect();
    let Some(list) = object.get("repositories").and_then(Value::as_array) else {
        problems.push("`repositories` must be a list of entries".to_string());
        return Err(problems);
    };
    if list.len() > MAX_ENTRIES {
        problems.push(format!(
            "`repositories` has {} entries, and at most {MAX_ENTRIES} are taken",
            list.len()
        ));
    }
    let mut mappings: Vec<Mapping> = Vec::new();
    for (i, item) in list.iter().enumerate() {
        match entry(i, item) {
            Ok(mapping) => {
                if mappings.iter().any(|m| m.repo == mapping.repo) {
                    problems.push(format!(
                        "entry {i}: the repository is mapped more than once"
                    ));
                }
                mappings.push(mapping);
            }
            Err(mut more) => problems.append(&mut more),
        }
    }
    if problems.is_empty() {
        Ok(mappings)
    } else {
        Err(problems)
    }
}

/// A field's name as a problem may show it: a name the section has, or none. A body's keys are the author's, and an
/// unknown one could be anything.
fn shown(key: &str) -> &str {
    if key.len() <= 32 && key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
        key
    } else {
        "(a name that is not shown)"
    }
}

/// What a list of text in a mapping may be.
struct List {
    /// Its name as a problem shows it.
    shown: &'static str,
    most: usize,
    longest: usize,
    /// Whether an empty list is one: not for a command, where empty would mean the image's own and leaving it out
    /// means the orchestrator's default.
    may_be_empty: bool,
}

const COMMAND: List = List {
    shown: "command",
    most: MAX_COMMAND,
    longest: MAX_WORD,
    may_be_empty: false,
};
const LOCKS: List = List {
    shown: "locks",
    most: MAX_LOCKS,
    longest: 512,
    may_be_empty: true,
};

/// Whether `path` is a lock's path in a tree: segments of letters, digits, `.`, `_` and `-`, none `.` or `..`, the last
/// `Cargo.lock`.
fn is_lock_path(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    segments.last() == Some(&"Cargo.lock")
        && segments.iter().all(|s| {
            !s.is_empty()
                && *s != "."
                && *s != ".."
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        })
}

const FACTS: List = List {
    shown: "facts",
    most: MAX_FACTS,
    longest: MAX_FACT,
    may_be_empty: true,
};

/// Whether `name` is a fact's name: a namespace of dot-separated words, a slash, and a word, each word a lower-case letter
/// and then lower-case letters, digits and `-` (`polar.image/found-at`).
pub fn is_fact_name(name: &str) -> bool {
    let word = |w: &str| {
        w.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && w.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    match name.split_once('/') {
        Some((namespace, rest)) => namespace.split('.').all(word) && word(rest),
        None => false,
    }
}

const CAPABILITIES: List = List {
    shown: "privileges.add_capabilities",
    most: MAX_CAPABILITIES,
    longest: 64,
    may_be_empty: true,
};

/// The list of non-empty text at `key`, held to `rule`; `None` if left out or wrong.
fn text_list(
    object: &Map<String, Value>,
    label: &str,
    key: &str,
    rule: &List,
    problems: &mut Vec<String>,
) -> Option<Vec<String>> {
    let shown = rule.shown;
    let items = match object.get(key) {
        None => return None,
        Some(Value::Array(items)) => items,
        Some(_) => {
            problems.push(format!("{label}: `{shown}` must be a list of text"));
            return None;
        }
    };
    if items.is_empty() && !rule.may_be_empty {
        problems.push(format!("{label}: `{shown}` is empty; leave it out instead"));
        return None;
    }
    if items.len() > rule.most {
        problems.push(format!(
            "{label}: `{shown}` has {} items, and at most {} are taken",
            items.len(),
            rule.most
        ));
        return None;
    }
    let texts: Vec<String> = items
        .iter()
        .filter_map(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= rule.longest)
        .map(str::to_string)
        .collect();
    if texts.len() != items.len() {
        problems.push(format!(
            "{label}: `{shown}` must be a list of text, each 1 to {} bytes",
            rule.longest
        ));
        return None;
    }
    Some(texts)
}

fn flag(object: &Map<String, Value>, label: &str, key: &str, problems: &mut Vec<String>) -> bool {
    match object.get(key) {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            problems.push(format!("{label}: `privileges.{key}` must be true or false"));
            false
        }
    }
}

fn privileges(object: &Map<String, Value>, label: &str, problems: &mut Vec<String>) -> Privileges {
    let Some(value) = object.get("privileges") else {
        return Privileges::default();
    };
    let Some(fields) = value.as_object() else {
        problems.push(format!("{label}: `privileges` must be an object"));
        return Privileges::default();
    };
    problems.extend(
        fields
            .keys()
            .filter(|k| !PRIVILEGES.contains(&k.as_str()))
            .map(|k| format!("{label}: `privileges.{}` is not a privilege", shown(k))),
    );
    let privileges = Privileges {
        run_as_root: flag(fields, label, "run_as_root", problems),
        allow_privilege_escalation: flag(fields, label, "allow_privilege_escalation", problems),
        add_capabilities: text_list(fields, label, "add_capabilities", &CAPABILITIES, problems)
            .unwrap_or_default(),
    };
    // A capability that is not one is named by its place, not its text.
    let wrong = privileges.problems().len();
    if wrong > 0 {
        problems.push(format!(
            "{label}: `privileges.add_capabilities` names {wrong} that are not capabilities to add: a Kubernetes name, \
             such as SETUID, and not ALL"
        ));
    }
    privileges
}

fn entry(i: usize, item: &Value) -> Result<Mapping, Vec<String>> {
    let label = format!("entry {i}");
    let Some(object) = item.as_object() else {
        return Err(vec![format!("{label}: must be an object")]);
    };
    let mut problems: Vec<String> = object
        .keys()
        .filter(|k| !FIELDS.contains(&k.as_str()))
        .map(|k| format!("{label}: `{}` is not a field of an entry", shown(k)))
        .collect();

    // Over ssh a source is fetched only with a credential: whether the entry names one is what the URL is read with.
    let names_a_credential = object.get("credential").is_some_and(|c| !c.is_null());
    let url = match object.get("url").and_then(Value::as_str) {
        None => {
            problems.push(format!("{label}: `url` is required, as text"));
            String::new()
        }
        Some(url) if url.len() > MAX_URL => {
            problems.push(format!("{label}: `url` is longer than {MAX_URL} bytes"));
            String::new()
        }
        Some(url) if url.chars().any(|c| c.is_control() || c.is_whitespace()) => {
            problems.push(format!("{label}: `url` has a space or a control character"));
            String::new()
        }
        Some(url) => match repository_host(url, names_a_credential) {
            Ok(_) => url.to_string(),
            Err(why) => {
                problems.push(format!("{label}: `url`: {why}"));
                String::new()
            }
        },
    };
    let pipeline_image = match object.get("pipeline_image") {
        None => {
            problems.push(format!("{label}: `pipeline_image` is required"));
            String::new()
        }
        Some(Value::String(s)) if pinned_by_digest(s) => s.clone(),
        Some(_) => {
            problems.push(format!(
                "{label}: `pipeline_image` must be an image pinned by digest (name@sha256:<64 hex digits>)"
            ));
            String::new()
        }
    };
    let command = text_list(object, &label, "command", &COMMAND, &mut problems);
    let privileges = privileges(object, &label, &mut problems);
    let credential = match object.get("credential") {
        None => None,
        Some(Value::String(name)) => match credential_name_problem(name) {
            None => Some(name.clone()),
            Some(why) => {
                problems.push(format!("{label}: `credential` {why}"));
                None
            }
        },
        Some(_) => {
            problems.push(format!("{label}: `credential` must be a credential's name"));
            None
        }
    };

    let locks = text_list(object, &label, "locks", &LOCKS, &mut problems).unwrap_or_default();
    if locks.iter().any(|path| !is_lock_path(path)) {
        problems.push(format!(
            "{label}: `locks` names a path that is not a Cargo.lock within the repository"
        ));
    }
    let facts = text_list(object, &label, "facts", &FACTS, &mut problems).unwrap_or_default();
    if facts.iter().any(|name| !is_fact_name(name)) {
        problems.push(format!(
            "{label}: `facts` names one that is not a namespace and a name in lower case, such as polar.image/found-at"
        ));
    }
    if facts
        .iter()
        .enumerate()
        .any(|(i, name)| facts[..i].contains(name))
    {
        problems.push(format!("{label}: `facts` names one more than once"));
    }
    if problems.is_empty() {
        Ok(Mapping {
            repo: repo_id_of(&url),
            url,
            pipeline_image,
            command,
            privileges,
            credential,
            locks,
            facts,
        })
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn image() -> String {
        format!("registry.polar/pipelines/ci@sha256:{}", "a".repeat(64))
    }

    #[test]
    fn a_mapping_reads() {
        let parsed = parse(&json!({"repositories": [
            {"url": "https://git.example.org/a/b.git", "pipeline_image": image(), "credential": "git-a",
             "privileges": {"run_as_root": true, "add_capabilities": ["SETUID", "SETGID"]}}
        ]}))
        .unwrap();
        assert_eq!(parsed.len(), 1);
        let m = &parsed[0];
        // Known by the id the controller gives the observer, `.git` and all.
        assert_eq!(m.repo, RepoId::from_url("https://git.example.org/a/b"));
        assert_eq!(m.credential.as_deref(), Some("git-a"));
        assert!(m.command.is_none());
        assert!(m.privileges.run_as_root);
        assert!(!m.privileges.allow_privilege_escalation);
        assert_eq!(m.privileges.add_capabilities, ["SETUID", "SETGID"]);
    }

    /// The private gitea over ssh: a mapping names it with the credential its source is fetched with, and is refused
    /// without one.
    #[test]
    fn a_repository_over_ssh_is_mapped_with_a_credential_and_refused_without_one() {
        let parsed = parse(&json!({"repositories": [
            {"url": "ssh://52.235.181.217/SEI/ACE.git", "pipeline_image": image(), "credential": "gitea"}
        ]}))
        .unwrap();
        assert_eq!(parsed[0].url, "ssh://52.235.181.217/SEI/ACE.git");
        assert_eq!(parsed[0].credential.as_deref(), Some("gitea"));
        let problems = parse(&json!({"repositories": [
            {"url": "ssh://52.235.181.217/SEI/ACE.git", "pipeline_image": image()}
        ]}))
        .unwrap_err()
        .join(" | ");
        assert!(
            problems.contains("`url`") && problems.contains("credential"),
            "{problems}"
        );
    }

    #[test]
    fn a_mapping_with_nothing_more_runs_hardened() {
        let parsed = parse(&json!({"repositories": [
            {"url": "https://git.example.org/a/b.git", "pipeline_image": image()}
        ]}))
        .unwrap();
        assert_eq!(parsed[0].privileges, Privileges::default());
        assert!(parsed[0].credential.is_none());
    }

    #[test]
    fn every_problem_is_named_and_none_is_a_value() {
        let problems = parse(&json!({"repositories": [
            {"url": "http://x.example/y", "pipeline_image": image(), "extra": 1},
            {"url": "https://u:secret@x.example/y", "pipeline_image": image()},
            {"url": "https://x.example/y", "pipeline_image": image(), "credential": ["git-a"]},
            {"url": "https://x.example/z", "pipeline_image": image()},
            {"url": "https://x.example/z", "pipeline_image": image()},
            {"url": "https://x.example/w", "pipeline_image": "reg/x:latest"},
            {"url": "https://x.example/v"},
            {"url": "https://x.example/u", "pipeline_image": image(), "command": []},
            {"url": "https://x.example/t", "pipeline_image": image(),
             "privileges": {"privileged": true, "run_as_root": "yes", "add_capabilities": ["ALL", "CAP_SYS_ADMIN"]}},
            {"url": "https://x.example/s", "pipeline_image": image(), "credential": "Secret_Name"},
            {"url": "https://x.example/r", "pipeline_image": image(), "Hidden-Key-secret": 1},
        ], "other": 1}))
        .unwrap_err();
        for expected in [
            "`other` is not a field",
            "entry 0: `extra`",
            "entry 0: `url`",
            "entry 1: `url`",
            "entry 2: `credential` must be",
            "entry 4: the repository is mapped more than once",
            "entry 5: `pipeline_image` must be an image pinned by digest",
            "entry 6: `pipeline_image` is required",
            "entry 7: `command` is empty",
            "entry 8: `privileges.privileged` is not a privilege",
            "entry 8: `privileges.run_as_root` must be true or false",
            "entry 8: `privileges.add_capabilities` names 2",
            "entry 9: `credential` may have",
            "entry 10: `(a name that is not shown)`",
        ] {
            assert!(
                problems.iter().any(|p| p.contains(expected)),
                "{expected} in {problems:#?}"
            );
        }
        for value in ["secret", "latest", "SYS_ADMIN", "Secret_Name", "Hidden"] {
            assert!(
                !problems.iter().any(|p| p.contains(value)),
                "{value} echoed in {problems:#?}"
            );
        }
    }

    #[test]
    fn a_mapping_names_its_locks_within_the_tree() {
        let parsed = parse(&json!({"repositories": [
            {"url": "https://git.example.org/a/b.git", "pipeline_image": image(),
             "locks": ["Cargo.lock", "src/agents/Cargo.lock"]}
        ]}))
        .unwrap();
        assert_eq!(parsed[0].locks, ["Cargo.lock", "src/agents/Cargo.lock"]);
        for bad in [
            "../Cargo.lock",
            "/Cargo.lock",
            "a//Cargo.lock",
            "a/./Cargo.lock",
            "Cargo.toml",
            "a/Cargo.lock/",
            "a b/Cargo.lock",
        ] {
            let problems = parse(&json!({"repositories": [
                {"url": "https://git.example.org/a/b.git", "pipeline_image": image(), "locks": [bad]}
            ]}))
            .unwrap_err();
            assert!(
                problems.iter().any(|p| p.contains("entry 0: `locks`")),
                "{bad}: {problems:?}"
            );
        }
    }

    /// A mapping names the facts its builds may report, each a namespace and a name; a name of another form, a repeat, or
    /// a list too long is refused, naming the field and never the name.
    #[test]
    fn a_mapping_names_the_facts_its_builds_may_report() {
        let parsed = parse(&json!({"repositories": [
            {"url": "https://git.example.org/a/b.git", "pipeline_image": image(),
             "facts": ["polar.image/found-at", "polar.nix/realised"]}
        ]}))
        .unwrap();
        assert_eq!(
            parsed[0].facts,
            ["polar.image/found-at", "polar.nix/realised"]
        );
        let none = parse(&json!({"repositories": [
            {"url": "https://git.example.org/a/b.git", "pipeline_image": image()}
        ]}))
        .unwrap();
        assert!(none[0].facts.is_empty(), "left out, no fact is allowed");
        let too_long = format!("a/{}", "b".repeat(MAX_FACT));
        let many: Vec<String> = (0..=MAX_FACTS)
            .map(|i| format!("polar.test/f{i}"))
            .collect();
        for bad in [
            json!(["Polar/Hidden"]),
            json!(["noslash"]),
            json!(["a/b/c"]),
            json!(["/name"]),
            json!(["space/a name"]),
            json!([""]),
            json!([too_long]),
            json!(["polar.x/a", "polar.x/a"]),
            json!(many),
            json!("polar.x/a"),
        ] {
            let problems = parse(&json!({"repositories": [
                {"url": "https://git.example.org/a/b.git", "pipeline_image": image(), "facts": bad}
            ]}))
            .unwrap_err();
            assert!(
                problems.iter().any(|p| p.contains("entry 0: `facts`")),
                "{bad}: {problems:?}"
            );
            assert!(
                !problems.iter().any(|p| p.contains("Hidden")),
                "{problems:?}"
            );
        }
    }

    #[test]
    fn an_empty_list_withdraws_every_mapping() {
        assert!(parse(&json!({"repositories": []})).unwrap().is_empty());
    }

    #[test]
    fn the_scaffold_body_is_json() {
        serde_json::from_str::<Value>(MAPPINGS.body).unwrap();
    }
}
