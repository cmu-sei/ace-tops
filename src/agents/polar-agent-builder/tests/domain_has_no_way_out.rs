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

// A domain crate on the builder reaches the outside through its protocol handlers: with no client of its own it cannot walk round
// the judgment, and with no CryptoActor or custody client of its own it cannot get to a credential (docs/architecture/protocol-handlers.md,
// "No way to the credential from domain code"). The workspace is read from `cargo metadata`, so a new agent, or a helper crate one of
// them leans on, is held to this without being listed here. What this cannot see, a raw socket or a method of a crate an agent may
// have, a lint in that crate's clippy.toml does, where it can.

use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// What makes a request of its own.
const CLIENTS: &[&str] = &[
    "reqwest",
    "git2",
    "oci-client",
    "kube",
    "kube-client",
    "hyper",
    "hyper-util",
    "h2",
    "ureq",
    "curl",
    "isahc",
    "surf",
    "awc",
    "tonic",
];

/// What could get to a credential by another way than the handler's: an actor of its own, which could load one and give it any pass,
/// or the custody daemon, which opens what is escrowed.
const WAYS_TO_A_SECRET: &[&str] = &["polar-crypto", "polar-custody"];

/// Not the domain, by decision: the credentials agent and cert-issuer do not use handlers (the maintainer, 2026-11-03), and the rest are
/// infrastructure, or serve rather than ask.
const NOT_THE_DOMAIN: &[(&str, &str)] = &[
    ("cert-issuer", "the maintainer: not this framework"),
    (
        "credentials-agent-consumer",
        "the maintainer: not this framework",
    ),
    (
        "credentials-agent-observer",
        "the maintainer: not this framework",
    ),
    (
        "credentials-agent-model",
        "the maintainer: not this framework",
    ),
    ("cassini-broker", "infrastructure, which serves"),
    ("polar-git-server", "serves git, and delivers configuration"),
    ("polar-custody-daemon", "it is the custody daemon"),
];

/// Where the walk stops: the framework's own crates, which do hold clients and keys, for the domain and in its stead.
const FRAMEWORK: &[&str] = &[
    "polar",
    "polar-agent-builder",
    "polar-crypto",
    "polar-custody",
    "polar-health",
    "cassini-client",
    "cassini-broker",
];

/// What a domain crate may have after all, because it holds the types and no more, and what says so.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "git-repo-observer",
        "git2",
        "reads the clone the handler fetched: `git/observe/clippy.toml` forbids the rest",
    ),
    (
        "oci-resolver",
        "oci-client",
        "its types: `resolver/clippy.toml` forbids its client",
    ),
    (
        "build-processor",
        "oci-client",
        "the manifest types of what the resolver verified: `build-processor/clippy.toml` forbids its client",
    ),
    (
        "kube-common",
        "kube",
        "derives the types of Flux's kinds, and never makes a client",
    ),
];

struct Rules<'a> {
    clients: &'a [&'a str],
    secrets: &'a [&'a str],
    not_the_domain: &'a [(&'a str, &'a str)],
    framework: &'a [&'a str],
    allowed: &'a [(&'a str, &'a str, &'a str)],
}

const RULES: Rules = Rules {
    clients: CLIENTS,
    secrets: WAYS_TO_A_SECRET,
    not_the_domain: NOT_THE_DOMAIN,
    framework: FRAMEWORK,
    allowed: ALLOWED,
};

fn normal_dependencies(package: &Value) -> Vec<&Value> {
    package["dependencies"]
        .as_array()
        .map(|deps| deps.iter().filter(|dep| dep["kind"].is_null()).collect())
        .unwrap_or_default()
}

/// Whether nothing of `package` can reach a workload: it builds no binary, and no crate in the workspace takes it as a normal
/// dependency, so only tests use it (`polar-http-testkit`). The day a crate takes it as a normal dependency, it is walked from
/// that crate as any helper is. A package that says nothing of its targets may ship.
fn only_tests_use(package: &Value, packages: &[Value]) -> bool {
    let name = package["name"].as_str().unwrap_or_default();
    let Some(targets) = package["targets"].as_array() else {
        return false;
    };
    let builds_a_binary = targets.iter().any(|target| {
        target["kind"]
            .as_array()
            .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
    });
    let taken = packages.iter().any(|other| {
        normal_dependencies(other)
            .iter()
            .any(|dep| dep_name(dep) == name)
    });
    !builds_a_binary && !taken
}

fn named<'a>(packages: &'a [Value], name: &str) -> Option<&'a Value> {
    packages.iter().find(|package| package["name"] == name)
}

fn dep_name(dep: &Value) -> &str {
    dep["name"].as_str().unwrap_or_default()
}

/// Every way a domain crate on the builder breaks the rule, and every allowance nothing needs any more.
fn problems(packages: &[Value], rules: &Rules) -> Vec<String> {
    let mut problems = Vec::new();
    let mut allowances_used = BTreeSet::new();
    let on_the_builder = packages.iter().filter(|package| {
        normal_dependencies(package)
            .iter()
            .any(|dep| dep_name(dep) == "polar-agent-builder")
    });
    for package in on_the_builder {
        let agent = package["name"].as_str().unwrap_or_default();
        if rules.not_the_domain.iter().any(|(name, _)| *name == agent)
            || only_tests_use(package, packages)
        {
            continue;
        }
        // Each crate it leans on as well: a helper crate is no way round this.
        let mut seen = BTreeSet::new();
        let mut walking = vec![agent];
        while let Some(crate_name) = walking.pop() {
            if !seen.insert(crate_name) {
                continue;
            }
            let Some(current) = named(packages, crate_name) else {
                continue;
            };
            for dep in normal_dependencies(current) {
                let name = dep_name(dep);
                if name == "polar-agent-builder"
                    && dep["features"]
                        .as_array()
                        .is_some_and(|features| features.iter().any(|f| f == "testing"))
                {
                    problems.push(format!(
                        "{crate_name} enables the builder's `testing` feature outside its tests, for {agent}"
                    ));
                }
                if rules.clients.contains(&name) || rules.secrets.contains(&name) {
                    if rules
                        .allowed
                        .iter()
                        .any(|(holder, what, _)| *holder == crate_name && *what == name)
                    {
                        allowances_used.insert((crate_name, name));
                    } else {
                        problems.push(format!(
                            "{crate_name} depends on {name}, which {agent} could then reach: the domain goes out through its protocol handlers"
                        ));
                    }
                }
                if !rules.framework.contains(&name) {
                    walking.push(name);
                }
            }
        }
    }
    for (holder, what, _) in rules.allowed {
        if !allowances_used.contains(&(*holder, *what)) {
            problems.push(format!(
                "{holder} is allowed {what}, and no longer needs it: take it off the list"
            ));
        }
    }
    problems.sort();
    problems.dedup();
    problems
}

fn workspace() -> Vec<Value> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .expect("cargo metadata runs");
    assert!(out.status.success(), "cargo metadata failed");
    let metadata: Value = serde_json::from_slice(&out.stdout).expect("cargo metadata is JSON");
    metadata["packages"].as_array().cloned().expect("packages")
}

#[test]
fn no_domain_crate_on_the_builder_has_a_way_out_of_its_own() {
    let packages = workspace();
    // It would pass by reading nothing: these are on the builder and on handlers, today.
    for agent in [
        "jira-observer",
        "git-repo-observer",
        "oci-resolver",
        "kube-observer",
        "attestation-agent",
    ] {
        assert!(
            named(&packages, agent).is_some(),
            "{agent} is in the workspace"
        );
    }
    let problems = problems(&packages, &RULES);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

// -- the check itself ---------------------------------------------------------------------------------------------------

fn dep(name: &str) -> Value {
    json!({"name": name, "kind": null, "features": []})
}

fn package(name: &str, deps: Vec<Value>) -> Value {
    json!({"name": name, "dependencies": deps})
}

fn found(packages: Vec<Value>, rules: &Rules) -> String {
    problems(&packages, rules).join("\n")
}

const TEST_RULES: Rules = Rules {
    clients: &["reqwest"],
    secrets: &["polar-crypto"],
    not_the_domain: &[("the-credentials-agent", "by decision")],
    framework: &["polar-agent-builder", "framework-crate"],
    allowed: &[("reads-types", "reqwest", "why")],
};

fn with_the_allowance_used() -> Value {
    package(
        "reads-types",
        vec![dep("polar-agent-builder"), dep("reqwest")],
    )
}

#[test]
fn a_client_or_a_way_to_a_secret_is_found() {
    for way_out in ["reqwest", "polar-crypto"] {
        let all = found(
            vec![
                package("agent", vec![dep("polar-agent-builder"), dep(way_out)]),
                with_the_allowance_used(),
            ],
            &TEST_RULES,
        );
        assert!(
            all.contains(&format!("agent depends on {way_out}")),
            "{all}"
        );
    }
}

#[test]
fn a_helper_crate_is_no_way_round_it() {
    let all = found(
        vec![
            package("agent", vec![dep("polar-agent-builder"), dep("helper")]),
            package("helper", vec![dep("deeper")]),
            package("deeper", vec![dep("reqwest")]),
            with_the_allowance_used(),
        ],
        &TEST_RULES,
    );
    assert!(
        all.contains("deeper depends on reqwest, which agent"),
        "{all}"
    );
}

#[test]
fn what_a_test_uses_what_is_not_on_the_builder_and_what_is_not_the_domain_are_left_alone() {
    let in_its_tests = json!({"name": "reqwest", "kind": "dev", "features": []});
    let all = found(
        vec![
            package("agent", vec![dep("polar-agent-builder"), in_its_tests]),
            package("not-on-the-builder-yet", vec![dep("reqwest")]),
            package(
                "the-credentials-agent",
                vec![dep("polar-agent-builder"), dep("reqwest")],
            ),
            package(
                "leans-on-the-framework",
                vec![dep("polar-agent-builder"), dep("framework-crate")],
            ),
            package("framework-crate", vec![dep("reqwest")]),
            with_the_allowance_used(),
        ],
        &TEST_RULES,
    );
    assert_eq!(all, "");
}

fn with_targets(mut package: Value, kinds: &[&str]) -> Value {
    package["targets"] = json!(
        kinds
            .iter()
            .map(|kind| json!({ "kind": [kind] }))
            .collect::<Vec<_>>()
    );
    package
}

#[test]
fn a_library_only_tests_use_is_left_alone_until_a_workload_takes_it() {
    let kit = || {
        with_targets(
            package("kit", vec![dep("polar-agent-builder"), dep("reqwest")]),
            &["lib"],
        )
    };
    assert_eq!(
        found(vec![kit(), with_the_allowance_used()], &TEST_RULES),
        ""
    );
    let taken = found(
        vec![
            kit(),
            package("agent", vec![dep("polar-agent-builder"), dep("kit")]),
            with_the_allowance_used(),
        ],
        &TEST_RULES,
    );
    assert!(
        taken.contains("kit depends on reqwest, which agent"),
        "{taken}"
    );
    let ships = found(
        vec![
            with_targets(
                package("kit", vec![dep("polar-agent-builder"), dep("reqwest")]),
                &["lib", "bin"],
            ),
            with_the_allowance_used(),
        ],
        &TEST_RULES,
    );
    assert!(
        ships.contains("kit depends on reqwest, which kit"),
        "{ships}"
    );
}

#[test]
fn the_testing_feature_is_for_tests() {
    let testing = json!({"name": "polar-agent-builder", "kind": null, "features": ["testing"]});
    let all = found(
        vec![package("agent", vec![testing]), with_the_allowance_used()],
        &TEST_RULES,
    );
    assert!(
        all.contains("agent enables the builder's `testing` feature"),
        "{all}"
    );
}

#[test]
fn an_allowance_nothing_needs_is_said_to_be_stale() {
    let all = found(
        vec![package("agent", vec![dep("polar-agent-builder")])],
        &TEST_RULES,
    );
    assert!(
        all.contains("reads-types is allowed reqwest, and no longer needs it"),
        "{all}"
    );
}
