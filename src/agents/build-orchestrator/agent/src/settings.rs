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

//! What build-orchestrator reads from its configuration, declared once (docs/architecture/build-orchestrator.md, decision 5):
//!
//! - the deployment's facts, Static and with no default, since the catalog says them: the namespace builds run in and the
//!   PodTemplate a build's Job is made from;
//! - its run-time settings, Dynamic, so a signed update changes them in a running agent, each with a default: how many
//!   builds run at once, what a pipeline may use, how long a finished Job is kept, how much one build may report, how
//!   much of a report line the reader reads, and the command a mapping that names none runs.
//!
//! The reader's bounds are also what its worker allocates when it is forked, at start: a signed update may narrow them
//! while the agent runs, never widen them past what the worker was given ([`narrowed`]).

use orchestrator_backend_k8s::job::PipelineResources;
use orchestrator_core::backend::Retention;
use orchestrator_core::relay::RelayBounds;
use orchestrator_report::Bounds;
use polar_env::{Config, Defaulted, Described, Env, Required, Section};
use std::time::Duration;

pub static NAMESPACE: Required<String> = Required::text(
    "POLAR_ORCHESTRATOR_NAMESPACE",
    "the namespace builds run in: the build workload's, where its PodTemplate is and its Jobs are made",
);

pub static TEMPLATE: Required<String> = Required::text(
    "POLAR_ORCHESTRATOR_TEMPLATE",
    "the PodTemplate a build's Job is made from: the build workload's name",
);

/// The registry's variable, by name: the operation that pushes there is declared at its host (`push::PUSH`).
pub const REGISTRY_VAR: &str = "POLAR_ORCHESTRATOR_REGISTRY";

pub static REGISTRY: Required<String> = Required::text(
    REGISTRY_VAR,
    "the registry a build's source is pushed to and its pod fetches it from, as a pod reaches it: http:// or https://, a \
     host and a port, and nothing more",
);

pub static CONCURRENT_BUILDS: Defaulted<usize> = Defaulted::number(
    "POLAR_ORCHESTRATOR_CONCURRENT_BUILDS",
    "how many builds run at once; one over it waits its turn. At least 1",
    "1",
)
.dynamic();

pub static CPU_LIMIT: Defaulted<String> = Defaulted::text(
    "POLAR_ORCHESTRATOR_CPU_LIMIT",
    "the most CPU a build's pipeline may use, as a Kubernetes quantity",
    "2",
)
.dynamic();

pub static MEMORY_LIMIT: Defaulted<String> = Defaulted::text(
    "POLAR_ORCHESTRATOR_MEMORY_LIMIT",
    "the most memory a build's pipeline may use, as a Kubernetes quantity",
    "4Gi",
)
.dynamic();

pub static CPU_REQUEST: Defaulted<String> = Defaulted::text(
    "POLAR_ORCHESTRATOR_CPU_REQUEST",
    "the CPU a build's pipeline is scheduled for, as a Kubernetes quantity; no more than its limit",
    "500m",
)
.dynamic();

pub static MEMORY_REQUEST: Defaulted<String> = Defaulted::text(
    "POLAR_ORCHESTRATOR_MEMORY_REQUEST",
    "the memory a build's pipeline is scheduled for, as a Kubernetes quantity; no more than its limit",
    "512Mi",
)
.dynamic();

pub static WORKSPACE_LIMIT: Defaulted<String> = Defaulted::text(
    "POLAR_ORCHESTRATOR_WORKSPACE_LIMIT",
    "the most a build's workspace may hold, as a Kubernetes quantity: past it the pod is evicted, before it fills the \
     node's disk",
    "8Gi",
)
.dynamic();

pub static KEEP_SUCCEEDED_SECS: Defaulted<u64> = Defaulted::seconds(
    "POLAR_ORCHESTRATOR_KEEP_SUCCEEDED_SECS",
    "how long a build's Job is kept once it succeeded, in seconds; at least 60, room for the one read after its pod ends",
    "3600",
)
.dynamic();

pub static KEEP_FAILED_SECS: Defaulted<u64> = Defaulted::seconds(
    "POLAR_ORCHESTRATOR_KEEP_FAILED_SECS",
    "how long a build's Job is kept once it failed, in seconds; at least 60. Longer than a success's: its pod and events \
     are what someone reads to find out why",
    "86400",
)
.dynamic();

pub static MAX_REPORTS: Defaulted<usize> = Defaulted::number(
    "POLAR_ORCHESTRATOR_MAX_REPORTS",
    "how many report lines one build may print, read or refused; past it the rest are refused. At least 1",
    "10000",
)
.dynamic();

pub static MAX_REPORT_BYTES: Defaulted<u64> = Defaulted::number(
    "POLAR_ORCHESTRATOR_MAX_REPORT_BYTES",
    "how many bytes of report lines one build may print, read or refused. At least 1",
    "67108864",
)
.dynamic();

pub static REPORT_LINE_BYTES: Defaulted<usize> = Defaulted::number(
    "POLAR_ORCHESTRATOR_REPORT_LINE_BYTES",
    "the longest report line the reader reads, in bytes, its prefix not counted. At least 1; narrowed while the agent \
     runs, never widened past its value at start",
    "16777216",
)
.dynamic();

pub static REPORT_STRING_BYTES: Defaulted<usize> = Defaulted::number(
    "POLAR_ORCHESTRATOR_REPORT_STRING_BYTES",
    "the longest string in a report line, in bytes as written. At least 1; never widened past its value at start",
    "4096",
)
.dynamic();

pub static REPORT_DEPTH: Defaulted<usize> = Defaulted::number(
    "POLAR_ORCHESTRATOR_REPORT_DEPTH",
    "how deep a report line's objects and lists may nest. At least 1 (an SBOM's report needs 3); never widened past its \
     value at start",
    "6",
)
.dynamic();

pub static REPORT_TOKENS: Defaulted<usize> = Defaulted::number(
    "POLAR_ORCHESTRATOR_REPORT_TOKENS",
    "the most tokens the reader makes of one line. 1 to 4294967295; never widened past its value at start",
    "1048576",
)
.dynamic();

pub static REPORT_ITEMS: Defaulted<usize> = Defaulted::number(
    "POLAR_ORCHESTRATOR_REPORT_ITEMS",
    "the most items in one list of a report line. At least 1; never widened past its value at start",
    "65536",
)
.dynamic();

pub static DEFAULT_COMMAND: Defaulted<Vec<String>> = Defaulted::list(
    "POLAR_ORCHESTRATOR_DEFAULT_COMMAND",
    "the command a build's pipeline runs when its repository's mapping names none; empty, the pipeline image's own",
    "",
)
.dynamic();

/// The deployment's facts.
pub static DEPLOYMENT: &[&dyn Described] = &[&NAMESPACE, &TEMPLATE, &REGISTRY];

/// The run-time settings, followed as one group: an update that changes several is one change.
pub static TUNING: &[&dyn Described] = &[
    &CONCURRENT_BUILDS,
    &CPU_LIMIT,
    &MEMORY_LIMIT,
    &CPU_REQUEST,
    &MEMORY_REQUEST,
    &WORKSPACE_LIMIT,
    &KEEP_SUCCEEDED_SECS,
    &KEEP_FAILED_SECS,
    &MAX_REPORTS,
    &MAX_REPORT_BYTES,
    &REPORT_LINE_BYTES,
    &REPORT_STRING_BYTES,
    &REPORT_DEPTH,
    &REPORT_TOKENS,
    &REPORT_ITEMS,
    &DEFAULT_COMMAND,
];

static VARIABLES: &[&dyn Described] = &[
    &NAMESPACE,
    &TEMPLATE,
    &REGISTRY,
    &CONCURRENT_BUILDS,
    &CPU_LIMIT,
    &MEMORY_LIMIT,
    &CPU_REQUEST,
    &MEMORY_REQUEST,
    &WORKSPACE_LIMIT,
    &KEEP_SUCCEEDED_SECS,
    &KEEP_FAILED_SECS,
    &MAX_REPORTS,
    &MAX_REPORT_BYTES,
    &REPORT_LINE_BYTES,
    &REPORT_STRING_BYTES,
    &REPORT_DEPTH,
    &REPORT_TOKENS,
    &REPORT_ITEMS,
    &DEFAULT_COMMAND,
];

/// The shortest a finished Job is kept.
const LEAST_KEEP_SECS: u64 = 60;

/// The most tokens a tape holds: its spans are `u32` (orchestrator-report, `Tape`).
const MOST_TOKENS: usize = u32::MAX as usize;

/// The section build-orchestrator registers.
pub static SECTION: Section = Section {
    name: "build-orchestrator",
    vars: VARIABLES,
    relations,
};

/// Where the builds are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    pub namespace: String,
    pub template: String,
    /// The registry's address, `http(s)://host:port`.
    pub registry: String,
}

/// The run-time settings in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuning {
    pub concurrent_builds: usize,
    pub resources: PipelineResources,
    pub workspace_limit: String,
    pub retention: Retention,
    pub relay: RelayBounds,
    pub reader: Bounds,
    pub default_command: Vec<String>,
}

pub fn deployment(config: &Config) -> Result<Deployment, String> {
    Ok(Deployment {
        namespace: config.read(&NAMESPACE).map_err(|e| e.to_string())?,
        template: config.read(&TEMPLATE).map_err(|e| e.to_string())?,
        registry: config.read(&REGISTRY).map_err(|e| e.to_string())?,
    })
}

pub fn tuning(config: &Config) -> Result<Tuning, String> {
    let read = |e: polar_env::ConfigError| e.to_string();
    Ok(Tuning {
        concurrent_builds: config.read(&CONCURRENT_BUILDS).map_err(read)?,
        resources: PipelineResources {
            cpu_limit: config.read(&CPU_LIMIT).map_err(read)?,
            memory_limit: config.read(&MEMORY_LIMIT).map_err(read)?,
            cpu_request: config.read(&CPU_REQUEST).map_err(read)?,
            memory_request: config.read(&MEMORY_REQUEST).map_err(read)?,
        },
        workspace_limit: config.read(&WORKSPACE_LIMIT).map_err(read)?,
        retention: Retention {
            succeeded: Duration::from_secs(config.read(&KEEP_SUCCEEDED_SECS).map_err(read)?),
            failed: Duration::from_secs(config.read(&KEEP_FAILED_SECS).map_err(read)?),
        },
        relay: RelayBounds {
            reports: config.read(&MAX_REPORTS).map_err(read)?,
            bytes: config.read(&MAX_REPORT_BYTES).map_err(read)?,
        },
        reader: reader_bounds(config)?,
        default_command: config.read(&DEFAULT_COMMAND).map_err(read)?,
    })
}

/// The reader's bounds in force: what its worker is forked with at start.
pub fn reader_bounds(config: &Config) -> Result<Bounds, String> {
    let read = |e: polar_env::ConfigError| e.to_string();
    Ok(Bounds {
        line: config.read(&REPORT_LINE_BYTES).map_err(read)?,
        string: config.read(&REPORT_STRING_BYTES).map_err(read)?,
        depth: config.read(&REPORT_DEPTH).map_err(read)?,
        tokens: config.read(&REPORT_TOKENS).map_err(read)?,
        items: config.read(&REPORT_ITEMS).map_err(read)?,
    })
}

/// The bounds a line is read to: each the smaller of what the worker was forked with and what is signed now. A signed
/// update narrows the reader; it never asks the worker for more than it was given.
pub fn narrowed(forked: &Bounds, signed: &Bounds) -> Bounds {
    Bounds {
        line: forked.line.min(signed.line),
        string: forked.string.min(signed.string),
        depth: forked.depth.min(signed.depth),
        tokens: forked.tokens.min(signed.tokens),
        items: forked.items.min(signed.items),
    }
}

/// A Kubernetes quantity as Polar takes one, in thousandths of its unit: digits, an optional fraction, and an optional
/// suffix (`m`, `k`, `M`, `G`, `T`, `P`, `E`, or `Ki` to `Ei`). No sign and no exponent: a request or a limit needs
/// neither, and a form the two sides could read differently is refused. `None` if it is not one, or too large to hold.
pub fn milli(quantity: &str) -> Option<u128> {
    const SUFFIXES: [(&str, u128); 14] = [
        ("Ki", 1 << 10),
        ("Mi", 1 << 20),
        ("Gi", 1 << 30),
        ("Ti", 1 << 40),
        ("Pi", 1 << 50),
        ("Ei", 1 << 60),
        ("m", 0),
        ("k", 1_000),
        ("M", 1_000_000),
        ("G", 1_000_000_000),
        ("T", 1_000_000_000_000),
        ("P", 1_000_000_000_000_000),
        ("E", 1_000_000_000_000_000_000),
        ("", 1),
    ];
    let (number, unit) = SUFFIXES.iter().find_map(|(suffix, unit)| {
        quantity
            .strip_suffix(suffix)
            .filter(|n| n.bytes().last().is_some_and(|b| b.is_ascii_digit()))
            .map(|n| (n, *unit))
    })?;
    // Thousandths of one unit of the number: `m` is a thousandth already.
    let per = if unit == 0 { 1 } else { unit * 1000 };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty()
        || whole.len() > 24
        || fraction.len() > 9
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || number.ends_with('.')
    {
        return None;
    }
    let whole: u128 = whole.parse().ok()?;
    let scale = 10u128.pow(fraction.len() as u32);
    let fraction: u128 = if fraction.is_empty() {
        0
    } else {
        fraction.parse().ok()?
    };
    whole
        .checked_mul(per)?
        .checked_add(fraction.checked_mul(per)? / scale)
}

/// Why `address` is not a registry's as this setting takes one: `http://` or `https://`, a host and an optional port, and
/// no login, path, query or fragment.
pub fn registry_problem(address: &str) -> Option<&'static str> {
    let Some(rest) = address
        .strip_prefix("http://")
        .or_else(|| address.strip_prefix("https://"))
    else {
        return Some("must begin http:// or https://");
    };
    let (host, port) = rest.rsplit_once(':').unwrap_or((rest, ""));
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let port_ok = rest
        .contains(':')
        .then_some(port)
        .is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()));
    (!host_ok || !port_ok).then_some("must be a host and an optional port, and nothing more")
}

fn relations(env: &dyn Env) -> Vec<String> {
    let mut problems = Vec::new();
    if let Ok(address) = REGISTRY.read(env)
        && let Some(why) = registry_problem(&address)
    {
        problems.push(format!("{} {why}", REGISTRY.name()));
    }
    let quantities = [
        &CPU_LIMIT,
        &MEMORY_LIMIT,
        &CPU_REQUEST,
        &MEMORY_REQUEST,
        &WORKSPACE_LIMIT,
    ];
    for var in quantities {
        if let Ok(value) = var.read(env)
            && milli(&value).is_none()
        {
            problems.push(format!(
                "{} must be a Kubernetes quantity, such as 500m, 2 or 4Gi",
                var.name()
            ));
        }
    }
    for (request, limit) in [(&CPU_REQUEST, &CPU_LIMIT), (&MEMORY_REQUEST, &MEMORY_LIMIT)] {
        if let (Ok(r), Ok(l)) = (request.read(env), limit.read(env))
            && let (Some(r), Some(l)) = (milli(&r), milli(&l))
            && r > l
        {
            problems.push(format!(
                "{} must be no more than {}",
                request.name(),
                limit.name()
            ));
        }
    }
    for var in [&KEEP_SUCCEEDED_SECS, &KEEP_FAILED_SECS] {
        if let Ok(secs) = var.read(env)
            && secs < LEAST_KEEP_SECS
        {
            problems.push(format!("{} must be at least {LEAST_KEEP_SECS}", var.name()));
        }
    }
    for var in [
        &CONCURRENT_BUILDS,
        &MAX_REPORTS,
        &REPORT_LINE_BYTES,
        &REPORT_STRING_BYTES,
        &REPORT_DEPTH,
        &REPORT_TOKENS,
        &REPORT_ITEMS,
    ] {
        if var.read(env) == Ok(0) {
            problems.push(format!("{} must be at least 1", var.name()));
        }
    }
    if MAX_REPORT_BYTES.read(env) == Ok(0) {
        problems.push(format!("{} must be at least 1", MAX_REPORT_BYTES.name()));
    }
    if let Ok(tokens) = REPORT_TOKENS.read(env)
        && tokens > MOST_TOKENS
    {
        problems.push(format!(
            "{} must be at most {MOST_TOKENS}",
            REPORT_TOKENS.name()
        ));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use polar_env::Mutability;
    use std::collections::HashMap;

    pub(crate) fn config(pairs: &[(&str, &str)]) -> Config {
        let mut env: HashMap<String, String> = [
            ("POLAR_ORCHESTRATOR_NAMESPACE", "polar-builds"),
            ("POLAR_ORCHESTRATOR_TEMPLATE", "build-runner"),
            (
                "POLAR_ORCHESTRATOR_REGISTRY",
                "http://registry.polar-registry.svc.cluster.local:5000",
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (k, v) in pairs {
            env.insert(k.to_string(), v.to_string());
        }
        Config::builder(&env).register(&SECTION).build()
    }

    #[test]
    fn the_section_is_sound_and_its_defaults_parse() {
        assert_eq!(SECTION.defaults_problems(), Vec::<String>::new());
    }

    #[test]
    fn every_variable_is_a_fact_or_a_setting() {
        let names =
            |vars: &[&dyn Described]| -> Vec<&str> { vars.iter().map(|v| v.desc().name).collect() };
        let mut both = names(DEPLOYMENT);
        both.extend(names(TUNING));
        assert_eq!(both, names(VARIABLES));
        for var in TUNING {
            assert_eq!(
                var.desc().mutability,
                Mutability::Dynamic,
                "{} is a run-time setting",
                var.desc().name
            );
        }
        for var in DEPLOYMENT {
            assert_eq!(
                var.desc().mutability,
                Mutability::Static,
                "{} is the catalog's fact",
                var.desc().name
            );
        }
    }

    #[test]
    fn the_defaults_are_the_crates_own() {
        let config = config(&[]);
        assert!(config.check().is_empty(), "{:?}", config.check());
        let tuning = tuning(&config).unwrap();
        assert_eq!(tuning.concurrent_builds, 1);
        assert_eq!(tuning.resources, PipelineResources::default());
        assert_eq!(tuning.retention, Retention::default());
        assert_eq!(tuning.relay, RelayBounds::default());
        assert_eq!(tuning.reader, Bounds::default());
        assert!(tuning.default_command.is_empty());
        assert_eq!(
            deployment(&config).unwrap(),
            Deployment {
                namespace: "polar-builds".into(),
                template: "build-runner".into(),
                registry: "http://registry.polar-registry.svc.cluster.local:5000".into(),
            }
        );
    }

    #[test]
    fn the_deployment_has_no_default() {
        let config = Config::builder(&HashMap::<String, String>::new())
            .register(&SECTION)
            .build();
        let problems = config.check().join(" | ");
        assert!(
            problems.contains("POLAR_ORCHESTRATOR_NAMESPACE"),
            "{problems}"
        );
        assert!(
            problems.contains("POLAR_ORCHESTRATOR_TEMPLATE"),
            "{problems}"
        );
    }

    #[test]
    fn each_bad_setting_is_named() {
        for (name, value, expected) in [
            (
                "POLAR_ORCHESTRATOR_REGISTRY",
                "registry:5000",
                "must begin http",
            ),
            (
                "POLAR_ORCHESTRATOR_REGISTRY",
                "ftp://registry:5000",
                "must begin http",
            ),
            (
                "POLAR_ORCHESTRATOR_REGISTRY",
                "http://u:p@registry:5000",
                "nothing more",
            ),
            (
                "POLAR_ORCHESTRATOR_REGISTRY",
                "http://registry:5000/v2",
                "nothing more",
            ),
            (
                "POLAR_ORCHESTRATOR_REGISTRY",
                "http://registry:",
                "nothing more",
            ),
            ("POLAR_ORCHESTRATOR_REGISTRY", "http://", "nothing more"),
            (
                "POLAR_ORCHESTRATOR_CPU_LIMIT",
                "two",
                "a Kubernetes quantity",
            ),
            (
                "POLAR_ORCHESTRATOR_MEMORY_LIMIT",
                "-1Gi",
                "a Kubernetes quantity",
            ),
            (
                "POLAR_ORCHESTRATOR_WORKSPACE_LIMIT",
                "1e3",
                "a Kubernetes quantity",
            ),
            (
                "POLAR_ORCHESTRATOR_CPU_REQUEST",
                "3",
                "no more than POLAR_ORCHESTRATOR_CPU_LIMIT",
            ),
            (
                "POLAR_ORCHESTRATOR_MEMORY_REQUEST",
                "5Gi",
                "no more than POLAR_ORCHESTRATOR_MEMORY_LIMIT",
            ),
            (
                "POLAR_ORCHESTRATOR_KEEP_SUCCEEDED_SECS",
                "59",
                "at least 60",
            ),
            ("POLAR_ORCHESTRATOR_KEEP_FAILED_SECS", "0", "at least 60"),
            ("POLAR_ORCHESTRATOR_CONCURRENT_BUILDS", "0", "at least 1"),
            ("POLAR_ORCHESTRATOR_MAX_REPORTS", "0", "at least 1"),
            ("POLAR_ORCHESTRATOR_MAX_REPORT_BYTES", "0", "at least 1"),
            ("POLAR_ORCHESTRATOR_REPORT_LINE_BYTES", "0", "at least 1"),
            ("POLAR_ORCHESTRATOR_REPORT_STRING_BYTES", "0", "at least 1"),
            ("POLAR_ORCHESTRATOR_REPORT_DEPTH", "0", "at least 1"),
            ("POLAR_ORCHESTRATOR_REPORT_TOKENS", "0", "at least 1"),
            (
                "POLAR_ORCHESTRATOR_REPORT_TOKENS",
                "4294967296",
                "at most 4294967295",
            ),
            ("POLAR_ORCHESTRATOR_REPORT_ITEMS", "0", "at least 1"),
        ] {
            let problems = config(&[(name, value)]).check().join(" | ");
            assert!(
                problems.contains(name) && problems.contains(expected),
                "{name}={value}: {problems}"
            );
        }
    }

    #[test]
    fn quantities_read_as_kubernetes_reads_them() {
        for (quantity, expected) in [
            ("1", Some(1000)),
            ("500m", Some(500)),
            ("0.5", Some(500)),
            ("1.5Gi", Some(1536 * 1024 * 1024 * 1000)),
            ("4Gi", Some(4 * (1u128 << 30) * 1000)),
            ("2k", Some(2_000_000)),
            ("1M", Some(1_000_000_000)),
            ("", None),
            ("m", None),
            ("Gi", None),
            (".5", None),
            ("5.", None),
            ("1.2.3", None),
            ("+1", None),
            ("1e3", None),
            ("1 Gi", None),
            ("1gi", None),
            ("1Kim", None),
        ] {
            assert_eq!(milli(quantity), expected, "{quantity:?}");
        }
    }
}
