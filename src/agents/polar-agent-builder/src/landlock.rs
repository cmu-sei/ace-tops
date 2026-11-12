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

//! The builder's lock, Landlock's half (docs/architecture/runtime-attestation.md, "C3b, the builder's Landlock lock"): once
//! an agent is running, it opens no file but those its build declares, so that code which gets into it cannot read what is
//! not its own (another mount, the node's files, `/proc/self/mem`).
//!
//! What it may open comes from two places, both in its scaffold, so applying the catalog signs them off: each variable
//! declared as a path, with the access its code says ([`polar_env::Access`]), at the value the document gives it; and the
//! [`Grant`]s, the builder's own (name resolution, the Kubernetes client's token for an agent with a Kubernetes
//! operation) and the agent's ([`crate::agent::PolarAgent::FILESYSTEM`]): a path no variable names, or a variable the
//! agent uses more widely than its declaration says, as the cert issuer writes the certificate every other agent reads.
//!
//! A file grants the directory it is in, not the file alone: a file updated by writing a new one and renaming it over the
//! old is a new file, which a grant on the old one would refuse. No grant covers a whole system directory ([`SYSTEM`]): a
//! file directly in one is granted alone, and a directory that is one is not granted. Execution, devices, and making
//! sockets, pipes and device files are granted nowhere; abstract Unix sockets are scoped to the agent. Signals are not:
//! an agent's workers are forked before the lock, outside its domain, and the agent must still be able to end one. Ports
//! are not handled: Canal's policy says where traffic goes (C4).
//!
//! It is installed by [`crate::run`] after the workers are forked and before the seccomp filter and the runtime, while the
//! process is one thread, so it needs none of Landlock's newer flags. A kernel without Landlock, or whose ABI lacks a
//! right, leaves the agent running with what it gives, saying exactly what that is ("run, report, policy may require").

use polar_env::Access;
use std::collections::BTreeMap;

/// Where a [`Grant`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    /// A path no variable names.
    Path(&'static str),
    /// Wherever the variable of this name says, which its declaration grants less of than the agent needs.
    Variable(&'static str),
}

/// What an agent opens beyond what its path variables' declarations grant: the builder's own, and
/// [`PolarAgent::FILESYSTEM`](crate::agent::PolarAgent::FILESYSTEM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    pub at: At,
    pub access: Access,
    /// Why the agent opens it, in a few words.
    pub why: &'static str,
}

impl Grant {
    /// A path no variable names.
    pub const fn path(path: &'static str, access: Access, why: &'static str) -> Self {
        Self {
            at: At::Path(path),
            access,
            why,
        }
    }

    /// The path a variable names, used as `access` says.
    pub const fn variable(name: &'static str, access: Access, why: &'static str) -> Self {
        Self {
            at: At::Variable(name),
            access,
            why,
        }
    }
}

/// What every agent reads to resolve a name (musl reads both on each lookup).
pub const NAME_RESOLUTION: &[Grant] = &[
    Grant::path("/etc/resolv.conf", Access::ReadFile, "name resolution"),
    Grant::path("/etc/hosts", Access::ReadFile, "name resolution"),
];

/// What the Kubernetes client reads, and reads again as its token is renewed, in an agent with a Kubernetes operation
/// (`protocol::kubernetes`, `Config::incluster`).
pub const KUBERNETES_CLIENT: Grant = Grant::path(
    "/var/run/secrets/kubernetes.io/serviceaccount",
    Access::ReadDir,
    "the Kubernetes client's token and CA",
);

/// The directories no grant covers whole.
pub const SYSTEM: &[&str] = &[
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/mnt", "/nix", "/opt", "/proc",
    "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var", "/var/lib", "/var/run",
];

// The rights, as `linux/landlock.h` (7.3) numbers them, and the ABI each came in.
const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SYM: u64 = 1 << 12;
/// ABI 2.
const REFER: u64 = 1 << 13;
/// ABI 3.
const TRUNCATE: u64 = 1 << 14;
/// ABI 5.
const IOCTL_DEV: u64 = 1 << 15;
/// ABI 9.
const RESOLVE_UNIX: u64 = 1 << 16;

/// The rights that apply to a file that is not a directory: anything else on a rule for one is refused by the kernel.
const FILE_RIGHTS: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV | RESOLVE_UNIX;

/// What a read grant gives.
pub(crate) const READ: u64 = READ_FILE | READ_DIR;
/// What a write grant gives: reading, and making, writing, moving and removing files, directories and symbolic links.
pub(crate) const WRITE: u64 = READ
    | WRITE_FILE
    | TRUNCATE
    | REMOVE_DIR
    | REMOVE_FILE
    | MAKE_DIR
    | MAKE_REG
    | MAKE_SYM
    | REFER;
/// What a socket's grant gives: connecting to the sockets in it.
pub(crate) const CONNECT: u64 = RESOLVE_UNIX;

/// The rights a kernel of Landlock ABI `abi` handles: every one this code knows that the kernel does.
pub(crate) fn handled(abi: u32) -> u64 {
    let mut rights = (1 << 13) - 1;
    for (since, right) in [(2, REFER), (3, TRUNCATE), (5, IOCTL_DEV), (9, RESOLVE_UNIX)] {
        if abi >= since {
            rights |= right;
        }
    }
    rights
}

/// The rights this code would have a kernel handle, which one of an older ABI cannot, by name.
pub(crate) fn lacking(abi: u32) -> Vec<&'static str> {
    let mut lacking: Vec<&'static str> = [
        (2, "moving files between directories"),
        (3, "truncating"),
        (5, "device ioctls"),
        (6, "abstract Unix sockets"),
        (9, "connecting to Unix sockets"),
    ]
    .into_iter()
    .filter(|(since, _)| abi < *since)
    .map(|(_, what)| what)
    .collect();
    lacking.sort_unstable();
    lacking
}

/// What the lock allows: each path with its rights, and each declared path it does not grant, with why.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub rules: BTreeMap<String, u64>,
    pub not_granted: BTreeMap<String, String>,
}

/// `path` without a trailing slash, `/` itself kept.
fn trimmed(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

fn parent(path: &str) -> &str {
    match trimmed(path).rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((parent, _)) => parent,
    }
}

fn is_system(dir: &str) -> bool {
    SYSTEM.contains(&trimmed(dir))
}

/// Where a path used as `access` is granted, and with what; or why it is not.
pub(crate) fn place(path: &str, access: Access) -> Result<(String, u64), String> {
    let path = trimmed(path);
    if !path.starts_with('/') {
        return Err("it is not an absolute path".into());
    }
    if path.split('/').any(|part| part == "..") {
        return Err("it climbs with '..'".into());
    }
    if is_system(path) {
        return Err(format!("{path} is a system directory"));
    }
    let beside = |dir_rights: u64, alone: u64| {
        let dir = parent(path);
        if is_system(dir) {
            (path.to_string(), alone)
        } else {
            (dir.to_string(), dir_rights)
        }
    };
    Ok(match access {
        Access::ReadFile => beside(READ, READ_FILE),
        Access::WriteFile => beside(WRITE, READ_FILE | WRITE_FILE | TRUNCATE),
        Access::Socket => beside(CONNECT, RESOLVE_UNIX),
        Access::ReadDir => (path.to_string(), READ),
        Access::WriteDir => (path.to_string(), WRITE),
    })
}

/// The plan for `declared` (each path variable's name, access and value, if it has one, and each grant at a variable,
/// resolved to its value by the caller) and the `grants` at a path: deterministic, whatever their order, and each path's
/// rights the union of what it is granted. A grant at a variable is not read here: only its caller knows the value.
pub fn plan<'a>(
    declared: impl IntoIterator<Item = (&'a str, Access, Option<&'a str>)>,
    grants: &[Grant],
) -> Plan {
    let mut plan = Plan::default();
    let asked = declared
        .into_iter()
        .filter_map(|(name, access, value)| value.map(|value| (name, access, value)))
        .chain(grants.iter().filter_map(|g| match g.at {
            At::Path(path) => Some((g.why, g.access, path)),
            At::Variable(_) => None,
        }));
    for (name, access, value) in asked {
        match place(value, access) {
            Ok((path, rights)) => *plan.rules.entry(path).or_default() |= rights,
            Err(why) => {
                plan.not_granted
                    .entry(format!("{name}={value}"))
                    .or_insert(why);
            }
        }
    }
    plan
}

/// What the lock came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Landlocked {
    /// Restricted to the plan, under this ABI, which cannot restrict what `lacking` names; each path in `missing` did not
    /// exist, so is not granted (what is not there cannot be read, and the rest of the lock stands).
    Abi {
        abi: u32,
        lacking: Vec<&'static str>,
        missing: Vec<String>,
    },
    /// Not restricted, and why: the agent runs without it.
    Not(String),
}

/// `struct landlock_ruleset_attr` as far as this code fills it (the kernel takes a shorter one from an older program,
/// and one with fields it does not know only when they are zero).
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `struct landlock_path_beneath_attr`, packed as the kernel's is.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const CREATE_RULESET_VERSION: u32 = 1 << 0;
const RULE_PATH_BENEATH: libc::c_int = 1;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;

/// The kernel's Landlock ABI, or why there is none.
pub fn abi() -> Result<u32, String> {
    // SAFETY: with a null attribute, a size of 0 and the version flag, the call only answers a number.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        return Err(format!(
            "the kernel has no Landlock: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(abi as u32)
}

/// Restricts this process to `plan`: every right the kernel handles is refused but where a rule grants it.
pub fn install(plan: &Plan) -> Landlocked {
    let abi = match abi() {
        Ok(abi) => abi,
        Err(why) => return Landlocked::Not(why),
    };
    let handled = handled(abi);
    let attr = RulesetAttr {
        handled_access_fs: handled,
        handled_access_net: 0,
        scoped: if abi >= 6 {
            SCOPE_ABSTRACT_UNIX_SOCKET
        } else {
            0
        },
    };
    // SAFETY: the attribute is a live value of the size given; the kernel copies it.
    let ruleset = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if ruleset < 0 {
        return Landlocked::Not(format!(
            "the kernel did not make a ruleset: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the call returned a new descriptor, which this owns from here.
    let ruleset =
        unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(ruleset as i32) };
    let mut missing = Vec::new();
    for (path, rights) in &plan.rules {
        match add_rule(&ruleset, path, rights & handled) {
            Ok(Added::Yes) => {}
            Ok(Added::Missing) => missing.push(path.clone()),
            Err(why) => return Landlocked::Not(why),
        }
    }
    // SAFETY: prctl with these arguments only sets a flag of this process; Landlock requires it of an unprivileged one.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Landlocked::Not(format!(
            "no new privileges could not be set: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the descriptor is the ruleset made above.
    let restricted = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            std::os::fd::AsRawFd::as_raw_fd(&ruleset),
            0u32,
        )
    };
    if restricted != 0 {
        return Landlocked::Not(format!(
            "the kernel did not restrict the process: {}",
            std::io::Error::last_os_error()
        ));
    }
    Landlocked::Abi {
        abi,
        lacking: lacking(abi),
        missing,
    }
}

enum Added {
    Yes,
    Missing,
}

fn add_rule(ruleset: &std::os::fd::OwnedFd, path: &str, rights: u64) -> Result<Added, String> {
    use std::os::fd::AsRawFd;
    let file = match std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Added::Missing),
        Err(e) => {
            return Err(format!(
                "{path}, which the lock grants, cannot be opened: {e}"
            ));
        }
    };
    let is_dir = file
        .metadata()
        .map_err(|e| format!("{path}, which the lock grants, cannot be read: {e}"))?
        .is_dir();
    let allowed = if is_dir { rights } else { rights & FILE_RIGHTS };
    if allowed == 0 {
        return Ok(Added::Yes);
    }
    let beneath = PathBeneathAttr {
        allowed_access: allowed,
        parent_fd: file.as_raw_fd(),
    };
    // SAFETY: the attribute is a live value naming a descriptor this holds open; the kernel copies it.
    let added = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &beneath as *const PathBeneathAttr,
            0u32,
        )
    };
    if added != 0 {
        return Err(format!(
            "the kernel did not take the rule for {path}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Added::Yes)
}

use std::os::unix::fs::OpenOptionsExt;

/// The plan's paths by what they allow, most first: each path once, under the most it allows.
fn by_allowance(plan: &Plan) -> Vec<(&'static str, Vec<&str>)> {
    let mut write = Vec::new();
    let mut read = Vec::new();
    let mut connect = Vec::new();
    for (path, rights) in &plan.rules {
        if rights & WRITE_FILE != 0 {
            write.push(path.as_str());
        } else if rights & READ_FILE != 0 {
            read.push(path.as_str());
        } else if rights & RESOLVE_UNIX != 0 {
            connect.push(path.as_str());
        }
    }
    [("write", write), ("read", read), ("connect", connect)]
        .into_iter()
        .filter(|(_, paths)| !paths.is_empty())
        .collect()
}

/// What the agent says of Landlock as it starts, on standard error (the runtime and its logging do not exist yet).
pub fn said(plan: &Plan, landlocked: &Landlocked) -> String {
    let mut said = match landlocked {
        Landlocked::Abi {
            abi,
            lacking,
            missing,
        } => {
            let allowed: Vec<String> = by_allowance(plan)
                .into_iter()
                .map(|(what, paths)| format!("{what} {}", paths.join(", ")))
                .collect();
            let mut said = format!(
                "locked: Landlock ABI {abi} allows no file but: {}",
                if allowed.is_empty() {
                    "none".to_string()
                } else {
                    allowed.join("; ")
                }
            );
            if !missing.is_empty() {
                said.push_str(&format!(
                    "; not there, so not granted: {}",
                    missing.join(", ")
                ));
            }
            if !lacking.is_empty() {
                said.push_str(&format!(
                    "; WARNING: this kernel's Landlock cannot restrict {}",
                    lacking.join(", ")
                ));
            }
            said
        }
        Landlocked::Not(why) => {
            format!("WARNING: not locked by Landlock, and running without it: {why}")
        }
    };
    if !plan.not_granted.is_empty() {
        let refused: Vec<String> = plan
            .not_granted
            .iter()
            .map(|(what, why)| format!("{what} ({why})"))
            .collect();
        said.push_str(&format!("; not granted: {}", refused.join(", ")));
    }
    said
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn a_path() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(SYSTEM.to_vec()).prop_map(str::to_string),
            (
                prop::sample::select(SYSTEM.to_vec()),
                "[a-c]{1,2}",
                prop::option::of("[a-c.]{1,3}")
            )
                .prop_map(|(at, a, b)| {
                    let at = at.trim_end_matches('/');
                    match b {
                        Some(b) => format!("{at}/{a}/{b}"),
                        None => format!("{at}/{a}"),
                    }
                }),
            "[a-c/]{0,6}",
        ]
    }

    fn an_access() -> impl Strategy<Value = Access> {
        prop::sample::select(Access::ALL.to_vec())
    }

    fn declared() -> impl Strategy<Value = Vec<(String, Access, Option<String>)>> {
        prop::collection::vec(("[A-D]", an_access(), prop::option::of(a_path())), 0..8)
    }

    fn plan_of(declared: &[(String, Access, Option<String>)]) -> Plan {
        plan(
            declared
                .iter()
                .map(|(name, access, value)| (name.as_str(), *access, value.as_deref())),
            &[],
        )
    }

    /// What each kind of path may be granted at most, wherever it is placed.
    fn at_most(access: Access) -> u64 {
        match access {
            Access::ReadFile | Access::ReadDir => READ,
            Access::WriteFile | Access::WriteDir => WRITE,
            Access::Socket => CONNECT,
        }
    }

    proptest! {
        /// The plan is the same whatever order the variables come in.
        #[test]
        fn the_plan_does_not_depend_on_order(declared in declared(), seed in any::<u64>()) {
            let mut shuffled = declared.clone();
            let n = shuffled.len();
            if n > 1 {
                for i in 0..n {
                    shuffled.swap(i, (seed as usize).wrapping_add(i * 7) % n);
                }
            }
            prop_assert_eq!(plan_of(&declared), plan_of(&shuffled));
        }

        /// Each path is granted exactly what its place gives it, and the plan is the union of its paths' grants: nothing
        /// more, nothing lost.
        #[test]
        fn the_plan_is_the_union_of_each_paths_place(declared in declared()) {
            let plan = plan_of(&declared);
            let mut expected: BTreeMap<String, u64> = BTreeMap::new();
            let mut refused = 0;
            for (_, access, value) in &declared {
                let Some(value) = value else { continue };
                match place(value, *access) {
                    Ok((path, rights)) => *expected.entry(path).or_default() |= rights,
                    Err(_) => refused += 1,
                }
            }
            prop_assert_eq!(&plan.rules, &expected);
            prop_assert!(plan.not_granted.len() <= refused);
            prop_assert_eq!(plan.not_granted.is_empty(), refused == 0);
        }

        /// No grant executes, makes a socket, pipe or device, or reaches a device's ioctls; none covers a system directory
        /// whole; and each kind of path is granted no more than its kind allows.
        #[test]
        fn no_grant_is_wider_than_its_kind(path in a_path(), access in an_access()) {
            if let Ok((at, rights)) = place(&path, access) {
                prop_assert_eq!(rights & (EXECUTE | IOCTL_DEV), 0);
                prop_assert_eq!(rights & !at_most(access), 0);
                prop_assert!(!is_system(&at), "{} granted whole", at);
                prop_assert!(at == trimmed(&path) || at == parent(&path));
                if at != trimmed(&path) {
                    prop_assert!(!is_system(parent(&path)));
                } else if matches!(access, Access::ReadFile | Access::WriteFile | Access::Socket) {
                    // A file granted alone, beside a system directory: file rights only.
                    prop_assert_eq!(rights & !FILE_RIGHTS, 0);
                }
            } else {
                prop_assert!(!trimmed(&path).starts_with('/') || path.contains("..") || is_system(&path));
            }
        }

        /// A kernel of a later ABI handles at least what an earlier one does, and says it lacks less.
        #[test]
        fn a_later_abi_handles_more(abi in 1u32..16) {
            prop_assert_eq!(handled(abi) & !handled(abi + 1), 0);
            prop_assert!(lacking(abi + 1).len() <= lacking(abi).len());
            prop_assert_eq!(lacking(abi).is_empty(), abi >= 9);
            prop_assert_eq!(handled(abi) & (WRITE | READ | CONNECT) & !handled(abi), 0);
        }
    }

    #[test]
    fn name_resolution_is_granted_its_two_files_alone() {
        let plan = plan(std::iter::empty(), NAME_RESOLUTION);
        assert_eq!(
            plan.rules,
            BTreeMap::from([
                ("/etc/hosts".to_string(), READ_FILE),
                ("/etc/resolv.conf".to_string(), READ_FILE),
            ])
        );
    }

    #[test]
    fn what_it_says_names_each_path_by_what_it_allows() {
        let plan = plan(
            [
                ("CERT", Access::ReadFile, Some("/etc/tls/certs/cert.pem")),
                ("DATA", Access::WriteDir, Some("/var/lib/a")),
                ("SOCKET", Access::Socket, Some("/run/custody/custody.sock")),
                ("ROOT", Access::ReadDir, Some("/etc")),
            ],
            &[],
        );
        let said = said(
            &plan,
            &Landlocked::Abi {
                abi: 11,
                lacking: vec![],
                missing: vec!["/var/lib/a".into()],
            },
        );
        assert_eq!(
            said,
            "locked: Landlock ABI 11 allows no file but: write /var/lib/a; read /etc/tls/certs; connect /run/custody; \
             not there, so not granted: /var/lib/a; not granted: ROOT=/etc (/etc is a system directory)"
        );
        let old = super::said(
            &Plan::default(),
            &Landlocked::Abi {
                abi: 5,
                lacking: lacking(5),
                missing: vec![],
            },
        );
        assert!(
            old.contains("cannot restrict abstract Unix sockets, connecting to Unix sockets"),
            "{old}"
        );
        assert!(
            super::said(&plan, &Landlocked::Not("no".into()))
                .starts_with("WARNING: not locked by Landlock")
        );
    }

    // -- the kernel's own: each case in a child process of its own, locked there ----------------------------------------

    const CASE: &str = "POLAR_LANDLOCK_TEST_CASE";
    const ROOT: &str = "POLAR_LANDLOCK_TEST_ROOT";

    /// Runs `case` in a child process, this test binary again alone, under a lock granting what the case's directory
    /// layout under `root` says (see [`a_landlocked_child`]). Its standard input and output are the test's to use.
    fn a_child(case: &str, root: &std::path::Path) -> std::process::Child {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "landlock::tests::a_landlocked_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CASE, case)
            .env(ROOT, root)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// The layout every case is locked over: `read/` granted as the directory of a file read, `write/` as a directory
    /// read and written, `socket/` as a socket's directory, and `outside/` granted nothing.
    fn layout() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for dir in ["read", "write", "socket", "outside"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
        }
        std::fs::write(root.path().join("read/ca.pem"), "first").unwrap();
        std::fs::write(root.path().join("outside/secret"), "no").unwrap();
        root
    }

    fn denied<T: std::fmt::Debug>(result: std::io::Result<T>, what: &str) {
        match result {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            other => panic!("{what}: expected a refusal, got {other:?}"),
        }
    }

    /// In a child (POLAR_LANDLOCK_TEST_CASE set): locks itself over the layout, then does the case. Run alone, it does
    /// nothing.
    #[test]
    fn a_landlocked_child() {
        use std::io::{BufRead, Write};
        let (Some(case), Some(root)) = (
            polar_env::Env::var(&polar_env::ProcessEnv, CASE),
            polar_env::Env::var(&polar_env::ProcessEnv, ROOT),
        ) else {
            return;
        };
        let at = |p: &str| format!("{root}/{p}");
        let (ca, data, socket) = (at("read/ca.pem"), at("write"), at("socket/s.sock"));
        let gone = at("gone");
        let plan = plan(
            [
                ("CA", Access::ReadFile, Some(ca.as_str())),
                ("DATA", Access::WriteDir, Some(data.as_str())),
                ("SOCKET", Access::Socket, Some(socket.as_str())),
                ("GONE", Access::ReadDir, Some(gone.as_str())),
            ],
            NAME_RESOLUTION,
        );
        let landlocked = install(&plan);
        let Landlocked::Abi { abi, missing, .. } = landlocked else {
            panic!("not locked: {landlocked:?}");
        };
        assert_eq!(missing, vec![gone.clone()]);
        match case.as_str() {
            // A granted file reads, and so does the file renamed over it after the lock, as an update delivers it.
            "read" => {
                assert_eq!(std::fs::read_to_string(&ca).unwrap(), "first");
                println!("swap");
                std::io::stdout().flush().unwrap();
                let mut line = String::new();
                std::io::stdin().lock().read_line(&mut line).unwrap();
                assert_eq!(std::fs::read_to_string(&ca).unwrap(), "second");
                denied(std::fs::write(&ca, "mine"), "writing a file read");
            }
            "refused" => {
                denied(
                    std::fs::read_to_string(at("outside/secret")),
                    "a file outside",
                );
                denied(std::fs::read_to_string("/etc/passwd"), "/etc/passwd");
                denied(
                    std::fs::File::open("/proc/self/mem"),
                    "this process's own memory",
                );
                denied(std::fs::read_dir("/"), "listing /");
            }
            "write" => {
                let file = format!("{data}/f");
                std::fs::write(format!("{file}.new"), "kept").unwrap();
                std::fs::rename(format!("{file}.new"), &file).unwrap();
                std::fs::create_dir(format!("{data}/sub")).unwrap();
                std::fs::rename(&file, format!("{data}/sub/f")).unwrap();
                assert_eq!(
                    std::fs::read_to_string(format!("{data}/sub/f")).unwrap(),
                    "kept"
                );
                std::fs::remove_file(format!("{data}/sub/f")).unwrap();
                std::fs::remove_dir(format!("{data}/sub")).unwrap();
                denied(std::fs::write(at("outside/f"), "no"), "writing outside");
                denied(
                    std::fs::create_dir(at("outside/d")),
                    "making a directory outside",
                );
                denied(
                    std::fs::remove_file(at("outside/secret")),
                    "removing a file outside",
                );
            }
            "socket" => {
                std::os::unix::net::UnixStream::connect(&socket).unwrap();
                if abi >= 9 {
                    denied(
                        std::os::unix::net::UnixStream::connect(at("outside/s.sock")),
                        "a socket outside",
                    );
                }
            }
            "resolve" => {
                use std::net::ToSocketAddrs;
                assert!(
                    ("localhost", 80)
                        .to_socket_addrs()
                        .unwrap()
                        .next()
                        .is_some()
                );
            }
            other => panic!("no case {other}"),
        }
        std::process::exit(0);
    }

    fn the_kernel_has_landlock() -> bool {
        match abi() {
            Ok(_) => true,
            Err(why) => {
                eprintln!("skipping: {why}");
                false
            }
        }
    }

    fn succeeds(mut child: std::process::Child, case: &str) {
        drop(child.stdin.take());
        let status = child.wait().unwrap();
        assert!(status.success(), "{case}: {status:?}");
    }

    #[test]
    fn under_the_lock_a_granted_file_reads_after_it_is_replaced() {
        if !the_kernel_has_landlock() {
            return;
        }
        use std::io::{BufRead, Write};
        let root = layout();
        let mut child = a_child("read", root.path());
        // The test harness says its own lines first, and starts the line the child's cue ends.
        let mut reader = std::io::BufReader::new(child.stdout.as_mut().unwrap());
        loop {
            let mut said = String::new();
            assert_ne!(
                reader.read_line(&mut said).unwrap(),
                0,
                "the child ended before its cue"
            );
            if said.trim_end().ends_with("swap") {
                break;
            }
        }
        let ca = root.path().join("read/ca.pem");
        std::fs::write(root.path().join("read/ca.pem.new"), "second").unwrap();
        std::fs::rename(root.path().join("read/ca.pem.new"), &ca).unwrap();
        writeln!(child.stdin.as_mut().unwrap(), "go").unwrap();
        succeeds(child, "read");
    }

    #[test]
    fn under_the_lock_what_is_not_granted_is_refused() {
        if !the_kernel_has_landlock() {
            return;
        }
        let root = layout();
        succeeds(a_child("refused", root.path()), "refused");
    }

    #[test]
    fn under_the_lock_a_written_directory_takes_its_work_and_nothing_outside_does() {
        if !the_kernel_has_landlock() {
            return;
        }
        let root = layout();
        succeeds(a_child("write", root.path()), "write");
    }

    #[test]
    fn under_the_lock_a_socket_connects_in_its_directory_only() {
        if !the_kernel_has_landlock() {
            return;
        }
        let root = layout();
        // Made outside the child's domain, as the custody sidecar makes its socket.
        let _granted =
            std::os::unix::net::UnixListener::bind(root.path().join("socket/s.sock")).unwrap();
        let _outside =
            std::os::unix::net::UnixListener::bind(root.path().join("outside/s.sock")).unwrap();
        succeeds(a_child("socket", root.path()), "socket");
    }

    #[test]
    fn under_the_lock_a_name_resolves() {
        if !the_kernel_has_landlock() {
            return;
        }
        let root = layout();
        succeeds(a_child("resolve", root.path()), "resolve");
    }
}
