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

//! The builder's lock, seccomp's half (docs/architecture/runtime-attestation.md, slice C, C3a): what no agent does, refused
//! for the life of its process, so that code which gets into an agent cannot do it either.
//!
//! No agent runs a program (slice C decided it, and C2 took git out of the two that did), traces or reads another
//! process, makes an anonymous file to run code from, maps or marks memory executable once it is running, loads BPF, or
//! loads a kernel module. Each of those, and a call made under another architecture's numbering (x86-64's 32-bit entry, or
//! its x32 numbers, which the same architecture carries), kills the process with `SIGSYS`, which the attestation agent
//! reports as a crash (slice B). Everything else is allowed by this filter and held to the runtime's own (`RuntimeDefault`,
//! C1): filters stack, and each call must pass all of them.
//!
//! It is installed by [`crate::run`] when the agent is started (not for `--help`, `--scaffold` and the rest), after its
//! workers are forked (each locks itself further) and before the runtime starts, while the process is one thread; with
//! `TSYNC` all the same. [`crate::agent::run_with`] does not install it: tests run agents in their own process, which must
//! go on running programs. A kernel that cannot take it leaves the agent running without it, saying so (runtime-attestation.md,
//! "When a node cannot give a protection": run, report, policy may require); the node sensor reads `Seccomp` and
//! `NoNewPrivs` from `/proc/<pid>/status` itself (C4).

/// The architecture a system call's number is of, as the kernel names it to a filter (`AUDIT_ARCH_*`): a call made under
/// another (x86-64's 32-bit entry, which numbers calls differently) is refused, not read by the wrong table.
#[cfg(target_arch = "x86_64")]
pub(crate) const ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
pub(crate) const ARCH: u32 = 0xc000_00b7;

/// x86-64's x32 calls carry this bit in their number, under the same architecture as its own: refused whole.
#[cfg(target_arch = "x86_64")]
const X32_BIT: Option<u32> = Some(0x4000_0000);
#[cfg(not(target_arch = "x86_64"))]
const X32_BIT: Option<u32> = None;

/// Where `struct seccomp_data` keeps the call's number, its architecture, and the low word of its third argument (on a
/// little-endian machine, which both targets are).
const NR: u32 = 0;
const ARCH_AT: u32 = 4;
const ARG2_LOW: u32 = 16 + 2 * 8;

/// The calls refused whatever their arguments.
pub(crate) const REFUSED: &[(&str, libc::c_long)] = &[
    ("execve", libc::SYS_execve),
    ("execveat", libc::SYS_execveat),
    ("ptrace", libc::SYS_ptrace),
    ("process_vm_readv", libc::SYS_process_vm_readv),
    ("process_vm_writev", libc::SYS_process_vm_writev),
    ("memfd_create", libc::SYS_memfd_create),
    ("bpf", libc::SYS_bpf),
    ("init_module", libc::SYS_init_module),
    ("finit_module", libc::SYS_finit_module),
    ("delete_module", libc::SYS_delete_module),
];

/// The calls refused when their third argument, the protection asked for, includes `PROT_EXEC`: new executable memory.
pub(crate) const NO_EXEC: &[(&str, libc::c_long)] = &[
    ("mmap", libc::SYS_mmap),
    ("mprotect", libc::SYS_mprotect),
    ("pkey_mprotect", libc::SYS_pkey_mprotect),
];

pub(crate) const fn statement(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

pub(crate) const fn jump_if(k: u32, ahead: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt: ahead,
        jf: 0,
        k,
    }
}

fn jump(op: u32, k: u32, ahead: usize) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | op | libc::BPF_K) as u16,
        jt: u8::try_from(ahead).expect("the filter is short enough for every jump"),
        jf: 0,
        k,
    }
}

/// The filter: another architecture or an x32 number is killed; then each refused call; then each call that may not ask
/// for executable memory, by its third argument; anything else is allowed.
pub(crate) fn filter() -> Vec<libc::sock_filter> {
    let load = |at| statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, at);
    let ret = |action| statement(libc::BPF_RET | libc::BPF_K, action);
    // The layout, with the kill at the end and the argument check before it.
    let checks = usize::from(X32_BIT.is_some()) + REFUSED.len() + NO_EXEC.len();
    let after_checks = 4 + checks; // the allow that ends the checks
    let protection = after_checks + 1;
    let kill = protection + 3;
    let mut program = vec![
        load(ARCH_AT),
        jump_if(ARCH, 1),
        ret(libc::SECCOMP_RET_KILL_PROCESS),
        load(NR),
    ];
    let ahead = |from: usize, to: usize| to - (from + 1);
    if let Some(bit) = X32_BIT {
        let at = program.len();
        program.push(jump(libc::BPF_JGE, bit, ahead(at, kill)));
    }
    for (_, call) in REFUSED {
        let at = program.len();
        program.push(jump(libc::BPF_JEQ, *call as u32, ahead(at, kill)));
    }
    for (_, call) in NO_EXEC {
        let at = program.len();
        program.push(jump(libc::BPF_JEQ, *call as u32, ahead(at, protection)));
    }
    program.push(ret(libc::SECCOMP_RET_ALLOW));
    program.push(load(ARG2_LOW));
    let at = program.len();
    program.push(jump(
        libc::BPF_JSET,
        libc::PROT_EXEC as u32,
        ahead(at, kill),
    ));
    program.push(ret(libc::SECCOMP_RET_ALLOW));
    program.push(ret(libc::SECCOMP_RET_KILL_PROCESS));
    debug_assert_eq!(program.len(), kill + 1);
    program
}

/// What the lock came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Locked {
    /// The filter is installed, on every thread.
    Seccomp,
    /// The kernel would not take it, and why: the agent runs without it.
    Not(String),
}

/// Installs the lock on this process: no new privileges, then the filter, on every thread.
pub fn install() -> Locked {
    let mut program = filter();
    let fprog = libc::sock_fprog {
        len: program.len() as u16,
        filter: program.as_mut_ptr(),
    };
    // SAFETY: prctl with these arguments only sets a flag of this process.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Locked::Not(format!(
            "no new privileges could not be set: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the program points at the filter, which outlives the call; the kernel copies it.
    let installed = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &fprog as *const libc::sock_fprog,
        )
    };
    if installed != 0 {
        return Locked::Not(format!(
            "the kernel did not take the seccomp filter: {}",
            std::io::Error::last_os_error()
        ));
    }
    Locked::Seccomp
}

/// What the agent says of the lock as it starts, on standard error (the runtime and its logging do not exist yet).
pub fn said(locked: &Locked) -> String {
    match locked {
        Locked::Seccomp => {
            let names: Vec<&str> = REFUSED
                .iter()
                .chain(NO_EXEC)
                .map(|(name, _)| *name)
                .collect();
            format!(
                "locked: seccomp refuses {} (the last three only for executable memory), and a call of another \
                 architecture, by killing the process",
                names.join(", ")
            )
        }
        Locked::Not(why) => {
            format!("WARNING: not locked, and running without it (the node cannot give it): {why}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::os::unix::process::ExitStatusExt;

    /// What a filter answers for one call, as the kernel runs it: only the instructions the filter uses.
    fn run(program: &[libc::sock_filter], arch: u32, nr: u32, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&nr.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (i, arg) in args.iter().enumerate() {
            data[16 + 8 * i..24 + 8 * i].copy_from_slice(&arg.to_le_bytes());
        }
        let mut acc: u32 = 0;
        let mut pc = 0usize;
        loop {
            let i = program[pc];
            let code = u32::from(i.code);
            let class = code & 0x07;
            pc += 1;
            match class {
                c if c == libc::BPF_LD => {
                    assert_eq!(
                        code,
                        libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                        "only absolute word loads"
                    );
                    let at = i.k as usize;
                    acc = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
                }
                c if c == libc::BPF_JMP => {
                    let taken = match code & 0xf0 {
                        op if op == libc::BPF_JEQ => acc == i.k,
                        op if op == libc::BPF_JGE => acc >= i.k,
                        op if op == libc::BPF_JSET => acc & i.k != 0,
                        other => panic!("a jump the filter does not use: {other:#x}"),
                    };
                    pc += usize::from(if taken { i.jt } else { i.jf });
                }
                c if c == libc::BPF_RET => return i.k,
                other => panic!("an instruction the filter does not use: {other:#x}"),
            }
        }
    }

    /// The rule the filter is to follow.
    fn refused_by_rule(arch: u32, nr: u32, prot: u64) -> bool {
        arch != ARCH
            || X32_BIT.is_some_and(|bit| nr >= bit)
            || REFUSED.iter().any(|(_, call)| *call as u32 == nr)
            || (NO_EXEC.iter().any(|(_, call)| *call as u32 == nr)
                && prot & libc::PROT_EXEC as u64 != 0)
    }

    fn a_call() -> impl Strategy<Value = u32> {
        let named: Vec<u32> = REFUSED
            .iter()
            .chain(NO_EXEC)
            .map(|(_, call)| *call as u32)
            .chain([
                libc::SYS_read as u32,
                libc::SYS_openat as u32,
                libc::SYS_clone as u32,
            ])
            .collect();
        prop_oneof![prop::sample::select(named), 0u32..512, any::<u32>()]
    }

    proptest! {
        /// For every call, of any architecture and any arguments, the filter kills exactly what its rule refuses.
        #[test]
        fn the_filter_kills_exactly_what_its_rule_refuses(
            arch in prop_oneof![Just(ARCH), any::<u32>()],
            nr in a_call(),
            prot in prop_oneof![Just(0u64), Just(libc::PROT_EXEC as u64), Just((libc::PROT_READ | libc::PROT_WRITE) as u64), any::<u64>()],
            rest in any::<[u64; 5]>(),
        ) {
            let args = [rest[0], rest[1], prot, rest[2], rest[3], rest[4]];
            let action = run(&filter(), arch, nr, args);
            let expected = if refused_by_rule(arch, nr, prot) { libc::SECCOMP_RET_KILL_PROCESS } else { libc::SECCOMP_RET_ALLOW };
            prop_assert_eq!(action, expected);
        }
    }

    #[test]
    fn what_it_says_names_every_call_it_refuses() {
        let locked = said(&Locked::Seccomp);
        for (name, _) in REFUSED.iter().chain(NO_EXEC) {
            assert!(locked.contains(name), "{name} in {locked}");
        }
        assert!(said(&Locked::Not("no".into())).starts_with("WARNING: not locked"));
    }

    // -- the kernel's own: each case in a child process of its own, locked there ----------------------------------------

    const CASE: &str = "POLAR_LOCK_TEST_CASE";

    /// Runs `case` in a child process: this test binary again, alone, which installs the lock and does it.
    fn in_a_child(case: &str) -> std::process::ExitStatus {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "lock::tests::a_locked_child",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CASE, case)
            .status()
            .unwrap()
    }

    /// In a child (POLAR_LOCK_TEST_CASE set): locks itself, then does the case. Run alone, it does nothing.
    #[test]
    fn a_locked_child() {
        let Some(case) = polar_env::Env::var(&polar_env::ProcessEnv, CASE) else {
            return;
        };
        assert_eq!(install(), Locked::Seccomp);
        let page = 4096;
        // SAFETY: each call below is made only to see whether the lock lets it through; none touches memory it does not own.
        unsafe {
            match case.as_str() {
                // In this process: `std::process::Command` would exec in a child it forks, which the lock kills, and
                // report a failed spawn here.
                "execve" => {
                    let program = c"/bin/sh";
                    let argv = [program.as_ptr(), std::ptr::null()];
                    let envp = [std::ptr::null()];
                    libc::execve(program.as_ptr(), argv.as_ptr(), envp.as_ptr());
                }
                "mmap-exec" => {
                    libc::mmap(
                        std::ptr::null_mut(),
                        page,
                        libc::PROT_READ | libc::PROT_EXEC,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    );
                }
                "mprotect-exec" => {
                    let p = libc::mmap(
                        std::ptr::null_mut(),
                        page,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    );
                    libc::mprotect(p, page, libc::PROT_READ | libc::PROT_EXEC);
                }
                "memfd" => {
                    libc::syscall(libc::SYS_memfd_create, c"x".as_ptr(), 0);
                }
                "ptrace" => {
                    libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
                }
                "bpf" => {
                    libc::syscall(libc::SYS_bpf, 0, 0, 0);
                }
                #[cfg(target_arch = "x86_64")]
                "x32" => {
                    libc::syscall(0x4000_0000 | libc::SYS_getpid);
                }
                "ordinary" => ordinary_work(),
                other => panic!("no case {other}"),
            }
        }
        // A case that is refused never gets here.
        std::process::exit(0);
    }

    /// What an agent does all day, under the lock: threads, a runtime, memory read and written, files, a connection, a name
    /// resolved, its own status read.
    fn ordinary_work() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        assert!(
            status
                .lines()
                .any(|l| l.starts_with("NoNewPrivs:") && l.ends_with('1')),
            "{status}"
        );
        assert!(
            status
                .lines()
                .any(|l| l.starts_with("Seccomp:") && l.ends_with('2')),
            "{status}"
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let at = listener.local_addr().unwrap();
            let accepted = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
            tokio::net::TcpStream::connect(at).await.unwrap();
            accepted.await.unwrap().unwrap();
            tokio::net::lookup_host("localhost:80")
                .await
                .unwrap()
                .next()
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            tokio::fs::write(dir.path().join("f"), vec![7u8; 1 << 20])
                .await
                .unwrap();
            assert_eq!(
                tokio::fs::read(dir.path().join("f")).await.unwrap().len(),
                1 << 20
            );
        });
        let big: Vec<u64> = (0..1_000_000).collect();
        assert_eq!(
            std::thread::spawn(move || big.iter().sum::<u64>())
                .join()
                .unwrap(),
            499_999_500_000
        );
    }

    #[test]
    fn under_the_lock_what_no_agent_does_kills_the_process_by_sigsys() {
        let mut cases = vec![
            "execve",
            "mmap-exec",
            "mprotect-exec",
            "memfd",
            "ptrace",
            "bpf",
        ];
        if cfg!(target_arch = "x86_64") {
            cases.push("x32");
        }
        for case in cases {
            let status = in_a_child(case);
            assert_eq!(status.signal(), Some(libc::SIGSYS), "{case}: {status:?}");
        }
    }

    #[test]
    fn under_the_lock_what_an_agent_does_all_day_goes_on() {
        let status = in_a_child("ordinary");
        assert!(status.success(), "{status:?}");
    }
}
