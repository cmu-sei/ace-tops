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

//! The worker (src/worker.rs), in a process of one thread: a binary with a main of its own, since libtest runs tests on
//! threads of its own and a worker is forked only from a process of one. Each case runs in order; the one that starts a
//! thread runs last.

use polar_agent_builder::worker::{Work, Worker, WorkerError, fork};
use std::os::fd::{AsRawFd, OwnedFd};

/// What a test asks a worker to do.
struct Probe {
    /// A descriptor the parent had open, to see whether the worker still has it.
    canary: i32,
}

impl Work for Probe {
    fn max_request(&self) -> usize {
        64
    }
    fn max_answer(&self) -> usize {
        64
    }
    fn answer(&mut self, request: &[u8], answer: &mut [u8]) -> usize {
        match request {
            // A system call strict mode does not allow.
            b"getpid" => {
                // SAFETY: getpid takes nothing.
                let _ = unsafe { libc::getpid() };
                0
            }
            // Memory asked of the kernel, as an allocation that big is.
            b"allocate" => {
                let big = vec![1u8; 64 * 1024 * 1024];
                answer[0] = big[big.len() - 1];
                1
            }
            // Whether the parent's descriptor is open here: a write on it is allowed, and fails on one that is closed.
            b"canary" => {
                // SAFETY: a write of one byte from a buffer one byte long.
                let n = unsafe { libc::write(self.canary, b"x".as_ptr().cast(), 1) };
                let said: &[u8] = if n == 1 { b"open" } else { b"closed" };
                answer[..said.len()].copy_from_slice(said);
                said.len()
            }
            // A worker whose work is not the worker's any more: it writes its own frame on the answer pipe, as the
            // child would, saying it answers more than it may.
            b"lie" => {
                let forged = (u64::MAX).to_le_bytes();
                // SAFETY: a write of eight bytes from a buffer eight long, on the answer pipe.
                let _ = unsafe { libc::write(1, forged.as_ptr().cast(), forged.len()) };
                0
            }
            other => {
                for (i, b) in other.iter().enumerate() {
                    answer[i] = b.to_ascii_uppercase();
                }
                other.len()
            }
        }
    }
}

fn worker(canary: &OwnedFd) -> Worker {
    let canary = canary.as_raw_fd();
    fork(move || Probe { canary }).expect("a worker of a process of one thread")
}

fn died_by_signal(result: Result<Vec<u8>, WorkerError>, signal: i32, what: &str) {
    match result {
        Err(WorkerError::Died(how)) => {
            assert_eq!(how, format!("killed by signal {signal}"), "{what}")
        }
        other => panic!("{what}: {other:?}"),
    }
}

fn main() {
    // A descriptor the parent holds open across the fork, as an agent's would be: a file, without close-on-exec.
    let canary: OwnedFd = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .expect("/dev/null")
        .into();
    // SAFETY: clears close-on-exec on a descriptor this process owns.
    unsafe { libc::fcntl(canary.as_raw_fd(), libc::F_SETFD, 0) };

    let mut cases = 0;
    let mut case = |name: &str, run: &dyn Fn()| {
        run();
        cases += 1;
        println!("  ok    {name}");
    };

    case(
        "a worker answers its requests, one after another, within its bounds",
        &|| {
            let mut w = worker(&canary);
            assert_eq!(w.max_request(), 64);
            assert_eq!(w.ask(b"abc").unwrap(), b"ABC");
            assert_eq!(w.ask(b"").unwrap(), b"");
            assert_eq!(w.ask(b"polar").unwrap(), b"POLAR");
            assert_eq!(
                w.ask(&[0u8; 65]),
                Err(WorkerError::TooLong(65)),
                "a request past its bound is not sent"
            );
            assert_eq!(w.ask(b"still").unwrap(), b"STILL");
        },
    );

    case(
        "a system call strict mode does not allow kills the worker",
        &|| {
            let mut w = worker(&canary);
            died_by_signal(w.ask(b"getpid"), libc::SIGKILL, "getpid");
        },
    );

    case("asking the kernel for memory kills the worker", &|| {
        let mut w = worker(&canary);
        died_by_signal(w.ask(b"allocate"), libc::SIGKILL, "a 64 MiB allocation");
    });

    case(
        "a descriptor the agent had open is closed in the worker",
        &|| {
            let mut w = worker(&canary);
            assert_eq!(w.ask(b"canary").unwrap(), b"closed");
        },
    );

    case(
        "an answer longer than the worker may give is not believed, and the worker is ended",
        &|| {
            let mut w = worker(&canary);
            assert_eq!(w.ask(b"lie"), Err(WorkerError::Lied(u64::MAX as usize)));
        },
    );

    case(
        "a process that has started a thread forks no worker",
        &|| {
            let parked =
                std::thread::spawn(|| std::thread::park_timeout(std::time::Duration::from_secs(5)));
            let refused = fork(|| Probe { canary: -1 });
            assert!(
                matches!(refused, Err(WorkerError::Threaded(n)) if n >= 2),
                "{refused:?}"
            );
            parked.thread().unpark();
            parked.join().unwrap();
        },
    );

    println!("all {cases} passed");
}
