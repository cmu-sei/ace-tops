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

use polar_agent_builder::worker::{
    Work, Worker, WorkerActor, WorkerArgs, WorkerError, WorkerHandle, fork,
};
use ractor::{Actor, ActorProcessingErr, ActorRef, SupervisionEvent};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
            // A system call the lock does not allow.
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
            // Never answers: a worker that hangs.
            b"spin" => loop {
                std::hint::spin_loop();
            },
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

/// Puts this process under a seccomp filter that allows every call, as a container's default profile allows most: what a
/// worker is forked under in a pod. Seccomp's strict mode is refused to such a process; filters stack.
fn under_a_filter_allowing_everything() {
    let mut allow = [libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let program = libc::sock_fprog {
        len: 1,
        filter: allow.as_mut_ptr(),
    };
    // SAFETY: prctl on this process; the program points at a filter that outlives the call, and the kernel copies it.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
                0,
                0
            ),
            0,
            "{}",
            std::io::Error::last_os_error()
        );
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
        "a system call the lock does not allow kills the worker",
        &|| {
            let mut w = worker(&canary);
            died_by_signal(w.ask(b"getpid"), libc::SIGSYS, "getpid");
        },
    );

    case("asking the kernel for memory kills the worker", &|| {
        let mut w = worker(&canary);
        died_by_signal(w.ask(b"allocate"), libc::SIGSYS, "a 64 MiB allocation");
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
        "a worker forked from a process under a seccomp filter already, as the runtime's default profile puts every \
         container, is locked all the same",
        &|| {
            under_a_filter_allowing_everything();
            let mut w = worker(&canary);
            assert_eq!(w.ask(b"abc").unwrap(), b"ABC");
            died_by_signal(w.ask(b"getpid"), libc::SIGSYS, "getpid, under two filters");
        },
    );

    // The running agent's side: workers forked now, while the process is one thread, then asked from a runtime.
    let asked = worker(&canary);
    let killed = worker(&canary);
    let killed_pid = killed.pid();
    let hung = worker(&canary);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let failures = Arc::new(Mutex::new(Vec::new()));
    let (asked, killed, hung) = runtime.block_on(async {
        let (supervisor, _) = Actor::spawn(None, Watch, failures.clone()).await.unwrap();
        let mut handles = Vec::new();
        for (w, timeout) in [
            (asked, Duration::from_secs(5)),
            (killed, Duration::from_secs(5)),
            (hung, Duration::from_millis(300)),
        ] {
            let (actor, _) = Actor::spawn_linked(
                None,
                WorkerActor,
                WorkerArgs {
                    name: "probe",
                    worker: w,
                    timeout,
                },
                supervisor.get_cell(),
            )
            .await
            .unwrap();
            handles.push(WorkerHandle::new(actor));
        }
        (handles.remove(0), handles.remove(0), handles.remove(0))
    });

    case(
        "a worker in the running agent is asked through its handle, and a request past its bound fails nothing",
        &|| {
            runtime.block_on(async {
                assert_eq!(asked.ask(b"abc".to_vec()).await.unwrap(), b"ABC");
                assert_eq!(asked.ask(vec![0; 65]).await, Err(WorkerError::TooLong(65)));
                assert_eq!(asked.ask(b"again".to_vec()).await.unwrap(), b"AGAIN");
            });
            assert!(
                failures.lock().unwrap().is_empty(),
                "{:?}",
                failures.lock().unwrap()
            );
        },
    );

    case(
        "a worker that dies fails its actor, which its supervisor sees",
        &|| {
            runtime.block_on(async {
                assert_eq!(killed.ask(b"x".to_vec()).await.unwrap(), b"X");
                // Killed from outside, as a crash would end it.
                // SAFETY: kill takes a pid and a signal; the pid is this test's own worker.
                unsafe { libc::kill(killed_pid, libc::SIGKILL) };
                assert!(matches!(
                    killed.ask(b"y".to_vec()).await,
                    Err(WorkerError::Died(_))
                ));
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
            let failures = failures.lock().unwrap();
            assert_eq!(failures.len(), 1, "{failures:?}");
            assert!(failures[0].contains("the worker probe"), "{failures:?}");
        },
    );

    case(
        "a worker that does not answer in its time is killed, and fails its actor",
        &|| {
            runtime.block_on(async {
                assert_eq!(
                    hung.ask(b"spin".to_vec()).await,
                    Err(WorkerError::TimedOut(Duration::from_millis(300)))
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
            assert_eq!(
                failures.lock().unwrap().len(),
                2,
                "{:?}",
                failures.lock().unwrap()
            );
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

/// A supervisor that only notes the failures of its children.
struct Watch;

#[ractor::async_trait]
impl Actor for Watch {
    type Msg = ();
    type State = Arc<Mutex<Vec<String>>>;
    type Arguments = Arc<Mutex<Vec<String>>>;

    async fn pre_start(
        &self,
        _: ActorRef<()>,
        seen: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        Ok(seen)
    }

    async fn handle_supervisor_evt(
        &self,
        _: ActorRef<()>,
        event: SupervisionEvent,
        seen: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        if let SupervisionEvent::ActorFailed(_, why) = event {
            seen.lock().unwrap().push(why.to_string());
        }
        Ok(())
    }
}
