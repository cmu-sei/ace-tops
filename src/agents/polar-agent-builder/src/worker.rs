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

//! Workers: a process forked from an agent before its runtime starts, to do one kind of work on bytes the agent must not
//! trust, locked down so that a bug in that work can hurt nothing but the worker (docs/architecture/build-orchestrator.md,
//! "How a report is read", layer 3; O2d2).
//!
//! The agent forks it while it is still one thread: forking a threaded process copies one thread and leaves every lock the
//! others held taken, and only `exec` is safe after that, which a worker does not do. So a worker is forked once, before the
//! runtime is built, and cannot be forked again: when one dies, the agent ends and its pod restarts with a fresh one.
//!
//! In the child, before it reads anything: its two pipes become its standard input and output, and every other descriptor is
//! closed (standard error too: it has nothing to say); no new privileges, not dumpable, and killed if its parent dies;
//! everything its work needs is allocated; and then seccomp's strict mode, in which the process may `read`, `write`, `exit`
//! and return from a signal, and any other system call kills it, asking for memory among them. So its work allocates nothing
//! and calls nothing: it reads a request, answers it into a buffer it was given, and writes the answer.
//!
//! The parent holds a worker to its bounds: a request longer than the worker takes is not sent, and an answer longer than it
//! may give, or none, is not believed. A worker that hangs up has died, and says how.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// The work a worker does, on the worker's side of the fork.
pub trait Work {
    /// The most a request may hold, in bytes.
    fn max_request(&self) -> usize;
    /// The most an answer may hold, in bytes.
    fn max_answer(&self) -> usize;
    /// Answers `request` into `answer`, returning how much of it the answer is. It runs in seccomp's strict mode: it may not
    /// allocate, nor make any system call; whatever it needs it was given when it was made, before the lockdown.
    fn answer(&mut self, request: &[u8], answer: &mut [u8]) -> usize;
}

/// Why a worker could not be made, or did not answer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WorkerError {
    #[error("a worker is forked while the process is one thread, and it has {0}")]
    Threaded(usize),
    #[error("the system refused to make the worker: {0}")]
    System(String),
    #[error("a request of {0} bytes is more than the worker takes")]
    TooLong(usize),
    #[error("the worker answered with more than it may ({0} bytes)")]
    Lied(usize),
    #[error("the worker died: {0}")]
    Died(String),
}

/// A worker, on the agent's side: its process and its two pipes.
#[derive(Debug)]
pub struct Worker {
    pid: libc::pid_t,
    requests: OwnedFd,
    answers: OwnedFd,
    max_request: usize,
    max_answer: usize,
}

/// How many threads the process has, from the kernel's own count.
fn threads() -> Result<usize, WorkerError> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| WorkerError::System(e.to_string()))?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|n| n.trim().parse().ok())
        .ok_or_else(|| {
            WorkerError::System("the kernel did not say how many threads the process has".into())
        })
}

fn pipe() -> Result<(OwnedFd, OwnedFd), WorkerError> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 writes two descriptors into the array it is given, which is two long.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(WorkerError::System(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    // SAFETY: both are new descriptors, owned by nothing else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Forks a worker doing the work `make` makes, which runs in the child, before the lockdown. The process must be one
/// thread.
pub fn fork<W: Work>(make: impl FnOnce() -> W) -> Result<Worker, WorkerError> {
    let count = threads()?;
    if count != 1 {
        return Err(WorkerError::Threaded(count));
    }
    let (request_read, request_write) = pipe()?;
    let (answer_read, answer_write) = pipe()?;
    // SAFETY: the process is one thread (above), so the child has every lock free; it runs only `child`, which never returns.
    match unsafe { libc::fork() } {
        -1 => Err(WorkerError::System(
            std::io::Error::last_os_error().to_string(),
        )),
        0 => child(request_read.as_raw_fd(), answer_write.as_raw_fd(), make),
        pid => {
            drop(request_read);
            drop(answer_write);
            Ok(Worker {
                pid,
                requests: request_write,
                answers: answer_read,
                max_request: 0,
                max_answer: 0,
            }
            .with_bounds()?)
        }
    }
}

/// The child's side: the lockdown, then requests answered until the parent hangs up.
fn child<W: Work>(requests: RawFd, answers: RawFd, make: impl FnOnce() -> W) -> ! {
    // SAFETY: each call is a system call on the process itself, with arguments it defines; none returns memory.
    unsafe {
        if libc::dup2(requests, 0) != 0 || libc::dup2(answers, 1) != 1 {
            die(10);
        }
        if libc::syscall(libc::SYS_close_range, 2u32, u32::MAX, 0u32) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
        {
            die(11);
        }
    }
    let mut work = make();
    let mut request = vec![0u8; work.max_request()].into_boxed_slice();
    let mut answer = vec![0u8; work.max_answer()].into_boxed_slice();
    // The worker's bounds, for the parent to hold it to: the first thing it writes.
    let mut bounds = [0u8; 16];
    bounds[..8].copy_from_slice(&(request.len() as u64).to_le_bytes());
    bounds[8..].copy_from_slice(&(answer.len() as u64).to_le_bytes());
    // SAFETY: strict mode takes no pointer; from here on only read, write, exit and sigreturn are allowed.
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_STRICT, 0, 0, 0) } != 0 {
        die(12);
    }
    if !write_all(1, &bounds) {
        die(13);
    }
    loop {
        let mut len = [0u8; 8];
        if !read_exact(0, &mut len) {
            // The parent hung up: the worker's work is done.
            die(0);
        }
        let len = u64::from_le_bytes(len) as usize;
        if len > request.len() || !read_exact(0, &mut request[..len]) {
            die(14);
        }
        let n = work.answer(&request[..len], &mut answer).min(answer.len());
        if !write_all(1, &(n as u64).to_le_bytes()) || !write_all(1, &answer[..n]) {
            die(15);
        }
    }
}

/// Ends the process with `code`, by the `exit` system call strict mode allows (not `exit_group`, which it does not).
fn die(code: i32) -> ! {
    // SAFETY: exit takes a status and does not return.
    unsafe { libc::syscall(libc::SYS_exit, code) };
    unreachable!()
}

fn read_exact(fd: RawFd, buf: &mut [u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: the pointer and length are of the unread rest of `buf`.
        let n = unsafe { libc::read(fd, buf[done..].as_mut_ptr().cast(), buf.len() - done) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        done += n as usize;
    }
    true
}

fn write_all(fd: RawFd, buf: &[u8]) -> bool {
    let mut done = 0;
    while done < buf.len() {
        // SAFETY: the pointer and length are of the unwritten rest of `buf`.
        let n = unsafe { libc::write(fd, buf[done..].as_ptr().cast(), buf.len() - done) };
        if n <= 0 {
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        done += n as usize;
    }
    true
}

impl Worker {
    /// Reads the bounds the worker says it was made with, the first thing it writes once locked down.
    fn with_bounds(mut self) -> Result<Self, WorkerError> {
        let mut bounds = [0u8; 16];
        if !read_exact(self.answers.as_raw_fd(), &mut bounds) {
            return Err(self.died());
        }
        self.max_request = u64::from_le_bytes(bounds[..8].try_into().unwrap_or_default()) as usize;
        self.max_answer = u64::from_le_bytes(bounds[8..].try_into().unwrap_or_default()) as usize;
        Ok(self)
    }

    /// The worker's process.
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// The most a request may hold.
    pub fn max_request(&self) -> usize {
        self.max_request
    }

    /// Sends `request` and returns the answer, blocking until it comes. An answer longer than the worker may give, or none,
    /// is not believed: the first says it lied, the second that it died, and how.
    pub fn ask(&mut self, request: &[u8]) -> Result<Vec<u8>, WorkerError> {
        if request.len() > self.max_request {
            return Err(WorkerError::TooLong(request.len()));
        }
        let to = self.requests.as_raw_fd();
        if !write_all(to, &(request.len() as u64).to_le_bytes()) || !write_all(to, request) {
            return Err(self.died());
        }
        let from = self.answers.as_raw_fd();
        let mut len = [0u8; 8];
        if !read_exact(from, &mut len) {
            return Err(self.died());
        }
        let len = u64::from_le_bytes(len) as usize;
        if len > self.max_answer {
            self.kill();
            return Err(WorkerError::Lied(len));
        }
        let mut answer = vec![0u8; len];
        if !read_exact(from, &mut answer) {
            return Err(self.died());
        }
        Ok(answer)
    }

    fn kill(&self) {
        // SAFETY: kill takes a pid and a signal.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
    }

    /// How the worker ended, once it has: waited for, so it is not left a zombie.
    fn died(&self) -> WorkerError {
        let mut status = 0;
        // SAFETY: waitpid writes the status into the integer it is given.
        let waited = unsafe { libc::waitpid(self.pid, &mut status, 0) };
        WorkerError::Died(if waited != self.pid {
            "it could not be waited for".into()
        } else if libc::WIFSIGNALED(status) {
            format!("killed by signal {}", libc::WTERMSIG(status))
        } else {
            format!("exited {}", libc::WEXITSTATUS(status))
        })
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.kill();
        let mut status = 0;
        // SAFETY: as in `died`.
        unsafe { libc::waitpid(self.pid, &mut status, 0) };
    }
}
