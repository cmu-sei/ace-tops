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

//! What polar-git says it did, over Cassini (docs/architecture/polar-git.md): every fetch, every repository made, every
//! push with each ref it moved and how, and every refusal with what was asked, each with who did it as their certificate
//! says. A source repository is as observable as any agent; nothing secret is in an event, only names and ids.

use cassini_client::TcpClientMessage;
use ractor::ActorRef;
use rkyv::{Archive, Deserialize, Serialize};
use tracing::{info, warn};

/// Where polar-git says what it did.
pub const GIT_EVENTS_TOPIC: &str = "polar-git-events";

/// One thing polar-git did, for whom (their identity, and the name people read them by), when (Unix milliseconds), to
/// which repository.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct GitEvent {
    pub who: String,
    pub name: String,
    pub repo: String,
    pub at_ms: u64,
    pub what: GitDone,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum GitDone {
    /// A fetch or clone was served.
    Read,
    /// The repository was made, `who` its owner.
    Created,
    /// A push was taken: each ref it moved.
    Pushed { moved: Vec<RefMoved> },
    /// Something was refused: what was asked (the action's name, or what was wrong with the request), and why.
    Refused { asked: String, why: String },
}

/// One ref a push moved: from and to which commit (the null id for none), and what policy was asked of it.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct RefMoved {
    pub refname: String,
    pub old: String,
    pub new: String,
    pub action: String,
}

impl GitEvent {
    pub fn now(who: &crate::edge::Who, repo: &str, what: GitDone) -> Self {
        Self {
            who: who.identity.clone(),
            name: who.name.clone(),
            repo: repo.to_string(),
            at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            what,
        }
    }
}

pub fn encode(event: &GitEvent) -> Vec<u8> {
    rkyv::to_bytes::<rkyv::rancor::Error>(event)
        .expect("an event of owned data always serializes")
        .into_vec()
}

pub fn decode(payload: &[u8]) -> Result<GitEvent, String> {
    let mut aligned = rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(payload);
    rkyv::from_bytes::<GitEvent, rkyv::rancor::Error>(&aligned)
        .map_err(|e| format!("not a polar-git event: {e}"))
}

/// Where events go.
pub trait Reporter: Send + Sync {
    fn report(&self, event: GitEvent);
}

/// Said on Cassini, and in the log.
pub struct CassiniReporter(pub ActorRef<TcpClientMessage>);

impl Reporter for CassiniReporter {
    fn report(&self, event: GitEvent) {
        info!(name = %event.name, who = %event.who, repo = %event.repo, what = ?event.what, "polar-git");
        if let Err(e) = self.0.send_message(TcpClientMessage::publish(
            GIT_EVENTS_TOPIC.to_string(),
            encode(&event),
            None,
        )) {
            warn!(error = %e, "an event could not be said on Cassini");
        }
    }
}

/// Kept, for a test to read.
#[derive(Default)]
pub struct Recorder(pub std::sync::Mutex<Vec<GitEvent>>);

impl Reporter for Recorder {
    fn report(&self, event: GitEvent) {
        self.0.lock().expect("recorder lock").push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_event_survives_the_wire_and_garbage_is_refused() {
        for what in [
            GitDone::Read,
            GitDone::Created,
            GitDone::Pushed {
                moved: vec![RefMoved {
                    refname: "refs/heads/main".into(),
                    old: "0".repeat(40),
                    new: "a".repeat(40),
                    action: "git-push".into(),
                }],
            },
            GitDone::Refused {
                asked: "git-force-push".into(),
                why: "alice may not git-force-push tools".into(),
            },
        ] {
            let event = GitEvent::now(&crate::edge::Who::of("alice", &[]), "tools", what);
            assert_eq!(decode(&encode(&event)).unwrap(), event);
        }
        assert!(decode(b"not an event").is_err());
    }
}
