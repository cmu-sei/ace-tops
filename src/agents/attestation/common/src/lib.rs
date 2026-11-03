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

//! What the attestation agent and those who ask it say to each other, and the judgement it gives
//! (docs/architecture/runtime-attestation.md). The judgement is a pure function of what the agent holds, so that it can
//! be tested over every way a pod can differ from the genuine one, and so that nothing Kubernetes-specific is in it: the
//! platform backend turns what it sees into these facts.

pub mod asker;
pub mod proof;
pub mod protocol;
pub mod record;
pub mod report;
pub mod verdict;

pub use proof::{Doubt, HeldPodFacts, Proved, prove};
pub use protocol::{
    AGENT_NAME, CERT_ISSUER_REPLIES_TOPIC, CREDENTIALS_AGENT_REPLIES_TOPIC, Envelope,
    InstanceQuestion, REQUESTS_TOPIC, decode_question, decode_verdict, encode_question,
    encode_verdict, replies_topic,
};
pub use record::{
    Deployed, DeploymentRecord, Drift, DriftChanges, DriftWatch, RecordedContainer,
    RecordedWorkload, drift,
};
pub use report::{
    CrashSignal, Finding, ObservedPod, REPORTS_TOPIC, Report, Reporting, Termination,
    accepted_report, crash_signal, decode_report, encode_report, findings,
};
pub use verdict::{
    ContainerFacts, NotGenuine, Owner, OwnerKind, PodFacts, Verdict, WorkloadFacts, digest_of,
    judge,
};
