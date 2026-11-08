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

//! Where what a build's actor says goes: its execution events, its own word, on `polar.provenance.executions`, and the
//! reports it relays, each in a `BuildReport` envelope, on `polar.provenance.events`; the broker stamps the orchestrator's
//! identity on each. A trait, so a build's actor is tested without a broker.

use polar::cassini::TcpClient;

#[ractor::async_trait]
pub trait Publish: Send + Sync {
    /// Publishes `payload`, archived with rkyv, on `topic`, waiting while the client has no room.
    async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), String>;
}

#[ractor::async_trait]
impl Publish for TcpClient {
    async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), String> {
        self.publish_when_ready(cassini_client::PublishRequest {
            topic: topic.to_string(),
            payload,
            trace_ctx: None,
            offline_behavior: cassini_client::OfflineBehavior::default(),
            share_identity: true,
        })
        .await
        .map_err(|e| e.to_string())
    }
}
