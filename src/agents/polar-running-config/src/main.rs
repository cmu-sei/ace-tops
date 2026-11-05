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

//! `polar-running-config <agent>`: asks a running agent for its configuration in force, over Cassini, with the asker's
//! own certificate, and prints the answer as JSON. `polar-sign template <agent> --settings --running -` writes a file to
//! edit and sign from it. Design: docs/architecture/dynamic-settings.md. It is its own tool because `polar-sign` has no
//! async runtime and needs none.

use anyhow::{Context, Result, anyhow};
use cassini_client::{
    ClientEventForwarder, ClientEventForwarderArgs, DeliveryMode, TCPClientConfig, TcpClientActor,
    TcpClientArgs, TcpClientMessage,
};
use cassini_types::ClientEvent;
use clap::Parser;
use polar_running_config::{Asking, Step};
use polar_scheduler_common::running::{
    ANSWERS_TOPIC, MAX_QUESTION_VALIDITY_SECS, QUESTIONS_TOPIC, RunningConfiguration,
    question_payload,
};
use ractor::{Actor, ActorProcessingErr, ActorRef};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(
    name = "polar-running-config",
    about = "Ask a running agent what configuration is in force"
)]
struct Cli {
    /// The agent's name, as it calls itself.
    agent: String,
    /// Whose certificate and key to ask with: <dir>/<user>.crt and .key. It needs c:update-configuration, or a policy
    /// that permits it.
    #[arg(long)]
    user: String,
    /// Where they are, with ca.pem; ~/.config/polar-admin by default.
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Where the broker is, as host:port.
    #[arg(long)]
    broker: String,
    /// The name on the broker's certificate.
    #[arg(long)]
    server_name: String,
    /// How long to wait for the answer, in seconds. A refused question gets none.
    #[arg(long, default_value_t = 15)]
    wait: u64,
}

struct Asker;

struct AskerArgs {
    asking: Asking,
    question: Vec<u8>,
    config: TCPClientConfig,
    done: oneshot::Sender<Result<RunningConfiguration, String>>,
}

struct AskerState {
    asking: Asking,
    question: Vec<u8>,
    client: ActorRef<TcpClientMessage>,
    done: Option<oneshot::Sender<Result<RunningConfiguration, String>>>,
}

#[ractor::async_trait]
impl Actor for Asker {
    type Msg = ClientEvent;
    type State = AskerState;
    type Arguments = AskerArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: AskerArgs,
    ) -> Result<Self::State, ActorProcessingErr> {
        let (forwarder, _) = Actor::spawn_linked(
            None,
            ClientEventForwarder::new(),
            ClientEventForwarderArgs {
                target: myself.clone(),
                mapper: Box::new(Some),
            },
            myself.clone().into(),
        )
        .await?;
        let events: Arc<ractor::OutputPort<ClientEvent>> = Arc::new(ractor::OutputPort::default());
        events.subscribe(forwarder, Some);
        let (client, _) = Actor::spawn_linked(
            None,
            TcpClientActor,
            TcpClientArgs {
                config: args.config,
                registration_id: None,
                delivery: DeliveryMode::Broadcast(events),
                answers: None,
            },
            myself.clone().into(),
        )
        .await?;
        Ok(AskerState {
            asking: args.asking,
            question: args.question,
            client,
            done: Some(args.done),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        event: ClientEvent,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match state.asking.on(event) {
            Step::Nothing => {}
            Step::Subscribe => state.client.send_message(TcpClientMessage::Subscribe {
                topic: ANSWERS_TOPIC.to_string(),
                trace_ctx: None,
            })?,
            Step::Ask => state.client.send_message(TcpClientMessage::publish(
                QUESTIONS_TOPIC.to_string(),
                state.question.clone(),
                None,
            ))?,
            Step::Answered(answer) => {
                if let Some(done) = state.done.take() {
                    let _ = done.send(Ok(*answer));
                }
                myself.stop(None);
            }
            Step::Failed(why) => {
                if let Some(done) = state.done.take() {
                    let _ = done.send(Err(why));
                }
                myself.stop(None);
            }
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    polar_version::exit_if_asked("polar-running-config");
    let cli = Cli::parse();
    let dir = match cli.dir {
        Some(dir) => dir,
        None => {
            PathBuf::from(std::env::var("HOME").context("HOME is not set: say where with --dir")?)
                .join(".config/polar-admin")
        }
    };
    let identity = polar_sign::load_identity(&dir, &cli.user).map_err(anyhow::Error::msg)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the clock is before 1970")?
        .as_secs();
    let id = uuid::Uuid::new_v4().to_string();
    let question = polar_signing::sign_in(
        polar_signing::Domain::RUNNING_CONFIGURATION_QUESTION,
        question_payload(
            &cli.agent,
            &id,
            now,
            now + MAX_QUESTION_VALIDITY_SECS.min(cli.wait.max(60)),
        ),
        &identity.chain,
        &identity.key_pem,
    )
    .map_err(|e| anyhow!("cannot sign the question: {e}"))?
    .to_value()
    .to_string()
    .into_bytes();

    let path = |name: String| dir.join(name).to_string_lossy().to_string();
    let env: HashMap<String, String> = HashMap::from([
        (
            "TLS_CLIENT_CERT".to_string(),
            path(format!("{}.crt", cli.user)),
        ),
        (
            "TLS_CLIENT_KEY".to_string(),
            path(format!("{}.key", cli.user)),
        ),
        ("TLS_CA_CERT".to_string(), path("ca.pem".to_string())),
        ("BROKER_ADDR".to_string(), cli.broker),
        ("CASSINI_SERVER_NAME".to_string(), cli.server_name),
    ]);
    let config = TCPClientConfig::from_env(&env).map_err(anyhow::Error::msg)?;

    let (done, answered) = oneshot::channel();
    let (_asker, _handle) = Actor::spawn(
        None,
        Asker,
        AskerArgs {
            asking: Asking {
                agent: cli.agent.clone(),
                id,
            },
            question,
            config,
            done,
        },
    )
    .await
    .map_err(|e| anyhow!("cannot start: {e}"))?;

    let answer = match tokio::time::timeout(Duration::from_secs(cli.wait), answered).await {
        Ok(Ok(Ok(answer))) => answer,
        Ok(Ok(Err(why))) => return Err(anyhow!(why)),
        Ok(Err(_)) => {
            return Err(anyhow!(
                "the connection to the broker ended before an answer"
            ));
        }
        Err(_) => {
            return Err(anyhow!(
                "no answer from {} in {} s. It answers nothing it refuses, so look for the refusal in its log; or it is not running, or the broker cannot be reached",
                cli.agent,
                cli.wait
            ));
        }
    };
    println!("{}", serde_json::to_string_pretty(&answer)?);
    Ok(())
}

// Every Polar binary allocates with Scudo (docs/architecture/broker-baseline.md, "Decided").
#[global_allocator]
static GLOBAL: polar_scudo::Scudo = polar_scudo::Scudo;
