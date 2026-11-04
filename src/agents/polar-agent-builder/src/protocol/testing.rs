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

//! A protocol handler for the tests of an agent: the real one, with the real client and the real judgment, given a test's
//! CA, variables and credentials. It holds only what the test gave it, so it is no way to a real credential.

use super::http::Http;
use super::{
    CredentialSource, CredentialsApplied, Holds, Instances, LiveConfiguration, OperationDecl,
    ProtocolActor, ProtocolArgs, ProtocolHandle, ProtocolMessage, RequestRecord,
};
use crate::runtime::RuntimeValue;
use async_trait::async_trait;
use polar_crypto::CryptoError;
use polar_crypto::registry::{GitCredential, HttpCredential, SecretBinding};
use ractor::{Actor, ActorRef, OutputPort};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A handler a test made, and what it recorded.
pub struct Site {
    pub handle: ProtocolHandle,
    pub records: Arc<Mutex<Vec<RequestRecord>>>,
    variables: Arc<Variables>,
}

impl Site {
    /// A signed update changes a variable.
    pub fn set(&self, name: &str, value: String) {
        self.variables
            .0
            .lock()
            .unwrap()
            .insert(name.to_string(), value);
    }
}

struct Variables(Mutex<HashMap<String, String>>);

#[async_trait]
impl LiveConfiguration for Variables {
    async fn value(&self, name: &str) -> Option<String> {
        self.0.lock().unwrap().get(name).cloned()
    }
    async fn section(&self, _: &str) -> Option<RuntimeValue> {
        None
    }
}

struct NoHealth;

impl Holds for NoHealth {
    fn hold_credentials(&self, _: String) {}
    fn release_credentials(&self) {}
}

/// Answers for one secret by the real rule (`polar_crypto::registry`).
struct OneSecret {
    name: String,
    secret: Vec<u8>,
    binding: SecretBinding,
}

#[async_trait]
impl CredentialSource for OneSecret {
    async fn http(&self, name: String, host: String) -> Result<HttpCredential, CryptoError> {
        if name != self.name {
            return Err(CryptoError::SecretNotRegistered(name));
        }
        polar_crypto::registry::http_credential(&self.binding, &self.secret, &host)
            .map_err(CryptoError::Use)
    }
    async fn git(&self, name: String, _: String) -> Result<GitCredential, CryptoError> {
        Err(CryptoError::SecretNotRegistered(name))
    }
    async fn bound_to(&self, host: String) -> Result<Option<String>, CryptoError> {
        Ok(polar_crypto::registry::bound_to(
            [(self.name.as_str(), self.binding.host_pattern.as_str())],
            &host,
        )
        .map(str::to_string))
    }
}

/// A handler over HTTP that trusts `ca_pem` as well, with `operations` declared and `variables` in force, its credentials
/// answered by `credentials`.
pub async fn http_handle(
    ca_pem: &str,
    operations: &'static [OperationDecl],
    variables: Vec<(&str, String)>,
    credentials: Option<Arc<dyn CredentialSource>>,
) -> Site {
    let certificate = reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("the test's CA");
    let client = Http::builder(super::http::CONNECT_TIMEOUT, super::http::REQUEST_TIMEOUT)
        .add_root_certificate(certificate)
        .no_proxy()
        .build()
        .expect("the test's client");
    let records: Arc<Mutex<Vec<RequestRecord>>> = Arc::default();
    let recorded = records.clone();
    let applied: Arc<OutputPort<CredentialsApplied>> = Arc::new(OutputPort::default());
    let in_force = Arc::new(Mutex::new(None));
    let variables = Arc::new(Variables(Mutex::new(
        variables
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect(),
    )));
    let (actor, _): (ActorRef<ProtocolMessage>, _) = Actor::spawn(
        None,
        ProtocolActor,
        ProtocolArgs {
            agent: "a-test".to_string(),
            declared: operations,
            instances: Instances {
                http: Some(Arc::new(Http::with_client(client))),
                #[cfg(test)]
                test: None,
            },
            credentials,
            crypto: None,
            configuration: variables.clone(),
            health: Arc::new(NoHealth),
            record: Arc::new(move |record| recorded.lock().unwrap().push(record.clone())),
            applied: applied.clone(),
            in_force: in_force.clone(),
        },
    )
    .await
    .expect("the test's handler");
    Site {
        handle: ProtocolHandle {
            actor,
            applied,
            in_force,
        },
        records,
        variables,
    }
}

/// [`http_handle`] with one secret, answered by the real binding rule.
pub async fn http_handle_for(
    ca_pem: &str,
    operations: &'static [OperationDecl],
    variables: Vec<(&str, String)>,
    secret: Option<(&str, &str, SecretBinding)>,
) -> Site {
    let credentials = secret.map(|(name, secret, binding)| {
        Arc::new(OneSecret {
            name: name.to_string(),
            secret: secret.as_bytes().to_vec(),
            binding,
        }) as Arc<dyn CredentialSource>
    });
    http_handle(ca_pem, operations, variables, credentials).await
}
