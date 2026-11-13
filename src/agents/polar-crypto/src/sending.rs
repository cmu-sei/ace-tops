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

//! A credentialed HTTP request, sent by the CryptoActor that holds the credential (docs/plans/registry/trusted-remotes.md,
//! "credentials are used without being seen"). The protocol handler judges the request, builds it without a credential,
//! and hands it over with its own client, which carries how the agent goes out (its proxy, the authorities it trusts); this
//! attaches the credential and sends the request with that client, and gives back the response and the facts the handler
//! reports about how the credential went. Where a request goes, and whether it may, stay the handler's.
//!
//! A container registry exchanges a login for a token at its auth host: that token is a secret too, so the exchange is
//! sent from here and the token kept here, and only the auth host's status and headers go back, with a handle the
//! handler presents the token by.

use crate::CryptoError;
use crate::registry::HttpCredential;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use reqwest::header::{AUTHORIZATION, HeaderValue};

/// How a credential is presented over HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpKind {
    /// `Authorization: Bearer`.
    Bearer,
    /// `Authorization: Basic`, a user name and a password.
    Basic,
}

/// What a request sent with a credential came to: the response, how the credential went, and whether it looks like a
/// base64-encoded copy of a token. Never the credential.
pub struct Sent {
    pub response: reqwest::Response,
    pub kind: HttpKind,
    pub looks_base64: bool,
}

/// Why a request was not sent, or failed in sending. None of these holds a value of the credential.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error(transparent)]
    Refused(#[from] CryptoError),
    #[error(transparent)]
    Transport(reqwest::Error),
    #[error("{0}")]
    Unreadable(&'static str),
}

/// The most a registry's auth host may answer with: a token, and what comes with it.
pub const MAX_TOKEN_REPLY: usize = 1024 * 1024;

/// Whether a secret looks like a base64-encoded copy of a token: it decodes, under some alphabet, to at least 16 printable
/// bytes. Someone encoded it who should not have, and the site will not accept it.
pub fn looks_base64(token: &str) -> bool {
    let token = token.trim();
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .filter_map(|engine| engine.decode(token).ok())
        .any(|decoded| decoded.len() >= 16 && decoded.iter().all(u8::is_ascii_graphic))
}

/// How `credential` is presented.
pub fn kind_of(credential: &HttpCredential) -> HttpKind {
    match credential {
        HttpCredential::Bearer(_) => HttpKind::Bearer,
        HttpCredential::Basic { .. } => HttpKind::Basic,
    }
}

/// Puts `credential` on `request` as its `Authorization`, marked sensitive so nothing logs it, replacing any the request
/// came with. How it went, and whether its secret looks base64-encoded.
fn authorize(
    request: &mut reqwest::Request,
    credential: &HttpCredential,
) -> Result<(HttpKind, bool), CryptoError> {
    let not_text = || CryptoError::Use(crate::registry::UseRefusal::NotText);
    let (mut value, looks) = match credential {
        HttpCredential::Bearer(token) => {
            let token = std::str::from_utf8(token).map_err(|_| not_text())?;
            let value =
                HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| not_text())?;
            (value, looks_base64(token))
        }
        HttpCredential::Basic { username, password } => {
            let password = std::str::from_utf8(password).map_err(|_| not_text())?;
            let encoded = STANDARD.encode(format!("{username}:{password}"));
            let value =
                HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|_| not_text())?;
            (value, looks_base64(password))
        }
    };
    value.set_sensitive(true);
    request.headers_mut().insert(AUTHORIZATION, value);
    Ok((kind_of(credential), looks))
}

/// Puts a kept token on `request` as a bearer token.
fn authorize_token(request: &mut reqwest::Request, token: &[u8]) -> Result<(), CryptoError> {
    let not_text = || CryptoError::Use(crate::registry::UseRefusal::NotText);
    let token = std::str::from_utf8(token).map_err(|_| not_text())?;
    let mut value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| not_text())?;
    value.set_sensitive(true);
    request.headers_mut().insert(AUTHORIZATION, value);
    Ok(())
}

#[derive(serde::Deserialize)]
struct TokenReply {
    token: Option<String>,
    access_token: Option<String>,
}

/// Sends `request` with `credential` on it, by `client`. The binding is the caller's to have checked.
pub async fn send(
    credential: &HttpCredential,
    mut request: reqwest::Request,
    client: reqwest::Client,
) -> Result<Sent, SendError> {
    let (kind, looks_base64) = authorize(&mut request, credential)?;
    let response = client
        .execute(request)
        .await
        .map_err(SendError::Transport)?;
    Ok(Sent {
        response,
        kind,
        looks_base64,
    })
}

/// Sends `request` with a kept token on it as a bearer token, by `client`.
pub async fn send_bearer(
    token: &[u8],
    mut request: reqwest::Request,
    client: reqwest::Client,
) -> Result<reqwest::Response, SendError> {
    authorize_token(&mut request, token)?;
    client.execute(request).await.map_err(SendError::Transport)
}

/// What a registry's auth host answered a login with: the token is there only when it answered 200, and then it is
/// there or this is [`SendError::Unreadable`].
pub struct Answered {
    pub status: reqwest::StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub token: Option<zeroize::Zeroizing<Vec<u8>>>,
    pub kind: HttpKind,
    pub looks_base64: bool,
}

/// Sends a login to a registry's auth host, and reads the token it answers with.
pub async fn log_in(
    credential: &HttpCredential,
    request: reqwest::Request,
    client: reqwest::Client,
) -> Result<Answered, SendError> {
    let Sent {
        mut response,
        kind,
        looks_base64,
    } = send(credential, request, client).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let token = if status == reqwest::StatusCode::OK {
        Some(token_of(&mut response).await?)
    } else {
        None
    };
    Ok(Answered {
        status,
        headers,
        token,
        kind,
        looks_base64,
    })
}

/// The token in a registry auth host's answer, read to [`MAX_TOKEN_REPLY`] bytes. What fails to parse says nothing of what
/// it read: a parser's message can repeat it.
async fn token_of(
    response: &mut reqwest::Response,
) -> Result<zeroize::Zeroizing<Vec<u8>>, SendError> {
    let mut whole = zeroize::Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(SendError::Transport)? {
        if whole.len() + chunk.len() > MAX_TOKEN_REPLY {
            return Err(SendError::Unreadable(
                "the registry's auth host answered with more than a token",
            ));
        }
        whole.extend_from_slice(&chunk);
    }
    let reply: TokenReply = serde_json::from_slice(&whole).map_err(|_| {
        SendError::Unreadable("the registry's auth host did not answer with a token")
    })?;
    let token = reply
        .token
        .or(reply.access_token)
        .ok_or(SendError::Unreadable(
            "the registry's auth host did not answer with a token",
        ))?;
    Ok(zeroize::Zeroizing::new(token.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> reqwest::Request {
        reqwest::Client::new()
            .get("https://site.example.org/x")
            .build()
            .unwrap()
    }

    #[test]
    fn a_bearer_token_and_a_user_and_password_are_put_on_the_request_marked_sensitive() {
        let mut r = request();
        let bearer = HttpCredential::Bearer(zeroize::Zeroizing::new(b"t0ken".to_vec()));
        assert_eq!(
            authorize(&mut r, &bearer).unwrap(),
            (HttpKind::Bearer, false)
        );
        let value = &r.headers()[AUTHORIZATION];
        assert_eq!(value, "Bearer t0ken");
        assert!(value.is_sensitive());

        let mut r = request();
        let basic = HttpCredential::Basic {
            username: "me@example.org".into(),
            password: zeroize::Zeroizing::new(b"pw".to_vec()),
        };
        assert_eq!(authorize(&mut r, &basic).unwrap(), (HttpKind::Basic, false));
        assert_eq!(
            r.headers()[AUTHORIZATION],
            format!("Basic {}", STANDARD.encode("me@example.org:pw"))
        );
        assert!(r.headers()[AUTHORIZATION].is_sensitive());
    }

    #[test]
    fn a_secret_that_cannot_be_a_header_is_refused_and_a_base64_copy_is_said() {
        let mut r = request();
        let not_text = HttpCredential::Bearer(zeroize::Zeroizing::new(vec![0xff, 0xfe]));
        assert!(authorize(&mut r, &not_text).is_err());
        let newline = HttpCredential::Bearer(zeroize::Zeroizing::new(b"a\nb".to_vec()));
        assert!(authorize(&mut r, &newline).is_err());
        assert!(r.headers().get(AUTHORIZATION).is_none());
        let encoded = STANDARD.encode("a-real-token-of-some-length");
        let copy = HttpCredential::Bearer(zeroize::Zeroizing::new(encoded.into_bytes()));
        assert_eq!(authorize(&mut r, &copy).unwrap(), (HttpKind::Bearer, true));
    }

    #[test]
    fn a_kept_token_replaces_whatever_authorization_the_request_had() {
        let mut r = request();
        r.headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_static("Basic stale"));
        authorize_token(&mut r, b"fresh").unwrap();
        assert_eq!(r.headers()[AUTHORIZATION], "Bearer fresh");
        assert!(r.headers()[AUTHORIZATION].is_sensitive());
    }
}
