//! Ciphertext relay and browser-compatible, single-connection test admission.
use axum::{
    Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use p256::ecdsa::VerifyingKey;
use rand::RngCore;
use selfie_enrollment_api_types::*;
use selfie_enrollment_enclave_types::{ExtractRequest, ExtractResponse, KeyAttestation};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time::{Instant, timeout, timeout_at},
};

#[async_trait::async_trait]
pub trait Enclave: Send + Sync {
    async fn health(&self) -> Result<(), ErrorCode>;
    async fn assignment(&self) -> Result<KeyAttestation, ErrorCode>;
    async fn extract(&self, request: ExtractRequest) -> Result<ExtractResponse, ErrorCode>;
}
#[derive(Clone)]
pub struct AppState {
    pub enclave: Arc<dyn Enclave>,
    pub admission_key: VerifyingKey,
    pub audience: String,
    pub allowed_origins: Vec<String>,
    pub connections: Arc<Semaphore>,
    max_connections: usize,
    session_finished: Arc<Notify>,
}
impl AppState {
    pub fn new(
        enclave: Arc<dyn Enclave>,
        key: &str,
        audience: String,
        allowed_origins: Vec<String>,
        connections: usize,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !audience.is_empty() && audience.len() <= 256 && (1..=32).contains(&connections),
            "invalid enrollment host limits"
        );
        let admission_key = VerifyingKey::from_sec1_bytes(
            &hex::decode(key).map_err(|_| anyhow::anyhow!("invalid admission public key"))?,
        )
        .map_err(|_| anyhow::anyhow!("invalid admission public key"))?;
        Ok(Self {
            enclave,
            admission_key,
            audience,
            allowed_origins,
            connections: Arc::new(Semaphore::new(connections)),
            max_connections: connections,
            session_finished: Arc::new(Notify::new()),
        })
    }
}
// Hyper releases upgraded connections from its graceful-shutdown accounting.
// Keep their permits until the session task actually exits, then wake the host drain.
struct SessionPermit {
    permit: Option<OwnedSemaphorePermit>,
    finished: Arc<Notify>,
}
impl Drop for SessionPermit {
    fn drop(&mut self) {
        drop(self.permit.take());
        self.finished.notify_one();
    }
}
impl AppState {
    /// Reject new sessions and await all upgraded sockets, bounded by their session deadline.
    pub async fn drain(&self) -> anyhow::Result<()> {
        self.connections.close();
        timeout(Duration::from_secs(91), async {
            loop {
                let finished = self.session_finished.notified();
                if self.connections.available_permits() == self.max_connections {
                    break;
                }
                finished.await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("enrollment sessions did not drain"))
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/ready", get(ready))
        .route("/v1/embeddings", get(upgrade))
        .with_state(state)
}
async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.connections.is_closed() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    match timeout(Duration::from_secs(2), state.enclave.health()).await {
        Ok(Ok(())) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
async fn upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    if let Some(origin) = headers.get("origin")
        && !origin
            .to_str()
            .is_ok_and(|o| state.allowed_origins.iter().any(|allowed| allowed == o))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(permit) = state.connections.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let permit = SessionPermit {
        permit: Some(permit),
        finished: state.session_finished.clone(),
    };
    upgrade
        .max_message_size(MAX_REQUEST_BYTES)
        .max_frame_size(MAX_REQUEST_BYTES)
        .on_upgrade(move |mut socket| async move {
            let _permit = permit;
            let result = timeout(Duration::from_secs(90), serve(&mut socket, &state))
                .await
                .unwrap_or(Err(ErrorCode::Timeout));
            let close_deadline = Instant::now() + Duration::from_secs(1);
            if let Err(code) = result {
                // Codes contain no payloads, tickets or underlying dependency errors.
                tracing::debug!(code=?code,"enrollment session ended");
                if let Ok(body) = serde_json::to_string(&ServerMessage::Error { code }) {
                    let _ =
                        timeout_at(close_deadline, socket.send(Message::Text(body.into()))).await;
                }
            }
            let _ = timeout_at(close_deadline, socket.send(Message::Close(None))).await;
        })
        .into_response()
}
async fn send_control(socket: &mut WebSocket, message: ServerMessage) -> Result<(), ErrorCode> {
    let body = serde_json::to_string(&message).map_err(|_| ErrorCode::Unavailable)?;
    if body.len() > MAX_CONTROL_BYTES {
        return Err(ErrorCode::Unavailable);
    }
    timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(body.into())),
    )
    .await
    .map_err(|_| ErrorCode::Timeout)?
    .map_err(|_| ErrorCode::Unavailable)
}
async fn next(socket: &mut WebSocket, duration: Duration) -> Result<Message, ErrorCode> {
    let deadline = Instant::now() + duration;
    loop {
        match timeout_at(deadline, socket.recv())
            .await
            .map_err(|_| ErrorCode::Timeout)?
        {
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            Some(Ok(message)) => return Ok(message),
            _ => return Err(ErrorCode::InvalidMessage),
        }
    }
}
async fn serve(socket: &mut WebSocket, state: &AppState) -> Result<(), ErrorCode> {
    let mut nonce = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let challenge = AdmissionChallenge {
        audience: state.audience.clone(),
        nonce,
    };
    send_control(socket, ServerMessage::Admission(challenge.clone())).await?;
    let Message::Text(text) = next(socket, Duration::from_secs(15)).await? else {
        return Err(ErrorCode::Unauthorized);
    };
    if text.len() > MAX_TICKET_BYTES {
        return Err(ErrorCode::Unauthorized);
    }
    let ticket: AdmissionTicket =
        serde_json::from_str(&text).map_err(|_| ErrorCode::Unauthorized)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ErrorCode::Unavailable)?
        .as_secs();
    verify_ticket(&state.admission_key, &challenge, &ticket, now)?;
    let assignment = timeout(Duration::from_secs(3), state.enclave.assignment())
        .await
        .map_err(|_| ErrorCode::Timeout)??;
    send_control(
        socket,
        ServerMessage::Assignment(Assignment {
            attestation: STANDARD.encode(assignment.document),
            public_key: STANDARD.encode(assignment.public_key),
        }),
    )
    .await?;
    let Message::Binary(ciphertext) = next(socket, Duration::from_secs(30)).await? else {
        return Err(ErrorCode::InvalidMessage);
    };
    if ciphertext.is_empty() || ciphertext.len() > MAX_REQUEST_BYTES {
        return Err(ErrorCode::InvalidMessage);
    }
    let response = timeout(
        Duration::from_secs(35),
        state.enclave.extract(ExtractRequest {
            ciphertext: ciphertext.to_vec(),
        }),
    )
    .await
    .map_err(|_| ErrorCode::Timeout)??;
    if response.ciphertext.len() > MAX_RESPONSE_BYTES {
        return Err(ErrorCode::Unavailable);
    }
    timeout(
        Duration::from_secs(5),
        socket.send(Message::Binary(response.ciphertext.into())),
    )
    .await
    .map_err(|_| ErrorCode::Timeout)?
    .map_err(|_| ErrorCode::Unavailable)
}

#[cfg(target_os = "linux")]
pub struct NitroEnclave {
    pub cid: u32,
    pub port: u32,
}
#[cfg(target_os = "linux")]
impl NitroEnclave {
    async fn call<R, T>(&self, request: R) -> Result<T, ErrorCode>
    where
        R: pontifex::Request<Response = Result<T, ErrorCode>> + Sync,
    {
        pontifex::client::send(
            pontifex::client::ConnectionDetails::new(self.cid, self.port),
            &request,
        )
        .await
        .map_err(|_| ErrorCode::Unavailable)?
    }
}
#[cfg(target_os = "linux")]
#[async_trait::async_trait]
impl Enclave for NitroEnclave {
    async fn health(&self) -> Result<(), ErrorCode> {
        self.call(selfie_enrollment_enclave_types::HealthRequest)
            .await
    }
    async fn assignment(&self) -> Result<KeyAttestation, ErrorCode> {
        self.call(selfie_enrollment_enclave_types::AssignmentRequest)
            .await
    }
    async fn extract(&self, r: ExtractRequest) -> Result<ExtractResponse, ErrorCode> {
        self.call(r).await
    }
}
