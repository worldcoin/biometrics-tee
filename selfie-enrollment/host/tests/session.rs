use futures_util::{SinkExt, StreamExt};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use selfie_enrollment_api_types::*;
use selfie_enrollment_enclave_types::{ExtractRequest, ExtractResponse, KeyAttestation};
use selfie_enrollment_host::{AppState, Enclave};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Default)]
struct FakeEnclave {
    assignments: AtomicUsize,
    extractions: AtomicUsize,
}
#[async_trait::async_trait]
impl Enclave for FakeEnclave {
    async fn health(&self) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn assignment(&self) -> Result<KeyAttestation, ErrorCode> {
        self.assignments.fetch_add(1, Ordering::SeqCst);
        Ok(KeyAttestation {
            document: vec![1],
            public_key: vec![2],
        })
    }
    async fn extract(&self, _: ExtractRequest) -> Result<ExtractResponse, ErrorCode> {
        self.extractions.fetch_add(1, Ordering::SeqCst);
        Ok(ExtractResponse {
            ciphertext: vec![4],
        })
    }
}
async fn server() -> (
    String,
    AppState,
    Arc<FakeEnclave>,
    SigningKey,
    tokio::task::JoinHandle<()>,
) {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let enclave = Arc::new(FakeEnclave::default());
    let state = AppState::new(
        enclave.clone(),
        &hex::encode(key.verifying_key().to_encoded_point(false).as_bytes()),
        "test".into(),
        vec!["http://localhost:8765".into()],
        1,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/embeddings", listener.local_addr().unwrap());
    let app = selfie_enrollment_host::router(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, state, enclave, key, task)
}
fn sign(key: &SigningKey, challenge: &AdmissionChallenge) -> AdmissionTicket {
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 30;
    let signature: Signature = key.sign(&ticket_message(challenge, expires_at));
    AdmissionTicket {
        expires_at,
        signature: hex::encode(signature.to_bytes()),
    }
}
async fn next(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> ServerMessage {
    let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(message.to_text().unwrap()).unwrap()
}
#[tokio::test]
async fn admission_binds_the_connection_and_precedes_enclave_access() {
    let (url, state, enclave, key, task) = server().await;
    let (mut socket, _) = connect_async(&url).await.unwrap();
    let ServerMessage::Admission(challenge) = next(&mut socket).await else {
        panic!("expected admission")
    };
    assert_eq!(enclave.assignments.load(Ordering::SeqCst), 0);
    assert!(connect_async(&url).await.is_err()); // permit includes the entire unauthenticated session
    let ticket = sign(&key, &challenge);
    socket
        .send(Message::Text(
            serde_json::to_string(&ticket).unwrap().into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Assignment(_)
    ));
    socket
        .send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert!(matches!(
        socket.next().await.unwrap().unwrap(),
        Message::Binary(_)
    ));
    drop(socket);
    tokio::time::timeout(Duration::from_secs(2), async {
        while state.connections.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (mut replay, _) = connect_async(&url).await.unwrap();
    assert!(matches!(
        next(&mut replay).await,
        ServerMessage::Admission(_)
    ));
    replay
        .send(Message::Text(
            serde_json::to_string(&ticket).unwrap().into(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        next(&mut replay).await,
        ServerMessage::Error {
            code: ErrorCode::Unauthorized
        }
    ));
    assert_eq!(enclave.assignments.load(Ordering::SeqCst), 1);
    assert_eq!(enclave.extractions.load(Ordering::SeqCst), 1);
    task.abort();
}
#[tokio::test]
async fn actual_client_sends_no_image_after_untrusted_attestation() {
    use selfie_enrollment_client::{Config, Release};
    let (url, _, enclave, key, task) = server().await;
    let config = Config {
        endpoint: url,
        audience: "test".into(),
        releases: vec![Release {
            pcr0: "1".repeat(96),
            pcr1: "2".repeat(96),
            pcr2: "3".repeat(96),
            worker_sha384: "4".repeat(96),
        }],
    };
    let result = selfie_enrollment_client::native::extract(
        &config,
        vec![1, 2, 3],
        move |challenge| async move { Ok(sign(&key, &challenge)) },
    )
    .await;
    assert!(matches!(
        result,
        Err(selfie_enrollment_client::Error::Attestation)
    ));
    assert_eq!(enclave.assignments.load(Ordering::SeqCst), 1);
    assert_eq!(enclave.extractions.load(Ordering::SeqCst), 0);
    task.abort();
}
#[tokio::test]
async fn unapproved_browser_origin_is_rejected_before_upgrade() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let (url, _, enclave, _, task) = server().await;
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("Origin", "https://untrusted.example".parse().unwrap());
    assert!(connect_async(request).await.is_err());
    assert_eq!(enclave.assignments.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test]
async fn shutdown_waits_for_upgraded_sockets_and_rejects_new_sessions() {
    let (url, state, _, _, task) = server().await;
    let (mut socket, _) = connect_async(&url).await.unwrap();
    assert!(matches!(
        next(&mut socket).await,
        ServerMessage::Admission(_)
    ));
    let draining = state.clone();
    let drain = tokio::spawn(async move { draining.drain().await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while !state.connections.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!drain.is_finished());
    assert!(connect_async(&url).await.is_err());
    socket.close(None).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), drain)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(state.connections.available_permits(), 1);
    task.abort();
}
