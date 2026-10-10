use futures_util::{SinkExt, StreamExt};
use selfie_enrollment_api_types::*;
use selfie_enrollment_enclave_types::{ExtractRequest, ExtractResponse, KeyAttestation};
use selfie_enrollment_host::{AppState, Enclave};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
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
    tokio::task::JoinHandle<()>,
) {
    let enclave = Arc::new(FakeEnclave::default());
    let state = AppState::new(enclave.clone(), 1).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/embeddings", listener.local_addr().unwrap());
    let app = selfie_enrollment_host::router(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, state, enclave, task)
}
async fn next(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> serde_json::Value {
    let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serde_json::from_str(message.to_text().unwrap()).unwrap()
}
#[tokio::test]
async fn one_assignment_and_extraction_per_socket_with_bounded_capacity() {
    let (url, state, enclave, task) = server().await;
    let (mut socket, _) = connect_async(&url).await.unwrap();
    assert!(connect_async(&url).await.is_err());
    assert_eq!(enclave.assignments.load(Ordering::SeqCst), 0);
    socket
        .send(Message::Text(r#"{"type":"assignment_request"}"#.into()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut socket).await,
        serde_json::json!({
            "type":"assignment", "attestation":"AQ==", "public_key":"Ag=="
        })
    );
    socket
        .send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert!(matches!(
        socket.next().await.unwrap().unwrap(),
        Message::Binary(_)
    ));
    assert!(matches!(
        socket.next().await.unwrap().unwrap(),
        Message::Close(_)
    ));
    drop(socket);
    tokio::time::timeout(Duration::from_secs(2), async {
        while state.connections.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(enclave.assignments.load(Ordering::SeqCst), 1);
    assert_eq!(enclave.extractions.load(Ordering::SeqCst), 1);
    task.abort();
}
#[tokio::test]
async fn unexpected_first_frame_never_reaches_the_enclave() {
    for frame in [
        Message::Text(r#"{"type":"unknown"}"#.into()),
        Message::Binary(vec![1].into()),
    ] {
        let (url, _, enclave, task) = server().await;
        let (mut socket, _) = connect_async(&url).await.unwrap();
        socket.send(frame).await.unwrap();
        let error: ErrorEnvelope = serde_json::from_value(next(&mut socket).await).unwrap();
        assert_eq!(error.error.code, ErrorCode::InvalidMessage);
        assert!(!error.allow_retry);
        assert_eq!(enclave.assignments.load(Ordering::SeqCst), 0);
        assert_eq!(enclave.extractions.load(Ordering::SeqCst), 0);
        task.abort();
    }
}
#[tokio::test]
async fn actual_client_sends_no_image_after_untrusted_attestation() {
    use selfie_enrollment_client::{Config, EnrollmentClient, Release};
    let (url, _, enclave, task) = server().await;
    let config = Config {
        endpoint: url,
        releases: vec![Release {
            pcr0: "1".repeat(96),
            pcr1: "2".repeat(96),
            pcr2: "3".repeat(96),
            worker_sha384: "4".repeat(96),
        }],
    };
    let result = EnrollmentClient::new(config).unwrap().connect().await;
    assert!(matches!(
        result,
        Err(selfie_enrollment_client::Error::Attestation)
    ));
    assert_eq!(enclave.assignments.load(Ordering::SeqCst), 1);
    assert_eq!(enclave.extractions.load(Ordering::SeqCst), 0);
    task.abort();
}
#[tokio::test]
async fn shutdown_waits_for_upgraded_sockets_and_rejects_new_sessions() {
    let (url, state, _, task) = server().await;
    let (mut socket, _) = connect_async(&url).await.unwrap();
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
