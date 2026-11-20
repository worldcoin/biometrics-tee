//! API input validation and error mapping around the shared proof verification client.

use std::sync::Arc;

use telemetry_batteries::reexports::metrics::counter;
use tokio::sync::Semaphore;

use world_id_proof_verification_client::{
    ProofVerificationClient, VerificationError, VerificationRequest,
};

/// Keeps subjects sent to verification bounded, independently of route validation.
const MAX_CREDENTIAL_SUB_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum ProofVerificationError {
    #[error("oversized")]
    Oversized,
    #[error("invalid")]
    Invalid,
    #[error("challenge_id_missing")]
    ChallengeIdMissing,
    #[error("proof_missing")]
    ProofMissing,
    #[error("credential_sub_missing")]
    CredentialSubMissing,
    #[error("verification_failed")]
    VerificationRejected,
    #[error("verification_error")]
    VerificationError,
    #[error("verification_busy")]
    Busy,
}

impl ProofVerificationError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Oversized => "oversized",
            Self::Invalid => "invalid",
            Self::ChallengeIdMissing => "challenge_id_missing",
            Self::ProofMissing => "proof_missing",
            Self::CredentialSubMissing => "credential_sub_missing",
            Self::VerificationRejected => "verification_failed",
            Self::VerificationError => "verification_error",
            Self::Busy => "verification_busy",
        }
    }
}

pub struct Verifier {
    max_proof_body_bytes: u64,
    /// Caps upstream verifications in flight from this pod; excess requests are shed.
    in_flight: Semaphore,
    client: Arc<dyn ProofVerificationClient>,
}

impl Verifier {
    pub fn new(
        max_proof_body_bytes: u64,
        max_in_flight: usize,
        client: Arc<dyn ProofVerificationClient>,
    ) -> Self {
        Self {
            max_proof_body_bytes,
            in_flight: Semaphore::new(max_in_flight),
            client,
        }
    }

    pub async fn verify(
        &self,
        challenge_id: String,
        credential_sub: String,
        proof: String,
    ) -> Result<(), ProofVerificationError> {
        if challenge_id.is_empty() {
            return Err(ProofVerificationError::ChallengeIdMissing);
        }
        if credential_sub.is_empty() {
            return Err(ProofVerificationError::CredentialSubMissing);
        }
        if proof.is_empty() {
            return Err(ProofVerificationError::ProofMissing);
        }
        if credential_sub.len() > MAX_CREDENTIAL_SUB_BYTES {
            return Err(ProofVerificationError::Invalid);
        }
        if self.max_proof_body_bytes > 0 && proof.len() as u64 > self.max_proof_body_bytes {
            return Err(ProofVerificationError::Oversized);
        }
        let request = VerificationRequest {
            challenge_id: challenge_id
                .parse()
                .map_err(|_| ProofVerificationError::Invalid)?,
            credential_sub,
            proof,
        };
        // Shed instead of queueing: waiting requests would hold sockets and the shared quota.
        let Ok(_permit) = self.in_flight.try_acquire() else {
            counter!("proof.verify.rejected_busy").increment(1);
            return Err(ProofVerificationError::Busy);
        };
        match self.client.verify(request).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let failure = match &error {
                    VerificationError::Rejected => {
                        return Err(ProofVerificationError::VerificationRejected);
                    }
                    VerificationError::Timeout(_) => "timeout",
                    VerificationError::Canceled(_) => "canceled",
                    VerificationError::Connection(_) => "connection",
                    VerificationError::Auth(_) | VerificationError::Unauthorized => "auth",
                    VerificationError::UnexpectedStatus { status } if status.is_server_error() => {
                        "upstream_5xx"
                    }
                    VerificationError::UnexpectedStatus { .. } => "upstream_4xx",
                };
                tracing::error!(%error, failure, dependency = "proof-verification", "proof verification failed");
                Err(ProofVerificationError::VerificationError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{
        Json, Router,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use world_id_proof_verification_client::{AuthProvider, Client, Config, VERIFY_PATH};

    use super::*;

    const CHALLENGE: &str = "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31";

    struct TestAuth;

    #[async_trait]
    impl AuthProvider for TestAuth {
        async fn token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
            Ok("test-token".to_owned())
        }
    }

    async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = format!("http://{}", listener.local_addr().unwrap());
        (
            host,
            tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            }),
        )
    }

    fn client(host: String, timeout: Duration) -> Verifier {
        let client = Client::new(
            Config {
                host,
                timeout,
                pool_max_idle_per_host: 1,
            },
            Arc::new(TestAuth),
        )
        .unwrap();
        Verifier::new(1 << 20, 16, Arc::new(client))
    }

    #[tokio::test]
    async fn shared_client_preserves_the_api_error_contract_and_uses_the_new_wire_request() {
        for (status, body, expected) in [
            (StatusCode::OK, "", None),
            (
                StatusCode::UNAUTHORIZED,
                r#"{"msg":"proof_rejected"}"#,
                Some("verification_failed"),
            ),
            (
                StatusCode::UNAUTHORIZED,
                r#"{"msg":"unauthorized"}"#,
                Some("verification_error"),
            ),
            (StatusCode::UNAUTHORIZED, "", Some("verification_error")),
            (StatusCode::BAD_REQUEST, "", Some("verification_error")),
            (
                StatusCode::TOO_MANY_REQUESTS,
                "",
                Some("verification_error"),
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "",
                Some("verification_error"),
            ),
        ] {
            let (host, server) = serve(Router::new().route(VERIFY_PATH, post(
                move |headers: HeaderMap, Json(request): Json<serde_json::Value>| async move {
                    assert_eq!(headers["authorization"], "Bearer test-token");
                    assert_eq!(request, serde_json::json!({
                        "challenge_id": CHALLENGE, "credential_sub": "test-sub", "proof": "YQ==",
                    }));
                    (status, body)
                }
            ))).await;
            let result = client(host, Duration::from_secs(2))
                .verify(
                    CHALLENGE.to_owned(),
                    "test-sub".to_owned(),
                    "YQ==".to_owned(),
                )
                .await;
            assert_eq!(result.err().map(ProofVerificationError::as_str), expected);
            server.abort();
        }
    }

    struct RecordingClient(AtomicUsize);

    #[async_trait]
    impl ProofVerificationClient for RecordingClient {
        async fn verify(&self, _request: VerificationRequest) -> Result<(), VerificationError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn invalid_requests_do_not_reach_the_verification_service() {
        let client = Arc::new(RecordingClient(AtomicUsize::new(0)));
        let verifier = Verifier::new(4, 16, client.clone());
        for (challenge, sub, proof, expected) in [
            ("", "test-sub".to_owned(), "YQ==", "challenge_id_missing"),
            (CHALLENGE, String::new(), "YQ==", "credential_sub_missing"),
            (CHALLENGE, "test-sub".to_owned(), "", "proof_missing"),
            ("invalid-uuid", "test-sub".to_owned(), "YQ==", "invalid"),
            (CHALLENGE, "a".repeat(257), "YQ==", "invalid"),
            (CHALLENGE, "test-sub".to_owned(), "YQ===", "oversized"),
        ] {
            let error = verifier
                .verify(challenge.to_owned(), sub, proof.to_owned())
                .await
                .unwrap_err();
            assert_eq!(error.as_str(), expected);
        }
        assert_eq!(client.0.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn upstream_timeouts_remain_service_failures() {
        let (host, server) = serve(Router::new().route(
            VERIFY_PATH,
            post(|| async {
                std::future::pending::<()>().await;
                StatusCode::OK
            }),
        ))
        .await;
        let error = client(host, Duration::from_millis(50))
            .verify(
                CHALLENGE.to_owned(),
                "test-sub".to_owned(),
                "YQ==".to_owned(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.as_str(), "verification_error");
        server.abort();
    }

    struct BlockingClient(tokio::sync::Notify);

    #[async_trait]
    impl ProofVerificationClient for BlockingClient {
        async fn verify(&self, _request: VerificationRequest) -> Result<(), VerificationError> {
            self.0.notified().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn verifications_beyond_the_limit_are_shed() {
        let client = Arc::new(BlockingClient(tokio::sync::Notify::new()));
        let verifier = Arc::new(Verifier::new(1 << 20, 1, client.clone()));
        let first = tokio::spawn({
            let verifier = Arc::clone(&verifier);
            async move {
                verifier
                    .verify(
                        CHALLENGE.to_owned(),
                        "test-sub".to_owned(),
                        "YQ==".to_owned(),
                    )
                    .await
            }
        });
        while verifier.in_flight.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        let second = verifier
            .verify(
                CHALLENGE.to_owned(),
                "test-sub".to_owned(),
                "YQ==".to_owned(),
            )
            .await;
        assert_eq!(
            second.err().map(ProofVerificationError::as_str),
            Some("verification_busy")
        );
        client.0.notify_one();
        assert!(first.await.unwrap().is_ok());
        assert_eq!(verifier.in_flight.available_permits(), 1);
    }
}
