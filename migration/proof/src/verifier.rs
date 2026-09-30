//! Validate an ownership proof and check it with the verification service.
//! The caller awaits the check and surfaces a failure before continuing.

use crate::client::Verdict;
use crate::header::MAX_CREDENTIAL_SUB_BYTES;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    DEFAULT_CHALLENGE_TYPE, VerificationRequest, client::ProofVerificationClient,
    header::ProofVerificationError,
};

#[derive(Clone, Debug)]
pub struct Config {
    pub max_proof_body_bytes: u64,
    pub challenge_type: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_proof_body_bytes: 1 << 20,
            challenge_type: DEFAULT_CHALLENGE_TYPE.to_owned(),
        }
    }
}

pub struct Verifier {
    pub config: Config,
    pub client: Arc<dyn ProofVerificationClient>,
}

impl Verifier {
    pub fn new(config: Config, client: Arc<dyn ProofVerificationClient>) -> Self {
        Self { config, client }
    }

    pub async fn verify(
        self: &Verifier,
        request: VerificationRequest,
    ) -> Result<(), ProofVerificationError> {
        self.validate_proof_fields(&request)?;
        match self.client.verify(request.clone()).await {
            Verdict::Accepted => Ok(()),
            Verdict::Rejected => Err(ProofVerificationError::VerificationRejected),
            Verdict::Error(failure) => {
                tracing::error!(
                    failure = failure.as_str(),
                    request = %request.credential_sub,
                    "proof verification failed"
                );
                Err(ProofVerificationError::VerificationError)
            }
        }
    }

    fn validate_proof_fields(
        self: &Verifier,
        request: &VerificationRequest,
    ) -> Result<(), ProofVerificationError> {
        if request.challenge_id.is_empty() {
            return Err(ProofVerificationError::ChallengeIdMissing);
        }
        if request.credential_sub.is_empty() {
            return Err(ProofVerificationError::CredentialSubMissing);
        }
        if request.proof.is_empty() {
            return Err(ProofVerificationError::ProofMissing);
        }

        if request.credential_sub.len() > MAX_CREDENTIAL_SUB_BYTES {
            return Err(ProofVerificationError::Invalid);
        }
        if self.config.max_proof_body_bytes > 0
            && request.proof.len() as u64 > self.config.max_proof_body_bytes
        {
            return Err(ProofVerificationError::Oversized);
        }
        if !Uuid::parse_str(&request.challenge_id).is_ok() {
            return Err(ProofVerificationError::Invalid);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use axum::{
        Json, Router,
        body::Body,
        extract::State,
        http::{Request, StatusCode, header},
        response::IntoResponse,
        routing::post,
    };
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use http_body_util::BodyExt;
    use serde::Deserialize;
    use tower::ServiceExt;

    use super::*;
    use crate::FailureClass;

    const CHALLENGE: &str = "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31";
    const SUB: &str = "0xab12cd34";
    const PROOF: &[u8] = &[0xa1, 0x00, 0xff, 0x00, 0xde, 0xad, 0xbe, 0xef];

    struct StubClient {
        verdict: Verdict,
        seen: Mutex<Vec<VerificationRequest>>,
    }

    impl StubClient {
        fn new(verdict: Verdict) -> Arc<Self> {
            Arc::new(Self {
                verdict,
                seen: Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> Vec<VerificationRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ProofVerificationClient for StubClient {
        async fn verify(&self, request: VerificationRequest) -> Verdict {
            self.seen.lock().unwrap().push(request);
            self.verdict
        }
    }

    #[derive(Deserialize)]
    struct InitMigrationBody {
        #[serde(default)]
        challenge_id: String,
        #[serde(default)]
        sub: String,
        #[serde(default)]
        proof: String,
    }

    async fn init_migration(
        State(verifier): State<Arc<Verifier>>,
        Json(body): Json<InitMigrationBody>,
    ) -> impl IntoResponse {
        let request = VerificationRequest {
            challenge_id: body.challenge_id,
            challenge_type: verifier.config.challenge_type.clone(),
            credential_sub: body.sub,
            proof: body.proof,
        };
        match verifier.verify(request).await {
            Ok(()) => (StatusCode::OK, String::new()),
            Err(error) => (StatusCode::BAD_REQUEST, error.as_str().to_owned()),
        }
    }

    fn router(client: Arc<StubClient>, config: Config) -> Router {
        let verifier = Arc::new(Verifier::new(
            config,
            client as Arc<dyn ProofVerificationClient>,
        ));
        Router::new()
            .route("/v1/init-migration", post(init_migration))
            .with_state(verifier)
    }

    fn json_body(challenge: Option<&str>, sub: Option<&str>, proof: Option<&[u8]>) -> String {
        let mut body = serde_json::Map::new();
        if let Some(challenge) = challenge {
            body.insert("challenge_id".to_owned(), challenge.into());
        }
        if let Some(sub) = sub {
            body.insert("sub".to_owned(), sub.into());
        }
        if let Some(proof) = proof {
            body.insert("proof".to_owned(), BASE64.encode(proof).into());
        }
        serde_json::Value::Object(body).to_string()
    }

    async fn post_json(router: Router, body: String) -> (StatusCode, String) {
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/init-migration")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn accepted_proof_forwards_the_request_fields() {
        let client = StubClient::new(Verdict::Accepted);
        let (status, _) = post_json(
            router(Arc::clone(&client), Config::default()),
            json_body(Some(CHALLENGE), Some(SUB), Some(PROOF)),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let seen = client.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].challenge_id, CHALLENGE);
        assert_eq!(seen[0].challenge_type, DEFAULT_CHALLENGE_TYPE);
        assert_eq!(seen[0].credential_sub, SUB);
        assert_eq!(seen[0].proof, BASE64.encode(PROOF));
    }

    #[tokio::test]
    async fn configured_challenge_type_is_forwarded() {
        let client = StubClient::new(Verdict::Accepted);
        let config = Config {
            challenge_type: "custom_type".to_owned(),
            ..Config::default()
        };
        let (status, _) = post_json(
            router(Arc::clone(&client), config),
            json_body(Some(CHALLENGE), Some(SUB), Some(PROOF)),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(client.seen()[0].challenge_type, "custom_type");
    }

    #[tokio::test]
    async fn rejected_proof_is_reported() {
        let client = StubClient::new(Verdict::Rejected);
        let (status, body) = post_json(
            router(Arc::clone(&client), Config::default()),
            json_body(Some(CHALLENGE), Some(SUB), Some(PROOF)),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "verification_failed");
        assert_eq!(client.seen().len(), 1);
    }

    #[tokio::test]
    async fn verification_service_error_is_reported() {
        let client = StubClient::new(Verdict::Error(FailureClass::UpstreamServer));
        let (status, body) = post_json(
            router(Arc::clone(&client), Config::default()),
            json_body(Some(CHALLENGE), Some(SUB), Some(PROOF)),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "verification_error");
    }

    struct FailingClient;

    #[async_trait]
    impl ProofVerificationClient for FailingClient {
        async fn verify(&self, _request: VerificationRequest) -> Verdict {
            Verdict::Error(FailureClass::Timeout)
        }
    }

    #[tokio::test]
    async fn client_failure_is_a_verification_error() {
        let verifier = Arc::new(Verifier::new(
            Config::default(),
            Arc::new(FailingClient) as Arc<dyn ProofVerificationClient>,
        ));
        let router = Router::new()
            .route("/v1/init-migration", post(init_migration))
            .with_state(verifier);
        let (status, body) =
            post_json(router, json_body(Some(CHALLENGE), Some(SUB), Some(PROOF))).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, "verification_error");
    }

    #[tokio::test]
    async fn invalid_fields_do_not_call_the_service() {
        let oversized = vec![0xab; 10];
        let cases = [
            (
                json_body(None, Some(SUB), Some(PROOF)),
                "challenge_id_missing",
            ),
            (
                json_body(Some(CHALLENGE), None, Some(PROOF)),
                "credential_sub_missing",
            ),
            (json_body(Some(CHALLENGE), Some(SUB), None), "proof_missing"),
            (
                json_body(Some("not-a-uuid"), Some(SUB), Some(PROOF)),
                "invalid",
            ),
            (
                json_body(
                    Some(CHALLENGE),
                    Some(&"a".repeat(MAX_CREDENTIAL_SUB_BYTES + 1)),
                    Some(PROOF),
                ),
                "invalid",
            ),
            (
                json_body(Some(CHALLENGE), Some(SUB), Some(&oversized)),
                "oversized",
            ),
        ];
        let config = Config {
            max_proof_body_bytes: BASE64.encode(PROOF).len() as u64,
            ..Config::default()
        };

        for (body, want) in cases {
            let client = StubClient::new(Verdict::Accepted);
            let (status, error) =
                post_json(router(Arc::clone(&client), config.clone()), body.clone()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(error, want, "{body}");
            assert!(client.seen().is_empty(), "{body}");
        }
    }
}
