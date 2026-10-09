//! The app side of DI migration: the migration API client and the sealed channel to the enclave.

pub mod sealing;

use std::time::Duration;

use attested_request::{
    base::CanonicalRequest,
    sign::{Signer, sign_request},
};
use di_migration_primitives::{
    EnclaveId,
    app_api::{
        DEVICE_KEY_THUMBPRINT, ErrorEnvelope, InitMigrationRequest, InitMigrationResponse,
        MigrateResponse, MigrationStatus,
    },
};
use reqwest::{StatusCode, Url, header::CONTENT_TYPE};

use crate::sealing::{EnclaveVerifier, PcpOpener, SealingError};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to build the HTTP client: {0}")]
    Build(#[source] reqwest::Error),
    #[error("{base_url} is not a valid migration API base URL")]
    InvalidBaseUrl { base_url: Url },
    #[error("failed to encode the request body: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("failed to build the canonical request: {0}")]
    CanonicalRequest(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to sign the request: {0}")]
    Sign(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("request to the migration API failed: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("migration API answered {status}")]
    UnexpectedStatus { status: StatusCode },
    #[error("migration API answered {status}: {code}")]
    Api { status: StatusCode, code: String },
    #[error("failed to decode the migration API response: {0}")]
    Decode(#[source] reqwest::Error),
    #[error(transparent)]
    Sealing(#[from] SealingError),
}

#[derive(Debug, Clone)]
pub struct MigrationApiClient {
    http: reqwest::Client,
    /// Routes are appended to its path as segments.
    base_url: Url,
    /// Sent as [`DEVICE_KEY_THUMBPRINT`] when set.
    ///
    /// In production the auth proxy populates this header from the request signature; leave
    /// unset there. Under the `test-util` feature (and in this crate's tests), set it via
    /// [`Self::with_device_public_key`].
    device_public_key: Option<String>,
}

/// Arguments of [`MigrationApiClient::start_migration`].
#[derive(Clone, Copy)]
pub struct StartMigration<'a, S> {
    /// Attestation Gateway integrity token (JWT).
    pub integrity_token: &'a str,
    /// Signs the init request.
    pub signer: &'a S,
    /// Trusts the enclave boot the API returns before the PCP is sealed to it.
    pub verifier: &'a EnclaveVerifier,
    /// Subject of the account being migrated.
    pub sub: &'a str,
    /// Standard-base64 ownership proof.
    pub proof: &'a str,
    /// Challenge id the proof was built for.
    pub challenge_id: &'a str,
    /// PCP sealed to the enclave and uploaded.
    pub pcp: &'a [u8],
    /// Self-custody credential sealed with the PCP.
    pub credential: &'a str,
}

impl MigrationApiClient {
    pub fn new(base_url: &Url) -> Result<Self, Error> {
        if base_url.cannot_be_a_base() {
            return Err(Error::InvalidBaseUrl {
                base_url: base_url.clone(),
            });
        }
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(Error::Build)?;

        Ok(Self {
            http,
            base_url: base_url.clone(),
            device_public_key: None,
        })
    }

    /// Sets the device public key header for tests and local tooling without an auth proxy.
    ///
    /// In production leave this unset; the proxy injects [`DEVICE_KEY_THUMBPRINT`] after
    /// verifying the signature.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_device_public_key(&self, device_public_key: impl Into<String>) -> Self {
        Self {
            device_public_key: Some(device_public_key.into()),
            http: self.http.clone(),
            base_url: self.base_url.clone(),
        }
    }

    /// Starts a migration for `sub` with a standard-base64 ownership `proof` and the
    /// `challenge_id` the proof was built for.
    ///
    /// The request is signed with `signer` and the Attestation Gateway `integrity_token`.
    /// Hardware signers block, so call this off any async executor that must stay responsive.
    /// Not retried here: each call creates a new migration record and must be re-signed.
    pub async fn init_migration<S: Signer>(
        &self,
        integrity_token: &str,
        signer: &S,
        sub: &str,
        proof: &str,
        challenge_id: &str,
    ) -> Result<InitMigrationResponse, Error>
    where
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        let body = serde_json::to_vec(&InitMigrationRequest {
            sub: sub.to_owned(),
            proof: proof.to_owned(),
            challenge_id: challenge_id.to_owned(),
        })
        .map_err(Error::Encode)?;

        let url = self.url(&["v1", "init-migration"]);
        let canonical = CanonicalRequest::new(
            "POST",
            url.scheme(),
            url.authority(),
            url.path(),
            url.query(),
            &body,
        )
        .map_err(|error| Error::CanonicalRequest(Box::new(error)))?;

        // Hardware signers block; callers that need a free executor should wrap this call.
        let signed = sign_request(&canonical, integrity_token, signer)
            .map_err(|error| Error::Sign(Box::new(error)))?;

        let mut request = self
            .http
            .post(url)
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(device_public_key) = &self.device_public_key {
            request = request.header(DEVICE_KEY_THUMBPRINT, device_public_key);
        }
        for (name, value) in signed.headers() {
            request = request.header(name, value);
        }

        let response = request.send().await.map_err(Error::Transport)?;
        decode(response).await
    }

    /// Hands the uploaded PCP to its host. A repeated call reports the running job.
    pub async fn migrate(&self, sub: &str) -> Result<MigrateResponse, Error> {
        let mut request = self.http.post(self.url(&["v1", "migrations", sub]));
        if let Some(device_public_key) = &self.device_public_key {
            request = request.header(DEVICE_KEY_THUMBPRINT, device_public_key);
        }
        let response = request.send().await.map_err(Error::Transport)?;
        decode(response).await
    }

    /// The `sub`'s latest migration, with a download URL once `migrated`.
    pub async fn migration_status(&self, sub: &str) -> Result<MigrationStatus, Error> {
        let mut request = self.http.get(self.url(&["v1", "migrations", sub]));
        if let Some(device_public_key) = &self.device_public_key {
            request = request.header(DEVICE_KEY_THUMBPRINT, device_public_key);
        }
        let response = request.send().await.map_err(Error::Transport)?;
        decode(response).await
    }

    /// The base URL with `segments` appended, each percent-encoded, so a `sub` stays one segment.
    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .expect("checked to be a base URL in new")
            .pop_if_empty()
            .extend(segments);
        url
    }

    /// Downloads the sealed migrated PCP from a presigned URL in [`MigrationStatus`].
    pub async fn download_pcp(&self, download_url: &str) -> Result<Vec<u8>, Error> {
        let response = self
            .http
            .get(download_url)
            .send()
            .await
            .map_err(Error::Transport)?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::UnexpectedStatus { status });
        }
        let blob = response.bytes().await.map_err(Error::Transport)?;
        Ok(blob.to_vec())
    }

    /// Uploads a sealed PCP to a presigned URL returned by [`Self::init_migration`].
    pub async fn upload_pcp(&self, upload_url: &str, pcp: Vec<u8>) -> Result<(), Error> {
        let response = self
            .http
            .put(upload_url)
            .body(pcp)
            .send()
            .await
            .map_err(Error::Transport)?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(Error::UnexpectedStatus { status })
        }
    }

    /// Inits, verifies the enclave, seals and uploads the PCP, and starts the job.
    ///
    /// Returns the opener for the migrated result and the attested `enclave_id`.
    /// Hardware signers block, so call this off any async executor that must stay responsive.
    /// Not retried here: each call creates a new migration record and must be re-signed.
    pub async fn start_migration<S: Signer>(
        &self,
        StartMigration {
            integrity_token,
            signer,
            verifier,
            sub,
            proof,
            challenge_id,
            pcp,
            credential,
        }: StartMigration<'_, S>,
    ) -> Result<(PcpOpener, EnclaveId), Error>
    where
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        let response = self
            .init_migration(integrity_token, signer, sub, proof, challenge_id)
            .await?;
        let (blob, opener) = verifier
            .attested_channel(&response)
            .and_then(|channel| channel.seal(pcp, credential))?;
        self.upload_pcp(&response.upload_url, blob).await?;
        self.migrate(sub).await?;
        Ok((opener, response.enclave_id))
    }
}

/// The success body, or the API's error code.
async fn decode<T: serde::de::DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    let status = response.status();
    if !status.is_success() {
        return Err(match response.json::<ErrorEnvelope>().await {
            Ok(envelope) => Error::Api {
                status,
                code: envelope.error.code,
            },
            Err(_) => Error::UnexpectedStatus { status },
        });
    }
    response.json().await.map_err(Error::Decode)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use attested_request::{
        Platform,
        sign::Signer,
        test_util::{SoftwareSigner, TestClaims, TestClient, TestIssuer, test_key},
    };
    use axum::{Json, Router, http::StatusCode, routing::post};

    use super::{Error, MigrationApiClient};

    #[test]
    fn routes_extend_the_base_path_and_keep_the_sub_one_segment() {
        let client = MigrationApiClient::new(&"http://api.test/prefix/".parse().unwrap()).unwrap();

        assert_eq!(
            client.url(&["v1", "init-migration"]).as_str(),
            "http://api.test/prefix/v1/init-migration"
        );
        assert_eq!(
            client.url(&["v1", "migrations", "a/b c"]).as_str(),
            "http://api.test/prefix/v1/migrations/a%2Fb%20c"
        );
    }

    fn test_signer() -> SoftwareSigner {
        SoftwareSigner::new(test_key("migration-api-client"), Platform::Android)
    }

    fn test_token(signer: &SoftwareSigner) -> String {
        TestIssuer::new("https://attestation.example").mint(&TestClaims::valid(
            "migration-api",
            signer.platform(),
            signer.verifying_key(),
            UNIX_EPOCH + Duration::from_secs(1_790_000_000),
        ))
    }

    async fn serve(router: Router) -> (reqwest::Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        (url, server)
    }

    #[tokio::test]
    async fn init_migration_returns_the_decoded_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: reqwest::Url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let mut test_client = TestClient::new(Platform::Android, url.authority());
        test_client.now = std::time::SystemTime::now();
        let verifier = test_client.verifier().scheme(url.scheme()).build().unwrap();
        let router = Router::new().route(
            "/v1/init-migration",
            post(move |request: axum::extract::Request| {
                let verifier = verifier.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    assert_eq!(parts.headers["x-attested-key-thumbprint"], "device-key");
                    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                    verifier.verify(&parts, &body).await.unwrap();

                    let mut tampered_body = body.to_vec();
                    tampered_body[0] ^= 1;
                    assert!(verifier.verify(&parts, &tampered_body).await.is_err());

                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    assert_eq!(body["sub"], "test-sub");
                    assert_eq!(body["proof"], "cHJvb2Y=");
                    assert_eq!(body["challenge_id"], "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31");
                    Json(serde_json::json!({
                        "enclave_id": "ab".repeat(32),
                        "attestation": "",
                        "enclave_public_key": "key",
                        "upload_url": "http://s3.test/pcp/1",
                        "migrate_by": 1,
                    }))
                }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let response = MigrationApiClient::new(&url)
            .unwrap()
            .with_device_public_key("device-key")
            .init_migration(
                &test_client.token(),
                &test_client.signer,
                "test-sub",
                "cHJvb2Y=",
                "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31",
            )
            .await
            .unwrap();

        assert_eq!(response.enclave_id.as_str(), "ab".repeat(32));
        assert_eq!(response.upload_url, "http://s3.test/pcp/1");
        server.abort();
    }

    #[tokio::test]
    async fn init_migration_surfaces_error_statuses() {
        let (url, server) = serve(Router::new().route(
            "/v1/init-migration",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        ))
        .await;

        let signer = test_signer();
        let token = test_token(&signer);
        let error = MigrationApiClient::new(&url)
            .unwrap()
            .with_device_public_key("device-key")
            .init_migration(
                &token,
                &signer,
                "test-sub",
                "cHJvb2Y=",
                "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31",
            )
            .await
            .unwrap_err();

        assert!(
            matches!(error, Error::UnexpectedStatus { status } if status == StatusCode::SERVICE_UNAVAILABLE),
            "{error}"
        );
        server.abort();
    }
}
