//! Client for the migration API.

use std::time::Duration;

use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
struct InitMigrationRequest<'a> {
    sub: &'a str,
    proof: &'a str,
    challenge_id: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitMigrationResponse {
    pub enclave_id: String,
    /// COSE attestation document, standard padded base64.
    pub attestation: String,
    /// Presigned S3 URL the PCP is uploaded to with `PUT`.
    pub presigned_url: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to build the HTTP client: {0}")]
    Build(#[source] reqwest::Error),
    #[error("{base_url} is not a valid migration API base URL")]
    InvalidBaseUrl { base_url: Url },
    #[error("request to the migration API failed: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("migration API answered {status}")]
    UnexpectedStatus { status: StatusCode },
    #[error("failed to decode the migration API response: {0}")]
    Decode(#[source] reqwest::Error),
}

#[derive(Debug, Clone)]
pub struct MigrationApiClient {
    http: reqwest::Client,
    init_migration_url: Url,
}

impl MigrationApiClient {
    pub fn new(base_url: &Url) -> Result<Self, Error> {
        let init_migration_url =
            base_url
                .join("v1/init-migration")
                .map_err(|_| Error::InvalidBaseUrl {
                    base_url: base_url.clone(),
                })?;
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(Error::Build)?;

        Ok(Self {
            http,
            init_migration_url,
        })
    }

    /// Starts a migration for `sub` with a standard-base64 ownership `proof`
    /// and the `challenge_id` the proof was built for.
    /// Not retried here: each call creates a new migration record.
    pub async fn init_migration(
        &self,
        sub: &str,
        proof: &str,
        challenge_id: &str,
    ) -> Result<InitMigrationResponse, Error> {
        let response = self
            .http
            .post(self.init_migration_url.clone())
            .json(&InitMigrationRequest {
                sub,
                proof,
                challenge_id,
            })
            .send()
            .await
            .map_err(Error::Transport)?;

        let status = response.status();
        if !status.is_success() {
            return Err(Error::UnexpectedStatus { status });
        }

        response.json().await.map_err(Error::Decode)
    }

    /// Uploads a PCP to a presigned URL returned by [`Self::init_migration`].
    pub async fn upload_pcp(&self, presigned_url: &str, pcp: Vec<u8>) -> Result<(), Error> {
        let response = self
            .http
            .put(presigned_url)
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
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, http::StatusCode, routing::post};

    use super::{Error, MigrationApiClient};

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
        let (url, server) = serve(Router::new().route(
            "/v1/init-migration",
            post(|Json(body): Json<serde_json::Value>| async move {
                assert_eq!(body["sub"], "test-sub");
                assert_eq!(body["proof"], "cHJvb2Y=");
                assert_eq!(body["challenge_id"], "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31");
                Json(serde_json::json!({
                    "enclave_id": "enc-1",
                    "attestation": "",
                    "presigned_url": "http://s3.test/pcp/1",
                }))
            }),
        ))
        .await;

        let response = MigrationApiClient::new(&url)
            .unwrap()
            .init_migration(
                "test-sub",
                "cHJvb2Y=",
                "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31",
            )
            .await
            .unwrap();

        assert_eq!(response.enclave_id, "enc-1");
        assert_eq!(response.presigned_url, "http://s3.test/pcp/1");
        server.abort();
    }

    #[tokio::test]
    async fn init_migration_surfaces_error_statuses() {
        let (url, server) = serve(Router::new().route(
            "/v1/init-migration",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        ))
        .await;

        let error = MigrationApiClient::new(&url)
            .unwrap()
            .init_migration(
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
