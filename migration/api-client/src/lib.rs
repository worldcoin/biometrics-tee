//! Client for the migration API.

use std::time::Duration;

use di_migration_primitives::app_api::{
    DEVICE_PUBLIC_KEY_HEADER, ErrorEnvelope, InitMigrationRequest, InitMigrationResponse,
    MigrateResponse, MigrationStatus,
};
use reqwest::{StatusCode, Url};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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
    #[error("migration API answered {status}: {code}")]
    Api { status: StatusCode, code: String },
    #[error("failed to decode the migration API response: {0}")]
    Decode(#[source] reqwest::Error),
}

#[derive(Debug, Clone)]
pub struct MigrationApiClient {
    http: reqwest::Client,
    init_migration_url: Url,
    migrations_url: Url,
}

impl MigrationApiClient {
    pub fn new(base_url: &Url) -> Result<Self, Error> {
        let init_migration_url =
            base_url
                .join("v1/init-migration")
                .map_err(|_| Error::InvalidBaseUrl {
                    base_url: base_url.clone(),
                })?;
        let migrations_url = base_url
            .join("v1/migrations/")
            .ok()
            .filter(|url| !url.cannot_be_a_base())
            .ok_or_else(|| Error::InvalidBaseUrl {
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
            migrations_url,
        })
    }

    /// Starts a migration for `sub` as the device with `device_public_key`, with a
    /// standard-base64 ownership `proof` and the `challenge_id` the proof was built for.
    /// Not retried here: each call creates a new migration record.
    pub async fn init_migration(
        &self,
        device_public_key: &str,
        sub: &str,
        proof: &str,
        challenge_id: &str,
    ) -> Result<InitMigrationResponse, Error> {
        let response = self
            .http
            .post(self.init_migration_url.clone())
            .header(DEVICE_PUBLIC_KEY_HEADER, device_public_key)
            .json(&InitMigrationRequest {
                sub: sub.to_owned(),
                proof: proof.to_owned(),
                challenge_id: challenge_id.to_owned(),
            })
            .send()
            .await
            .map_err(Error::Transport)?;

        decode(response).await
    }

    /// Hands the uploaded PCP to its host. A repeated call reports the running job.
    pub async fn migrate(
        &self,
        device_public_key: &str,
        sub: &str,
    ) -> Result<MigrateResponse, Error> {
        let response = self
            .http
            .post(self.migration_url(sub))
            .header(DEVICE_PUBLIC_KEY_HEADER, device_public_key)
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    /// The `sub`'s latest migration, with a download URL once `migrated`.
    pub async fn migration_status(
        &self,
        device_public_key: &str,
        sub: &str,
    ) -> Result<MigrationStatus, Error> {
        let response = self
            .http
            .get(self.migration_url(sub))
            .header(DEVICE_PUBLIC_KEY_HEADER, device_public_key)
            .send()
            .await
            .map_err(Error::Transport)?;
        decode(response).await
    }

    /// `sub` as one percent-encoded path segment.
    fn migration_url(&self, sub: &str) -> Url {
        let mut url = self.migrations_url.clone();
        url.path_segments_mut()
            .expect("checked to be a base URL")
            .pop_if_empty()
            .push(sub);
        url
    }

    /// Uploads a PCP to a presigned URL returned by [`Self::init_migration`].
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
    use axum::{
        Json, Router,
        http::{HeaderMap, StatusCode},
        routing::post,
    };

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
            post(
                |headers: HeaderMap, Json(body): Json<serde_json::Value>| async move {
                    assert_eq!(headers["x-device-public-key"], "device-key");
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
                },
            ),
        ))
        .await;

        let response = MigrationApiClient::new(&url)
            .unwrap()
            .init_migration(
                "device-key",
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

        let error = MigrationApiClient::new(&url)
            .unwrap()
            .init_migration(
                "device-key",
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
