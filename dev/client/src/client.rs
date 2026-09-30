//! HTTP calls against the dev host.

use std::time::Duration;

use di_dev_api_types::{ErrorEnvelope, MIGRATION_CONTENT_TYPE, codes};
use reqwest::{StatusCode, blocking};

use crate::error::Error;

/// Exceeds the host's own 300s enclave deadline, so a slow migration surfaces as the host's
/// `enclave_timeout` rather than as a bare client-side timeout with no explanation.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(330);

/// Talks to one dev host.
#[derive(Debug)]
pub struct Client {
    http: blocking::Client,
    host: String,
}

impl Client {
    /// Builds a client for `host`, e.g. `http://localhost:8000`.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is unusable or the HTTP client cannot be built.
    pub fn new(host: &str) -> Result<Self, Error> {
        let host = host.trim_end_matches('/').to_owned();
        if !host.starts_with("http://") && !host.starts_with("https://") {
            return Err(Error::InvalidHost(format!(
                "{host} must start with http:// or https://"
            )));
        }

        let http = blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(Error::Request)?;

        Ok(Self { http, host })
    }

    /// Migrates one gzipped PCP, returning the migrated one.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the host rejects it.
    pub fn migrate(&self, pcp: Vec<u8>) -> Result<Vec<u8>, Error> {
        let response = self
            .http
            .post(format!("{}/v1/migrations", self.host))
            .header(reqwest::header::CONTENT_TYPE, MIGRATION_CONTENT_TYPE)
            .body(pcp)
            .send()
            .map_err(Error::Request)?;

        if !response.status().is_success() {
            return Err(api_error(response));
        }

        response
            .bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(Error::Request)
    }

    /// Reports whether the host is up and whether it can reach its enclave.
    ///
    /// # Errors
    ///
    /// Returns an error only if a probe could not be reached at all; a probe answering with a
    /// failure status is a result, not an error.
    pub fn health(&self) -> Result<(bool, bool), Error> {
        Ok((self.probe("health")?, self.probe("ready")?))
    }

    fn probe(&self, path: &str) -> Result<bool, Error> {
        self.http
            .get(format!("{}/{path}", self.host))
            .send()
            .map(|response| response.status() == StatusCode::OK)
            .map_err(Error::Request)
    }
}

/// Reads the host's error envelope, promoting the one code the caller can act on.
fn api_error(response: blocking::Response) -> Error {
    let status = response.status().as_u16();

    let Ok(envelope) = response.json::<ErrorEnvelope>() else {
        return Error::Status(status);
    };

    if envelope.error.code == codes::MIGRATION_IN_PROGRESS {
        return Error::MigrationInProgress;
    }

    Error::Api {
        status,
        code: envelope.error.code,
        message: envelope.error.message,
        allow_retry: envelope.allow_retry,
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::mpsc, thread};

    use axum::{
        Router,
        http::StatusCode,
        response::IntoResponse,
        routing::{get, post},
    };

    use super::Client;
    use crate::error::Error;

    /// Serves `router` on an ephemeral port from its own runtime, so the blocking client can
    /// call it — `reqwest::blocking` panics if used inside a tokio context.
    fn serve(router: Router) -> String {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime should build");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("should bind");
                tx.send(listener.local_addr().expect("should have an address"))
                    .expect("receiver should be alive");
                axum::serve(listener, router).await.expect("should serve");
            });
        });
        let address: SocketAddr = rx.recv().expect("server should report its address");
        format!("http://{address}")
    }

    fn envelope(code: &str, allow_retry: bool) -> String {
        serde_json::json!({
            "allowRetry": allow_retry,
            "error": { "code": code, "message": "stub" },
        })
        .to_string()
    }

    fn client_for(router: Router) -> Client {
        Client::new(&serve(router)).expect("client should build")
    }

    #[test]
    fn a_migrated_pcp_comes_back() {
        let client =
            client_for(Router::new().route("/v1/migrations", post(|| async { "migrated" })));

        let pcp = client.migrate(b"sent".to_vec()).expect("should migrate");

        assert_eq!(pcp, b"migrated");
    }

    /// The one code promoted to its own variant, so the caller can act without string matching.
    #[test]
    fn a_busy_host_is_promoted_to_its_own_error() {
        let client = client_for(Router::new().route(
            "/v1/migrations",
            post(|| async {
                (
                    StatusCode::CONFLICT,
                    envelope("migration_in_progress", true),
                )
                    .into_response()
            }),
        ));

        let error = client.migrate(b"sent".to_vec()).expect_err("should refuse");

        assert!(matches!(error, Error::MigrationInProgress), "{error:?}");
    }

    #[test]
    fn any_other_code_keeps_its_envelope() {
        let client = client_for(Router::new().route(
            "/v1/migrations",
            post(|| async {
                (
                    StatusCode::BAD_GATEWAY,
                    envelope("enclave_unreachable", true),
                )
                    .into_response()
            }),
        ));

        let error = client.migrate(b"sent".to_vec()).expect_err("should fail");

        match error {
            Error::Api {
                status,
                code,
                allow_retry,
                ..
            } => {
                assert_eq!(status, 502);
                assert_eq!(code, "enclave_unreachable");
                assert!(allow_retry);
            }
            other => panic!("expected an envelope, got {other:?}"),
        }
    }

    /// A proxy or ingress can answer without the host's envelope; that must not be a parse panic.
    #[test]
    fn a_failure_without_an_envelope_keeps_the_status() {
        let client = client_for(Router::new().route(
            "/v1/migrations",
            post(|| async {
                (StatusCode::BAD_GATEWAY, "<html>bad gateway</html>").into_response()
            }),
        ));

        let error = client.migrate(b"sent".to_vec()).expect_err("should fail");

        assert!(matches!(error, Error::Status(502)), "{error:?}");
    }

    #[test]
    fn health_reports_each_probe_separately() {
        let client = client_for(
            Router::new()
                .route("/health", get(|| async { StatusCode::OK }))
                .route("/ready", get(|| async { StatusCode::SERVICE_UNAVAILABLE })),
        );

        assert_eq!(client.health().expect("should probe"), (true, false));
    }

    #[test]
    fn a_host_without_a_scheme_is_rejected() {
        let error = Client::new("localhost:8000").expect_err("should reject");

        assert!(matches!(error, Error::InvalidHost(_)), "{error:?}");
    }
}
