use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};

use crate::auth::AuthProvider;

pub const VERIFY_PATH: &str = "/api/v4/verify";
pub const DEFAULT_CHALLENGE_TYPE: &str = "teedi_migration";

/// Three-state so a rejected proof stays distinguishable from an unreachable service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Rejected,
    Error,
}

impl Verdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Error => "error",
        }
    }
}

/// Explains a [`Verdict::Error`] so triage does not need the logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    None,
    Timeout,
    Canceled,
    Connection,
    UpstreamClient,
    UpstreamServer,
    Request,
    Auth,
}

impl FailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Timeout => "timeout",
            Self::Canceled => "canceled",
            Self::Connection => "connection",
            Self::UpstreamClient => "upstream_4xx",
            Self::UpstreamServer => "upstream_5xx",
            Self::Request => "request",
            Self::Auth => "auth",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyResult {
    pub verdict: Verdict,
    pub failure: FailureClass,
    pub status_code: u16,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to build the HTTP client: {0}")]
    Build(#[source] reqwest::Error),
    #[error("{host} is not a valid proof verification service host")]
    InvalidHost { host: String },
    #[error("failed to get auth token: {0}")]
    Auth(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("request to the proof verification service failed: {0}")]
    Transport(#[source] reqwest::Error),
    #[error("world-id-proof-verification-service returned {status}")]
    UnexpectedStatus { status: StatusCode },
}

/// Implemented by [`Client`]; tests may substitute a stub.
#[async_trait]
pub trait ProofVerificationClient: Send + Sync {
    /// Classifies the upstream response. The [`VerifyResult`] is always populated
    /// so metrics can tag verdict and failure even when the `Result` is `Err`.
    async fn verify(&self, request: VerificationRequest) -> (VerifyResult, Result<(), Error>);
}

/// The verification service uses `challenge_type` plus `challenge_id` to recover
/// the nonce. This API always sends a configured type; it is not taken from the
/// client request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub challenge_id: String,
    pub challenge_type: String,
    pub credential_sub: String,
    pub proof: String,
}

pub struct Config {
    pub host: String,
    pub timeout: Duration,
    pub max_conns: usize,
}

pub struct Client {
    http: reqwest::Client,
    verify_url: Url,
    auth_provider: Arc<dyn AuthProvider>,
}

impl Client {
    pub fn new(config: Config, auth_provider: Arc<dyn AuthProvider>) -> Result<Self, Error> {
        let max_conns = config.max_conns.max(1);
        let mut http = reqwest::Client::builder().pool_max_idle_per_host(max_conns);
        if !config.timeout.is_zero() {
            http = http.timeout(config.timeout);
        }
        let http = http.build().map_err(Error::Build)?;

        let host = config.host.trim_end_matches('/');
        let verify_url = format!("{host}{VERIFY_PATH}")
            .parse()
            .map_err(|_| Error::InvalidHost { host: config.host })?;

        Ok(Self {
            http,
            verify_url,
            auth_provider,
        })
    }

    /// Classifies the upstream response. The [`VerifyResult`] is always populated
    /// so metrics can tag verdict and failure even when the `Result` is `Err`.
    pub async fn verify(&self, request: VerificationRequest) -> (VerifyResult, Result<(), Error>) {
        let mut http_request = self.http.post(self.verify_url.clone()).json(&request);
        match self.auth_provider.token().await {
            Ok(token) => {
                http_request = http_request.bearer_auth(token);
            }
            Err(error) => {
                return (
                    VerifyResult {
                        verdict: Verdict::Error,
                        failure: FailureClass::Auth,
                        status_code: 0,
                    },
                    Err(Error::Auth(error)),
                );
            }
        }

        let response = match http_request.send().await {
            Ok(response) => response,
            Err(error) => {
                return (
                    VerifyResult {
                        verdict: Verdict::Error,
                        failure: classify_transport(&error),
                        status_code: 0,
                    },
                    Err(Error::Transport(error)),
                );
            }
        };

        let status = response.status();
        // Drain in full so the connection can return to the pool.
        let _ = response.bytes().await;

        match status {
            StatusCode::OK => (
                VerifyResult {
                    verdict: Verdict::Accepted,
                    failure: FailureClass::None,
                    status_code: status.as_u16(),
                },
                Ok(()),
            ),
            StatusCode::UNAUTHORIZED => (
                VerifyResult {
                    verdict: Verdict::Rejected,
                    failure: FailureClass::None,
                    status_code: status.as_u16(),
                },
                Ok(()),
            ),
            status => {
                let failure = if status.as_u16() < 500 {
                    FailureClass::UpstreamClient
                } else {
                    FailureClass::UpstreamServer
                };
                (
                    VerifyResult {
                        verdict: Verdict::Error,
                        failure,
                        status_code: status.as_u16(),
                    },
                    Err(Error::UnexpectedStatus { status }),
                )
            }
        }
    }
}

#[async_trait]
impl ProofVerificationClient for Client {
    async fn verify(&self, request: VerificationRequest) -> (VerifyResult, Result<(), Error>) {
        Self::verify(self, request).await
    }
}

fn classify_transport(error: &reqwest::Error) -> FailureClass {
    if error.is_timeout() {
        return FailureClass::Timeout;
    }
    if is_canceled(error) {
        return FailureClass::Canceled;
    }
    FailureClass::Connection
}

fn is_canceled(error: &reqwest::Error) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(err) = source {
        if let Some(io) = err.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::Interrupted
        {
            return true;
        }
        let message = err.to_string();
        if message.contains("canceled") || message.contains("cancelled") {
            return true;
        }
        source = err.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{
        Router,
        extract::OriginalUri,
        http::{HeaderMap, StatusCode, header},
        routing::post,
    };

    use super::{
        Client, Config, DEFAULT_CHALLENGE_TYPE, Error, FailureClass, VERIFY_PATH, Verdict,
        VerificationRequest, VerifyResult,
    };
    use crate::auth::AuthProvider;

    struct StubAuth {
        token: Result<String, &'static str>,
    }

    #[async_trait]
    impl AuthProvider for StubAuth {
        async fn token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
            self.token
                .clone()
                .map_err(|message| Box::new(std::io::Error::other(message)).into())
        }
    }

    fn test_request() -> VerificationRequest {
        VerificationRequest {
            challenge_id: "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31".to_owned(),
            challenge_type: DEFAULT_CHALLENGE_TYPE.to_owned(),
            credential_sub: "0xab12cd34".to_owned(),
            proof: "0xa100ff00deadbeef".to_owned(),
        }
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

    fn verify_route<H, T>(handler: H) -> Router
    where
        H: axum::handler::Handler<T, ()> + Send + 'static,
        T: 'static,
    {
        Router::new().route(VERIFY_PATH, post(handler))
    }

    fn stub_auth(token: Result<String, &'static str>) -> Arc<dyn AuthProvider> {
        Arc::new(StubAuth { token })
    }

    fn client(host: &reqwest::Url, timeout: Duration) -> Client {
        Client::new(
            Config {
                host: host.to_string(),
                timeout,
                max_conns: 2,
            },
            stub_auth(Ok("test-token".to_owned())),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn verify_classifies_responses() {
        for (status, verdict, failure, want_err) in [
            (StatusCode::OK, Verdict::Accepted, FailureClass::None, false),
            (
                StatusCode::UNAUTHORIZED,
                Verdict::Rejected,
                FailureClass::None,
                false,
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Verdict::Error,
                FailureClass::UpstreamServer,
                true,
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Verdict::Error,
                FailureClass::UpstreamServer,
                true,
            ),
            (
                StatusCode::BAD_REQUEST,
                Verdict::Error,
                FailureClass::UpstreamClient,
                true,
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                Verdict::Error,
                FailureClass::UpstreamClient,
                true,
            ),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let seen_path = Arc::new(Mutex::new(String::new()));
            let seen_content_type = Arc::new(Mutex::new(String::new()));
            let seen_body = Arc::new(Mutex::new(None));
            let (url, server) = {
                let calls = Arc::clone(&calls);
                let seen_path = Arc::clone(&seen_path);
                let seen_content_type = Arc::clone(&seen_content_type);
                let seen_body = Arc::clone(&seen_body);
                serve(verify_route(
                    move |uri: OriginalUri, headers: HeaderMap, body: String| {
                        let calls = Arc::clone(&calls);
                        let seen_path = Arc::clone(&seen_path);
                        let seen_content_type = Arc::clone(&seen_content_type);
                        let seen_body = Arc::clone(&seen_body);
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            *seen_path.lock().unwrap() = uri.path().to_owned();
                            *seen_content_type.lock().unwrap() = headers
                                .get(header::CONTENT_TYPE)
                                .and_then(|value| value.to_str().ok())
                                .unwrap_or_default()
                                .to_owned();
                            *seen_body.lock().unwrap() =
                                Some(serde_json::from_str::<VerificationRequest>(&body).unwrap());
                            status
                        }
                    },
                ))
                .await
            };

            let request = test_request();
            let (result, error) = client(&url, Duration::from_secs(2))
                .verify(request.clone())
                .await;

            assert_eq!(
                result,
                VerifyResult {
                    verdict,
                    failure,
                    status_code: status.as_u16(),
                }
            );
            assert_eq!(error.is_err(), want_err, "{error:?}");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(*seen_path.lock().unwrap(), VERIFY_PATH);
            assert!(
                seen_content_type
                    .lock()
                    .unwrap()
                    .starts_with("application/json"),
                "{}",
                seen_content_type.lock().unwrap()
            );
            assert_eq!(seen_body.lock().unwrap().as_ref(), Some(&request));
            server.abort();
        }
    }

    #[tokio::test]
    async fn verify_forwards_no_nonce() {
        let raw = Arc::new(Mutex::new(serde_json::Value::Null));
        let (url, server) = {
            let raw = Arc::clone(&raw);
            serve(verify_route(move |body: String| {
                let raw = Arc::clone(&raw);
                async move {
                    *raw.lock().unwrap() = serde_json::from_str(&body).unwrap();
                    StatusCode::OK
                }
            }))
            .await
        };

        client(&url, Duration::from_secs(1))
            .verify(test_request())
            .await
            .1
            .unwrap();

        let raw = raw.lock().unwrap();
        assert!(raw.get("nonce").is_none(), "{raw}");
        assert_eq!(raw["challenge_id"], "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31");
        assert_eq!(raw["challenge_type"], DEFAULT_CHALLENGE_TYPE);
        server.abort();
    }

    #[tokio::test]
    async fn verify_classifies_timeout() {
        let (url, server) = serve(verify_route(|| async {
            std::future::pending::<()>().await;
            StatusCode::OK
        }))
        .await;

        let (result, error) = client(&url, Duration::from_millis(50))
            .verify(test_request())
            .await;
        assert_eq!(result.verdict, Verdict::Error);
        assert_eq!(result.failure, FailureClass::Timeout);
        assert!(error.is_err(), "{error:?}");
        server.abort();
    }

    #[tokio::test]
    async fn verify_classifies_unreachable_host() {
        let client = Client::new(
            Config {
                host: "http://127.0.0.1:1".to_owned(),
                timeout: Duration::from_secs(1),
                max_conns: 1,
            },
            stub_auth(Ok("test-token".to_owned())),
        )
        .unwrap();
        let (result, error) = client.verify(test_request()).await;
        assert_eq!(result.verdict, Verdict::Error);
        assert_eq!(result.failure, FailureClass::Connection);
        assert!(error.is_err(), "{error:?}");
    }

    #[tokio::test]
    async fn verify_sends_bearer_token_when_auth_provider_is_set() {
        let seen = Arc::new(Mutex::new(None));
        let (url, server) = {
            let seen = Arc::clone(&seen);
            serve(verify_route(move |headers: HeaderMap| {
                let seen = Arc::clone(&seen);
                async move {
                    *seen.lock().unwrap() = headers
                        .get(header::AUTHORIZATION)
                        .map(|value| value.to_str().unwrap().to_owned());
                    StatusCode::OK
                }
            }))
            .await
        };

        Client::new(
            Config {
                host: url.to_string(),
                timeout: Duration::from_secs(1),
                max_conns: 1,
            },
            stub_auth(Ok("test-token".to_owned())),
        )
        .unwrap()
        .verify(test_request())
        .await
        .1
        .unwrap();

        assert_eq!(seen.lock().unwrap().as_deref(), Some("Bearer test-token"));
        server.abort();
    }

    #[tokio::test]
    async fn verify_classifies_auth_failure_without_calling_the_server() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (url, server) = {
            let calls = Arc::clone(&calls);
            serve(verify_route(move || {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    StatusCode::OK
                }
            }))
            .await
        };

        let (result, error) = Client::new(
            Config {
                host: url.to_string(),
                timeout: Duration::from_secs(1),
                max_conns: 1,
            },
            stub_auth(Err("kms unavailable")),
        )
        .unwrap()
        .verify(test_request())
        .await;

        assert_eq!(result.verdict, Verdict::Error);
        assert_eq!(result.failure, FailureClass::Auth);
        assert!(matches!(error, Err(Error::Auth(_))), "{error:?}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "an unsigned request must never reach the verification service"
        );
        server.abort();
    }

    #[tokio::test]
    async fn client_trims_trailing_slash_from_host() {
        let seen_path = Arc::new(Mutex::new(String::new()));
        let (url, server) = {
            let seen_path = Arc::clone(&seen_path);
            serve(verify_route(move |uri: OriginalUri| {
                let seen_path = Arc::clone(&seen_path);
                async move {
                    *seen_path.lock().unwrap() = uri.path().to_owned();
                    StatusCode::OK
                }
            }))
            .await
        };

        Client::new(
            Config {
                host: format!("{url}/"),
                timeout: Duration::from_secs(1),
                max_conns: 1,
            },
            stub_auth(Ok("test-token".to_owned())),
        )
        .unwrap()
        .verify(test_request())
        .await
        .1
        .unwrap();

        assert_eq!(*seen_path.lock().unwrap(), VERIFY_PATH);
        server.abort();
    }
}
