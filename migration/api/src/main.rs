mod attestation;
mod config;
mod db;
mod error;
mod fleet;
mod host_client;
mod routes;

use std::time::Duration;

use anyhow::Context;
use aws_config::BehaviorVersion;
use std::sync::Arc;
use telemetry_batteries::tracing::middleware::TraceLayer;
use tokio::net::TcpListener;

use di_migration_storage::PcpBucket;

use crate::{
    attestation::Attestor,
    db::Db,
    fleet::{DnsResolver, Fleet},
    host_client::HostClient,
};

fn verifier(
    config: &config::Config,
    aws_config: &aws_config::SdkConfig,
) -> anyhow::Result<proof::Verifier> {
    let auth_provider = proof::JwtAuthProvider::new(
        aws_sdk_kms::Client::new(aws_config),
        config.proof_jwt_kms_key_id.clone(),
        config.proof_jwt_subject.clone(),
    )?;

    let client = proof::Client::new(
        proof::Config {
            host: config.proof_verification_host.clone(),
            timeout: Duration::from_secs(config.proof_verify_timeout_secs),
            max_conns: config.proof_max_conns,
        },
        std::sync::Arc::new(auth_provider) as std::sync::Arc<dyn proof::AuthProvider>,
    )?;
    Ok(proof::Verifier::new(
        proof::VerifierConfig {
            max_proof_body_bytes: config.proof_max_proof_body_bytes,
            challenge_type: config.proof_challenge_type.clone(),
        },
        std::sync::Arc::new(client),
    ))
}

#[derive(Clone)]
struct AppState {
    db: Db,
    bucket: PcpBucket,
    /// How long presigned upload URLs stay valid.
    presigned_url_ttl: Duration,
    attestor: Attestor,
    verifier: Arc<proof::Verifier>,
    fleet: Arc<Fleet>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;
    let config = config::Config::from_env()?;
    let aws_config = tokio::time::timeout(
        Duration::from_secs(5),
        aws_config::load_defaults(BehaviorVersion::latest()),
    )
    .await
    .context("timed out loading AWS configuration")?;
    anyhow::ensure!(
        aws_config.region().is_some(),
        "AWS region is not configured"
    );
    let verifier = verifier(&config, &aws_config)?;
    let db = Db::new(
        aws_sdk_dynamodb::Client::new(&aws_config),
        config.dynamodb_table_name,
    );
    let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
        .force_path_style(config.s3_force_path_style)
        .build();
    let bucket = PcpBucket::new(aws_sdk_s3::Client::from_conf(s3_config), config.pcp_bucket);

    if config.stub_attestation {
        tracing::warn!("serving a stub attestation; this build must not handle production traffic");
    }
    let attestor = Attestor::stub(config.enclave_id);

    let poll_interval = Duration::from_secs(config.capacity_poll_interval_secs);
    let fleet = Arc::new(Fleet::new(
        Arc::new(DnsResolver::new(config.host_service, config.host_port)),
        HostClient::new().context("failed to build the host client")?,
        // Three missed polls in a row and the fleet's load counts as unknown.
        poll_interval * 3,
        config.admission_threshold_percent,
    ));
    tokio::spawn(Arc::clone(&fleet).run(poll_interval));

    let state = AppState {
        db,
        bucket,
        presigned_url_ttl: config.presigned_url_ttl,
        attestor,
        verifier: Arc::new(verifier),
        fleet,
    };
    let listener = TcpListener::bind(config.http_addr)
        .await
        .with_context(|| format!("failed to bind HTTP server to {}", config.http_addr))?;
    let internal_listener = TcpListener::bind(config.internal_http_addr)
        .await
        .with_context(|| {
            format!(
                "failed to bind internal HTTP server to {}",
                config.internal_http_addr
            )
        })?;

    // One signal stops both servers; each lets its in-flight requests finish.
    let (stop, _) = tokio::sync::watch::channel(());
    let stopped = |mut receiver: tokio::sync::watch::Receiver<()>| async move {
        let _ = receiver.changed().await;
    };
    let public = axum::serve(
        listener,
        routes::router(state.clone()).layer(TraceLayer::new_for_axum()),
    )
    .with_graceful_shutdown(stopped(stop.subscribe()));
    let internal = axum::serve(
        internal_listener,
        routes::internal_router(state).layer(TraceLayer::new_for_axum()),
    )
    .with_graceful_shutdown(stopped(stop.subscribe()));
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stop.send(());
    });

    let (public, internal) = tokio::join!(public, internal);
    public.context("HTTP server failed")?;
    internal.context("internal HTTP server failed")
}

/// Resolves on the first shutdown signal; SIGTERM too, since that is what drains a pod.
/// In-flight requests then finish before the server exits.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::warn!("received Ctrl-C, shutting down"),
        () = terminate => tracing::warn!("received SIGTERM, shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
        routing::post,
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use di_migration_storage::PcpBucket;

    use crate::{
        AppState, attestation::Attestor, db::Db, fleet::Fleet, host_client::HostClient, routes,
    };

    fn unavailable_db() -> Db {
        let config = aws_sdk_dynamodb::Config::builder()
            .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
            .behavior_version(aws_config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url("http://127.0.0.1:9")
            .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
            .build();
        Db::new(
            aws_sdk_dynamodb::Client::from_conf(config),
            "test-table".to_owned(),
        )
    }

    /// Presigning is offline, so this client signs URLs even though the endpoint is unreachable.
    fn unavailable_bucket() -> PcpBucket {
        let config = aws_sdk_s3::Config::builder()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .behavior_version(aws_config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url("http://127.0.0.1:9")
            .force_path_style(true)
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .build();
        PcpBucket::new(
            aws_sdk_s3::Client::from_conf(config),
            "test-bucket".to_owned(),
        )
    }

    fn accepting_verifier() -> Arc<proof::Verifier> {
        Arc::new(proof::Verifier::new(
            proof::VerifierConfig::default(),
            Arc::new(MockVerifier {
                result: proof::Verdict::Accepted,
                seen: Mutex::new(Vec::new()),
            }),
        ))
    }

    fn unavailable_state() -> AppState {
        AppState {
            db: unavailable_db(),
            bucket: unavailable_bucket(),
            presigned_url_ttl: Duration::from_secs(900),
            attestor: Attestor::stub("i-0123456789abcdef-enc0".to_owned()),
            verifier: accepting_verifier(),
            fleet: Arc::new(Fleet::new(
                Arc::new(NoHosts),
                HostClient::new().unwrap(),
                Duration::from_secs(15),
                70,
            )),
        }
    }

    struct NoHosts;

    #[async_trait]
    impl crate::fleet::Resolver for NoHosts {
        async fn resolve(&self) -> Result<Vec<std::net::SocketAddr>, String> {
            Ok(Vec::new())
        }
    }

    /// Internal routes must not be reachable through the public listener.
    #[tokio::test]
    async fn the_public_router_does_not_serve_internal_routes() {
        let response = routes::router(unavailable_state())
            .oneshot(
                Request::builder()
                    .uri("/internal/capacity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// The scheduler pauses on an error, so an unknown fleet must not read as zero capacity.
    #[tokio::test]
    async fn capacity_is_unavailable_until_the_fleet_is_polled() {
        let response = routes::internal_router(unavailable_state())
            .oneshot(
                Request::builder()
                    .uri("/internal/capacity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(response).await, "capacity_unknown");
    }

    #[tokio::test]
    async fn capacity_reports_the_polled_fleet() {
        let state = unavailable_state();
        state.fleet.refresh().await;

        let response = routes::internal_router(state)
            .oneshot(
                Request::builder()
                    .uri("/internal/capacity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(
            body,
            serde_json::json!({"queued": 0, "capacity": 0, "open_slots": 0})
        );
    }

    #[tokio::test]
    async fn probes_when_dependencies_are_unavailable() {
        for (path, expected) in [
            ("/healthz", StatusCode::OK),
            ("/readyz", StatusCode::SERVICE_UNAVAILABLE),
        ] {
            let response = routes::router(unavailable_state())
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{path}");
        }
    }

    #[tokio::test]
    async fn init_migration_returns_attestation_and_presigned_url() {
        let (address, server) = spawn_put_item_dynamodb().await;
        let state = state_with_db(&address);

        let response = routes::router(state)
            .oneshot(init_migration_request("test-sub"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["enclave_id"], "i-0123456789abcdef-enc0");
        assert_eq!(body["attestation"], "");
        let presigned_url = body["presigned_url"].as_str().unwrap();
        assert!(
            presigned_url.starts_with("http://127.0.0.1:9/test-bucket/pcp/"),
            "{presigned_url}"
        );
        assert!(
            presigned_url.contains("X-Amz-Signature="),
            "{presigned_url}"
        );
        server.abort();
    }

    #[tokio::test]
    async fn init_migration_rejects_a_blank_sub() {
        let response = routes::router(unavailable_state())
            .oneshot(init_migration_request("   "))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(response).await, "invalid_sub");
    }

    #[tokio::test]
    async fn init_migration_reports_a_missing_proof() {
        let response = routes::router(unavailable_state())
            .oneshot(json_request(
                "test-sub",
                "",
                "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31",
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(response).await, "proof_missing");
    }

    #[tokio::test]
    async fn init_migration_reports_a_verification_service_failure() {
        let state = AppState {
            verifier: Arc::new(proof::Verifier::new(
                proof::VerifierConfig::default(),
                Arc::new(FailingVerifier),
            )),
            ..unavailable_state()
        };
        let response = routes::router(state)
            .oneshot(init_migration_request("test-sub"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(response).await, "verification_error");
    }

    #[tokio::test]
    async fn init_migration_verifies_the_ownership_proof() {
        const CHALLENGE_ID: &str = "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31";
        const PROOF: &str = "0xa100ff00deadbeef";
        let mocked = proof::Verdict::Accepted;
        let verifier = Arc::new(MockVerifier {
            result: mocked,
            seen: Mutex::new(Vec::new()),
        });

        let (address, server) = spawn_put_item_dynamodb().await;
        let state = AppState {
            verifier: Arc::new(proof::Verifier::new(
                proof::VerifierConfig::default(),
                Arc::clone(&verifier) as Arc<dyn proof::ProofVerificationClient>,
            )),
            ..state_with_db(&address)
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let api = tokio::spawn(async move {
            axum::serve(listener, routes::router(state)).await.unwrap();
        });

        let response = migration_api_client::MigrationApiClient::new(&api_url)
            .unwrap()
            .init_migration("test-sub", PROOF, CHALLENGE_ID)
            .await
            .unwrap();

        assert_eq!(response.enclave_id, "i-0123456789abcdef-enc0");
        assert!(
            response.presigned_url.contains("X-Amz-Signature="),
            "{}",
            response.presigned_url
        );

        let seen = verifier.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0.challenge_id, CHALLENGE_ID);
        assert_eq!(seen[0].0.challenge_type, proof::DEFAULT_CHALLENGE_TYPE);
        assert_eq!(seen[0].0.credential_sub, "test-sub");
        assert_eq!(seen[0].0.proof, "0xa100ff00deadbeef");
        assert_eq!(seen[0].1, mocked);
        api.abort();
        server.abort();
    }

    #[tokio::test]
    async fn readiness_fails_when_only_the_bucket_is_unavailable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/",
                    post(|| async {
                        (
                            [(header::CONTENT_TYPE, "application/x-amz-json-1.0")],
                            r#"{"Table":{"TableName":"test-table","TableStatus":"ACTIVE"}}"#,
                        )
                    }),
                ),
            )
            .await
            .unwrap();
        });

        let db_config = aws_sdk_dynamodb::Config::builder()
            .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
            .behavior_version(aws_config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(format!("http://{address}"))
            .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
            .build();
        let state = AppState {
            db: Db::new(
                aws_sdk_dynamodb::Client::from_conf(db_config),
                "test-table".to_owned(),
            ),
            ..unavailable_state()
        };
        assert!(state.db.check_ready().await.is_ok());

        let response = routes::router(state)
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        server.abort();
    }

    #[tokio::test]
    async fn a_rejected_proof_is_forbidden() {
        let state = AppState {
            verifier: Arc::new(proof::Verifier::new(
                proof::VerifierConfig::default(),
                Arc::new(MockVerifier {
                    result: proof::Verdict::Rejected,
                    seen: Mutex::new(Vec::new()),
                }),
            )),
            ..unavailable_state()
        };
        let response = routes::router(state)
            .oneshot(init_migration_request("test-sub"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(error_code(response).await, "verification_failed");
    }

    async fn error_code(response: axum::response::Response) -> String {
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        body["error"]["code"].as_str().unwrap().to_owned()
    }

    fn init_migration_request(sub: &str) -> Request<Body> {
        json_request(sub, "YQ==", "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31")
    }

    fn json_request(sub: &str, proof: &str, challenge_id: &str) -> Request<Body> {
        let body = serde_json::json!({
            "sub": sub,
            "proof": proof,
            "challenge_id": challenge_id,
        });
        Request::builder()
            .method("POST")
            .uri("/v1/init-migration")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn spawn_put_item_dynamodb() -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route(
                    "/",
                    post(|| async {
                        ([(header::CONTENT_TYPE, "application/x-amz-json-1.0")], "{}")
                    }),
                ),
            )
            .await
            .unwrap();
        });
        (address, server)
    }

    fn state_with_db(address: &str) -> AppState {
        let db_config = aws_sdk_dynamodb::Config::builder()
            .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
            .behavior_version(aws_config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(format!("http://{address}"))
            .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
            .build();
        AppState {
            db: Db::new(
                aws_sdk_dynamodb::Client::from_conf(db_config),
                "test-table".to_owned(),
            ),
            ..unavailable_state()
        }
    }

    struct FailingVerifier;

    #[async_trait]
    impl proof::ProofVerificationClient for FailingVerifier {
        async fn verify(&self, _request: proof::VerificationRequest) -> proof::Verdict {
            proof::Verdict::Error(proof::FailureClass::Timeout)
        }
    }

    struct MockVerifier {
        result: proof::Verdict,
        seen: Mutex<Vec<(proof::VerificationRequest, proof::Verdict)>>,
    }

    #[async_trait]
    impl proof::ProofVerificationClient for MockVerifier {
        async fn verify(&self, request: proof::VerificationRequest) -> proof::Verdict {
            self.seen.lock().unwrap().push((request, self.result));
            self.result
        }
    }
}
