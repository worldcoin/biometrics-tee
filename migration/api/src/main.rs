mod config;
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

use di_migration_storage::{JobTable, PcpBucket};

use crate::{
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
    jobs: JobTable,
    bucket: PcpBucket,
    /// How long presigned upload URLs stay valid.
    presigned_url_ttl: Duration,
    /// How long after init migrate is accepted.
    upload_window: Duration,
    /// How long after migrate an unfinished job counts as timed out.
    job_deadline: Duration,
    /// The port every host serves its internal API on.
    host_port: u16,
    verifier: Arc<proof::Verifier>,
    fleet: Arc<Fleet>,
    hosts: HostClient,
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
    let jobs = JobTable::new(
        aws_sdk_dynamodb::Client::new(&aws_config),
        config.dynamodb_table_name,
    );
    let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
        .force_path_style(config.s3_force_path_style)
        .build();
    let bucket = PcpBucket::new(aws_sdk_s3::Client::from_conf(s3_config), config.pcp_bucket);

    let hosts = HostClient::new().context("failed to build the host client")?;
    let poll_interval = Duration::from_secs(config.capacity_poll_interval_secs);
    let fleet = Arc::new(Fleet::new(
        Arc::new(DnsResolver::new(config.host_service, config.host_port)),
        hosts.clone(),
        // Three missed polls in a row and the fleet's load counts as unknown.
        poll_interval * 3,
        config.admission_threshold_percent,
    ));
    tokio::spawn(Arc::clone(&fleet).run(poll_interval));

    let state = AppState {
        jobs,
        bucket,
        presigned_url_ttl: config.presigned_url_ttl,
        upload_window: Duration::from_secs(config.upload_window_secs),
        job_deadline: Duration::from_secs(config.job_deadline_secs),
        host_port: config.host_port,
        verifier: Arc::new(verifier),
        fleet,
        hosts,
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
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{
        Json, Router,
        body::Body,
        http::{Request, StatusCode, header},
        routing::{get, post},
    };
    use di_migration_primitives::{
        EnclaveId,
        app_api::DEVICE_PUBLIC_KEY_HEADER,
        host_api::{AttestationResponse, Capacity},
    };
    use di_migration_storage::{JobTable, PcpBucket};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::{AppState, fleet::Fleet, host_client::HostClient, routes};

    const CHALLENGE_ID: &str = "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31";
    const AMZ_JSON: &str = "application/x-amz-json-1.0";

    async fn serve(router: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        address
    }

    fn enclave_id() -> EnclaveId {
        EnclaveId::from_commitment([7; 32])
    }

    /// A host reporting `queued` of `capacity` that attests as [`enclave_id`].
    async fn host(queued: usize, capacity: usize) -> SocketAddr {
        serve(
            Router::new()
                .route(
                    "/capacity",
                    get(move || async move { Json(Capacity { queued, capacity }) }),
                )
                .route(
                    "/attestation",
                    get(|| async {
                        Json(AttestationResponse {
                            enclave_id: enclave_id(),
                            attestation: "attestation".to_owned(),
                            enclave_public_key: "enclave-key".to_owned(),
                            host_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        })
                    }),
                ),
        )
        .await
    }

    /// `DynamoDB` that accepts every write and records the request bodies.
    async fn dynamodb(seen: Arc<Mutex<Vec<serde_json::Value>>>) -> SocketAddr {
        serve(Router::new().route(
            "/",
            post(move |body: String| async move {
                seen.lock()
                    .unwrap()
                    .push(serde_json::from_str(&body).unwrap());
                ([(header::CONTENT_TYPE, AMZ_JSON)], "{}")
            }),
        ))
        .await
    }

    /// `DynamoDB` that refuses the lock because the `sub` has an active job.
    /// `DynamoDB` where the `sub` already holds the job `current`: a plain create is refused,
    /// reads serve `current`, and a replacement is accepted and recorded.
    async fn dynamodb_with_active_job(
        current: serde_json::Value,
        replacements: Arc<Mutex<Vec<serde_json::Value>>>,
    ) -> SocketAddr {
        serve(Router::new().route(
            "/",
            post(move |headers: axum::http::HeaderMap, body: String| async move {
                let body: serde_json::Value = serde_json::from_str(&body).unwrap();
                let target = headers["x-amz-target"].to_str().unwrap();
                if target.ends_with("GetItem") {
                    let id = body["Key"]["id"]["S"].as_str().unwrap();
                    let item = if id.starts_with("sub#") {
                        serde_json::json!({"id": {"S": id}, "job_id": {"S": JOB_ID}, "active_until": {"N": "0"}})
                    } else {
                        current.clone()
                    };
                    return (StatusCode::OK, [(header::CONTENT_TYPE, AMZ_JSON)], serde_json::json!({"Item": item}).to_string());
                }
                if body["TransactItems"].as_array().unwrap().len() == 2 {
                    return (
                        StatusCode::BAD_REQUEST,
                        [(header::CONTENT_TYPE, AMZ_JSON)],
                        r#"{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","message":"canceled","CancellationReasons":[{"Code":"None"},{"Code":"ConditionalCheckFailed"}]}"#.to_owned(),
                    );
                }
                replacements.lock().unwrap().push(body);
                (StatusCode::OK, [(header::CONTENT_TYPE, AMZ_JSON)], "{}".to_owned())
            }),
        ))
        .await
    }

    fn job_table(endpoint: &str) -> JobTable {
        let config = aws_sdk_dynamodb::Config::builder()
            .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
            .behavior_version(aws_config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(endpoint)
            .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
            .build();
        JobTable::new(
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

    fn verifier(verdict: proof::Verdict) -> Arc<proof::Verifier> {
        Arc::new(proof::Verifier::new(
            proof::VerifierConfig::default(),
            Arc::new(MockVerifier {
                result: verdict,
                seen: Mutex::new(Vec::new()),
            }),
        ))
    }

    struct Fixed(Vec<SocketAddr>);

    #[async_trait]
    impl crate::fleet::Resolver for Fixed {
        async fn resolve(&self) -> Result<Vec<SocketAddr>, String> {
            Ok(self.0.clone())
        }
    }

    fn fleet(hosts: Vec<SocketAddr>) -> Arc<Fleet> {
        Arc::new(Fleet::new(
            Arc::new(Fixed(hosts)),
            HostClient::new().unwrap(),
            Duration::from_secs(15),
            70,
        ))
    }

    /// Every dependency unreachable and an unpolled, empty fleet.
    fn unavailable_state() -> AppState {
        AppState {
            jobs: job_table("http://127.0.0.1:9"),
            bucket: unavailable_bucket(),
            presigned_url_ttl: Duration::from_secs(300),
            upload_window: Duration::from_secs(420),
            job_deadline: Duration::from_secs(600),
            host_port: 9,
            verifier: verifier(proof::Verdict::Accepted),
            fleet: fleet(Vec::new()),
            hosts: HostClient::new().unwrap(),
        }
    }

    /// A polled fleet of `hosts` and a `DynamoDB` at `dynamodb`.
    async fn state(hosts: Vec<SocketAddr>, dynamodb: SocketAddr) -> AppState {
        let state = AppState {
            jobs: job_table(&format!("http://{dynamodb}")),
            fleet: fleet(hosts),
            ..unavailable_state()
        };
        state.fleet.refresh().await;
        state
    }

    fn init_request(device_key: Option<&str>, sub: &str, proof: &str) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/init-migration")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(key) = device_key {
            request = request.header(DEVICE_PUBLIC_KEY_HEADER, key);
        }
        request
            .body(Body::from(
                serde_json::json!({"sub": sub, "proof": proof, "challenge_id": CHALLENGE_ID})
                    .to_string(),
            ))
            .unwrap()
    }

    fn valid_init() -> Request<Body> {
        init_request(Some("device-key"), "test-sub", "YQ==")
    }

    async fn json(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    async fn error_code(response: axum::response::Response) -> String {
        json(response).await["error"]["code"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn init_admits_places_and_pins_the_job() {
        let host = host(0, 4).await;
        let writes = Arc::new(Mutex::new(Vec::new()));
        let state = state(vec![host], dynamodb(Arc::clone(&writes)).await).await;

        let response = routes::router(state).oneshot(valid_init()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["enclave_id"], enclave_id().as_str());
        assert_eq!(body["attestation"], "attestation");
        assert_eq!(body["enclave_public_key"], "enclave-key");
        let upload_url = body["upload_url"].as_str().unwrap();
        assert!(
            upload_url.starts_with("http://127.0.0.1:9/test-bucket/pcp/")
                && upload_url.contains("X-Amz-Signature="),
            "{upload_url}"
        );

        let writes = writes.lock().unwrap();
        assert_eq!(writes.len(), 1, "one transaction: job row and lock");
        let job = &writes[0]["TransactItems"][0]["Put"]["Item"];
        assert_eq!(job["device_public_key"]["S"], "device-key");
        assert_eq!(job["host_ip"]["S"], "127.0.0.1");
        assert_eq!(job["enclave_id"]["S"], enclave_id().as_str());
        let lock = &writes[0]["TransactItems"][1]["Put"]["Item"];
        let created_at: u64 = job["created_at"]["N"].as_str().unwrap().parse().unwrap();
        let active_until: u64 = lock["active_until"]["N"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            active_until,
            created_at + 420,
            "the lock lasts the upload window"
        );
        assert_eq!(body["migrate_by"], active_until);
    }

    #[tokio::test]
    async fn init_without_a_device_key_is_rejected() {
        let response = routes::router(unavailable_state())
            .oneshot(init_request(None, "test-sub", "YQ=="))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(response).await, "invalid_device_key");
    }

    /// Hosts at the admission threshold take no jobs; the app backs off for a jittered while.
    #[tokio::test]
    async fn a_full_fleet_answers_at_capacity() {
        let state = state(vec![host(3, 4).await], dynamodb(Arc::default()).await).await;

        let response = routes::router(state).oneshot(valid_init()).await.unwrap();

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = response.headers()[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((30..=60).contains(&retry_after), "{retry_after}");
        assert_eq!(error_code(response).await, "at_capacity");
    }

    #[tokio::test]
    async fn an_unknown_fleet_admits_nothing() {
        let response = routes::router(unavailable_state())
            .oneshot(valid_init())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(response).await, "capacity_unknown");
    }

    #[tokio::test]
    async fn a_second_init_for_a_running_or_foreign_job_is_in_progress() {
        let mut foreign = job_row("created", now(), &[]);
        foreign["device_public_key"] = serde_json::json!({"S": "other-device"});
        for current in [job_row("migrating", now(), &[]), foreign] {
            let replacements = Arc::new(Mutex::new(Vec::new()));
            let dynamodb = dynamodb_with_active_job(current, Arc::clone(&replacements)).await;
            let state = state(vec![host(0, 4).await], dynamodb).await;

            let response = routes::router(state).oneshot(valid_init()).await.unwrap();

            assert_eq!(response.status(), StatusCode::CONFLICT);
            assert_eq!(error_code(response).await, "migration_in_progress");
            assert!(replacements.lock().unwrap().is_empty());
        }
    }

    /// An app that lost its init response, or never uploaded, starts over with a new job.
    #[tokio::test]
    async fn a_second_init_replaces_the_device_s_unclaimed_job() {
        let replacements = Arc::new(Mutex::new(Vec::new()));
        let dynamodb =
            dynamodb_with_active_job(job_row("created", now(), &[]), Arc::clone(&replacements))
                .await;
        let state = state(vec![host(0, 4).await], dynamodb).await;

        let response = routes::router(state).oneshot(valid_init()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(json(response).await["upload_url"].is_string());
        let replacements = replacements.lock().unwrap();
        assert_eq!(replacements.len(), 1);
        let lock = &replacements[0]["TransactItems"][1]["Put"];
        assert_eq!(lock["ExpressionAttributeValues"][":previous"]["S"], JOB_ID);
    }

    /// The host was polled but stops answering before init asks it to attest.
    #[tokio::test]
    async fn a_silent_host_fails_init_before_any_write() {
        let only_capacity = serve(Router::new().route(
            "/capacity",
            get(|| async {
                Json(Capacity {
                    queued: 0,
                    capacity: 4,
                })
            }),
        ))
        .await;
        let writes = Arc::new(Mutex::new(Vec::new()));
        let state = state(vec![only_capacity], dynamodb(Arc::clone(&writes)).await).await;

        let response = routes::router(state).oneshot(valid_init()).await.unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn init_rejects_a_blank_sub() {
        let response = routes::router(unavailable_state())
            .oneshot(init_request(Some("device-key"), "   ", "YQ=="))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(response).await, "invalid_sub");
    }

    #[tokio::test]
    async fn init_reports_a_missing_proof() {
        let response = routes::router(unavailable_state())
            .oneshot(init_request(Some("device-key"), "test-sub", ""))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(response).await, "proof_missing");
    }

    #[tokio::test]
    async fn init_reports_a_verification_service_failure() {
        let state = AppState {
            verifier: Arc::new(proof::Verifier::new(
                proof::VerifierConfig::default(),
                Arc::new(FailingVerifier),
            )),
            ..unavailable_state()
        };
        let response = routes::router(state).oneshot(valid_init()).await.unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(error_code(response).await, "verification_error");
    }

    #[tokio::test]
    async fn a_rejected_proof_is_forbidden() {
        let state = AppState {
            verifier: verifier(proof::Verdict::Rejected),
            ..unavailable_state()
        };
        let response = routes::router(state).oneshot(valid_init()).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(error_code(response).await, "verification_failed");
    }

    /// The client sends the proof fields and the device key header the API expects.
    #[tokio::test]
    async fn the_client_round_trips_init() {
        let mock = Arc::new(MockVerifier {
            result: proof::Verdict::Accepted,
            seen: Mutex::new(Vec::new()),
        });
        let state = AppState {
            verifier: Arc::new(proof::Verifier::new(
                proof::VerifierConfig::default(),
                Arc::clone(&mock) as Arc<dyn proof::ProofVerificationClient>,
            )),
            ..state(vec![host(0, 4).await], dynamodb(Arc::default()).await).await
        };
        let api = serve(routes::router(state)).await;

        let response = migration_api_client::MigrationApiClient::new(
            &format!("http://{api}").parse().unwrap(),
        )
        .unwrap()
        .init_migration("device-key", "test-sub", "0xa100ff00deadbeef", CHALLENGE_ID)
        .await
        .unwrap();

        assert_eq!(response.enclave_id, enclave_id());
        let seen = mock.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0.challenge_id, CHALLENGE_ID);
        assert_eq!(seen[0].0.challenge_type, proof::DEFAULT_CHALLENGE_TYPE);
        assert_eq!(seen[0].0.credential_sub, "test-sub");
        assert_eq!(seen[0].0.proof, "0xa100ff00deadbeef");
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
        let state = state(vec![host(1, 4).await], dynamodb(Arc::default()).await).await;

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
        assert_eq!(
            json(response).await,
            serde_json::json!({"queued": 1, "capacity": 4, "open_slots": 2})
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
    async fn readiness_fails_when_only_the_bucket_is_unavailable() {
        let table = serve(Router::new().route(
            "/",
            post(|| async {
                (
                    [(header::CONTENT_TYPE, AMZ_JSON)],
                    r#"{"Table":{"TableName":"test-table","TableStatus":"ACTIVE"}}"#,
                )
            }),
        ))
        .await;
        let state = AppState {
            jobs: job_table(&format!("http://{table}")),
            ..unavailable_state()
        };
        assert!(state.jobs.check_ready().await.is_ok());

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

    /// The stored job the fake table serves, and every write it receives.
    #[derive(Default)]
    struct Table {
        job: Option<serde_json::Value>,
        writes: Vec<serde_json::Value>,
    }

    const JOB_ID: &str = "3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A job row as `DynamoDB` returns it.
    fn job_row(
        status: &str,
        created_at: u64,
        extra: &[(&str, serde_json::Value)],
    ) -> serde_json::Value {
        let mut row = serde_json::json!({
            "id": {"S": format!("job#{JOB_ID}")},
            "status": {"S": status},
            "device_public_key": {"S": "device-key"},
            "host_ip": {"S": "127.0.0.1"},
            "enclave_id": {"S": enclave_id().as_str()},
            "created_at": {"N": created_at.to_string()},
        });
        for (key, value) in extra {
            row[*key] = value.clone();
        }
        row
    }

    /// `DynamoDB` serving the `sub`'s lock and `table.job`, and accepting every transaction.
    async fn job_dynamodb(table: Arc<Mutex<Table>>) -> SocketAddr {
        serve(Router::new().route(
            "/",
            post(
                move |headers: axum::http::HeaderMap, body: String| async move {
                    let body: serde_json::Value = serde_json::from_str(&body).unwrap();
                    let target = headers["x-amz-target"].to_str().unwrap().to_owned();
                    let mut table = table.lock().unwrap();
                    let reply = if target.ends_with("GetItem") {
                        let id = body["Key"]["id"]["S"].as_str().unwrap();
                        match (&table.job, id.starts_with("sub#")) {
                            (None, _) => serde_json::json!({}),
                            (Some(_), true) => serde_json::json!({"Item": {
                                "id": {"S": id},
                                "job_id": {"S": JOB_ID},
                                "active_until": {"N": "0"},
                            }}),
                            (Some(job), false) => serde_json::json!({"Item": job}),
                        }
                    } else {
                        table.writes.push(body);
                        serde_json::json!({})
                    };
                    ([(header::CONTENT_TYPE, AMZ_JSON)], reply.to_string())
                },
            ),
        ))
        .await
    }

    /// S3 answering every `HEAD` with `status`.
    async fn s3(status: StatusCode) -> SocketAddr {
        serve(Router::new().fallback(move || async move { status })).await
    }

    fn bucket(endpoint: SocketAddr) -> PcpBucket {
        let config = aws_sdk_s3::Config::builder()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .behavior_version(aws_config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .endpoint_url(format!("http://{endpoint}"))
            .force_path_style(true)
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .build();
        PcpBucket::new(
            aws_sdk_s3::Client::from_conf(config),
            "test-bucket".to_owned(),
        )
    }

    /// A host whose `/jobs` answers `status` with error `code`, recording each request.
    async fn jobs_host(
        status: StatusCode,
        code: &'static str,
        seen: Arc<Mutex<Vec<serde_json::Value>>>,
    ) -> SocketAddr {
        serve(Router::new().route(
            "/jobs",
            post(move |Json(body): Json<serde_json::Value>| async move {
                seen.lock().unwrap().push(body);
                (
                    status,
                    Json(serde_json::json!({
                        "allowRetry": false,
                        "error": {"code": code, "message": ""},
                    })),
                )
            }),
        ))
        .await
    }

    /// State for one stored `job`, an S3 answering uploads with `uploaded`, and a host.
    async fn migration_state(
        job: Option<serde_json::Value>,
        uploaded: StatusCode,
        host: SocketAddr,
    ) -> (AppState, Arc<Mutex<Table>>) {
        let table = Arc::new(Mutex::new(Table {
            job,
            writes: Vec::new(),
        }));
        let state = AppState {
            jobs: job_table(&format!(
                "http://{}",
                job_dynamodb(Arc::clone(&table)).await
            )),
            bucket: bucket(s3(uploaded).await),
            host_port: host.port(),
            ..unavailable_state()
        };
        (state, table)
    }

    fn migrations_request(method: &str, device_key: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri("/v1/migrations/test-sub")
            .header(DEVICE_PUBLIC_KEY_HEADER, device_key)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn migrate_claims_then_dispatches_the_uploaded_job() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let host = jobs_host(StatusCode::ACCEPTED, "", Arc::clone(&seen)).await;
        let (state, table) =
            migration_state(Some(job_row("created", now(), &[])), StatusCode::OK, host).await;

        let response = routes::router(state)
            .oneshot(migrations_request("POST", "device-key"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = json(response).await;
        assert_eq!(body["status"], "migrating");
        let deadline = body["deadline"].as_u64().unwrap();
        assert!(deadline >= now() + 599, "{deadline}");

        let table = table.lock().unwrap();
        assert_eq!(table.writes.len(), 1, "only the claim");
        let claim = &table.writes[0]["TransactItems"][0]["Update"];
        assert_eq!(
            claim["ExpressionAttributeValues"][":deadline"]["N"],
            deadline.to_string()
        );

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0]["job_id"], JOB_ID);
        assert_eq!(seen[0]["object_key"], format!("pcp/{JOB_ID}"));
        assert_eq!(seen[0]["sub"], "test-sub");
        assert_eq!(seen[0]["device_public_key"], "device-key");
        assert_eq!(seen[0]["enclave_id"], enclave_id().as_str());
    }

    #[tokio::test]
    async fn migrate_refuses_jobs_it_must_not_start() {
        let host = jobs_host(StatusCode::ACCEPTED, "", Arc::default()).await;
        let cases = [
            (
                "no job",
                None,
                StatusCode::OK,
                "device-key",
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                "another device",
                Some(job_row("created", now(), &[])),
                StatusCode::OK,
                "other-key",
                StatusCode::FORBIDDEN,
                "device_key_mismatch",
            ),
            (
                "not uploaded",
                Some(job_row("created", now(), &[])),
                StatusCode::NOT_FOUND,
                "device-key",
                StatusCode::CONFLICT,
                "not_uploaded",
            ),
            (
                "upload window passed",
                Some(job_row("created", now() - 421, &[])),
                StatusCode::OK,
                "device-key",
                StatusCode::CONFLICT,
                "expired",
            ),
            (
                "already migrated",
                Some(job_row("migrated", now(), &[])),
                StatusCode::OK,
                "device-key",
                StatusCode::CONFLICT,
                "invalid_state",
            ),
            (
                "already failed",
                Some(job_row(
                    "failed",
                    now(),
                    &[("reason", serde_json::json!({"S": "enclave_error"}))],
                )),
                StatusCode::OK,
                "device-key",
                StatusCode::CONFLICT,
                "enclave_error",
            ),
        ];

        for (case, job, uploaded, device_key, status, code) in cases {
            let (state, table) = migration_state(job, uploaded, host).await;
            let response = routes::router(state)
                .oneshot(migrations_request("POST", device_key))
                .await
                .unwrap();

            assert_eq!(response.status(), status, "{case}");
            assert_eq!(error_code(response).await, code, "{case}");
            assert!(table.lock().unwrap().writes.is_empty(), "{case}");
        }
    }

    /// A retried migrate reports the running job instead of starting it again.
    #[tokio::test]
    async fn a_repeated_migrate_reports_the_running_job() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let host = jobs_host(StatusCode::ACCEPTED, "", Arc::clone(&seen)).await;
        let deadline = now() + 300;
        let row = job_row(
            "migrating",
            now(),
            &[("deadline", serde_json::json!({"N": deadline.to_string()}))],
        );
        let (state, table) = migration_state(Some(row), StatusCode::OK, host).await;

        let response = routes::router(state)
            .oneshot(migrations_request("POST", "device-key"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(json(response).await["deadline"], deadline);
        assert!(table.lock().unwrap().writes.is_empty());
        assert!(seen.lock().unwrap().is_empty());
    }

    /// A host that refuses or is gone fails the job with the matching reason and frees the `sub`.
    #[tokio::test]
    async fn a_failed_dispatch_fails_the_job() {
        let unreachable: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let cases = [
            (
                jobs_host(StatusCode::CONFLICT, "enclave_changed", Arc::default()).await,
                "enclave_changed",
            ),
            (
                jobs_host(StatusCode::SERVICE_UNAVAILABLE, "host_busy", Arc::default()).await,
                "host_busy",
            ),
            (unreachable, "enclave_changed"),
        ];

        for (host, reason) in cases {
            let (state, table) =
                migration_state(Some(job_row("created", now(), &[])), StatusCode::OK, host).await;
            let response = routes::router(state)
                .oneshot(migrations_request("POST", "device-key"))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::CONFLICT, "{reason}");
            assert_eq!(error_code(response).await, reason);
            let table = table.lock().unwrap();
            assert_eq!(table.writes.len(), 2, "claim, then fail_dispatch");
            let failed = &table.writes[1]["TransactItems"];
            assert_eq!(
                failed[0]["Update"]["ExpressionAttributeValues"][":reason"]["S"],
                reason
            );
            assert_eq!(
                failed[1]["Update"]["ExpressionAttributeValues"][":active_until"]["N"],
                "0"
            );
        }
    }

    #[tokio::test]
    async fn status_resolves_the_job_on_read() {
        let host: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let past = now() - 1;
        let cases = [
            (
                job_row("created", now(), &[]),
                serde_json::json!({"status": "created"}),
            ),
            (
                job_row(
                    "migrating",
                    now(),
                    &[("deadline", serde_json::json!({"N": past.to_string()}))],
                ),
                serde_json::json!({"status": "failed", "reason": "timeout", "deadline": past}),
            ),
            (
                job_row(
                    "failed",
                    now(),
                    &[("reason", serde_json::json!({"S": "host_busy"}))],
                ),
                serde_json::json!({"status": "failed", "reason": "host_busy"}),
            ),
        ];

        for (row, expected) in cases {
            let (state, table) = migration_state(Some(row), StatusCode::OK, host).await;
            let response = routes::router(state)
                .oneshot(migrations_request("GET", "device-key"))
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(json(response).await, expected);
            assert!(table.lock().unwrap().writes.is_empty(), "reads never write");
        }
    }

    #[tokio::test]
    async fn a_migrated_job_carries_a_fresh_download_url() {
        let host: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let row = job_row(
            "migrated",
            now(),
            &[(
                "result_key",
                serde_json::json!({"S": format!("result/{JOB_ID}")}),
            )],
        );
        let (state, _) = migration_state(Some(row), StatusCode::OK, host).await;

        let response = routes::router(state)
            .oneshot(migrations_request("GET", "device-key"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = json(response).await;
        assert_eq!(body["status"], "migrated");
        let url = body["download_url"].as_str().unwrap();
        assert!(
            url.contains(&format!("/test-bucket/result/{JOB_ID}")),
            "{url}"
        );
        assert!(body["download_expires_at"].as_u64().unwrap() >= now() + 299);
    }

    #[tokio::test]
    async fn status_needs_the_job_s_device_key() {
        let host: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let (state, _) =
            migration_state(Some(job_row("created", now(), &[])), StatusCode::OK, host).await;

        let response = routes::router(state)
            .oneshot(migrations_request("GET", "other-key"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// The client's migrate and status calls match the routes.
    #[tokio::test]
    async fn the_client_round_trips_migrate_and_status() {
        let host = jobs_host(StatusCode::ACCEPTED, "", Arc::default()).await;
        let (state, _) =
            migration_state(Some(job_row("created", now(), &[])), StatusCode::OK, host).await;
        let api = serve(routes::router(state)).await;
        let client = migration_api_client::MigrationApiClient::new(
            &format!("http://{api}").parse().unwrap(),
        )
        .unwrap();

        let migrating = client.migrate("device-key", "test-sub").await.unwrap();
        // The fake table keeps serving the `created` row.
        let status = client
            .migration_status("device-key", "test-sub")
            .await
            .unwrap();

        assert_eq!(migrating.status, di_migration_primitives::Status::Migrating);
        assert_eq!(status.status, di_migration_primitives::Status::Created);
        assert!(matches!(
            client.migration_status("other-key", "test-sub").await,
            Err(migration_api_client::Error::Api { code, .. }) if code == "device_key_mismatch"
        ));
    }
}
