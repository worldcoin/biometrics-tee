//! Runs the `migration-api` binary against `LocalStack` through init, upload, migrate and status,
//! with a stand-in host that finishes the job the way the real one does.
//!
//! Needs `LocalStack` with S3, `DynamoDB` and KMS, e.g. `docker compose -f
//! migration/api/docker-compose.yml up -d localstack`, then
//! `cargo test -p migration-api --test localstack -- --ignored`.
//! `LOCALSTACK_ENDPOINT` overrides the default `http://localhost:4566`.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::{Child, Command},
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
};
use aws_sdk_kms::types::{KeySpec, KeyUsageType};
use axum::{
    Json, Router,
    http::StatusCode,
    routing::{get, post},
};
use di_migration_primitives::{
    EnclaveId, JobId, Status,
    host_api::{AttestationResponse, Capacity, JobAccepted, JobRequest},
};
use di_migration_storage::{JobTable, PcpBucket};
use migration_api_client::{Error, MigrationApiClient};

const DEVICE_KEY: &str = "device-key";
const CHALLENGE_ID: &str = "0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31";
const PCP: &[u8] = b"sealed pcp";

fn endpoint() -> String {
    std::env::var("LOCALSTACK_ENDPOINT").unwrap_or_else(|_| "http://localhost:4566".to_owned())
}

async fn sdk_config() -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            "test", "test", None, None, "test",
        ))
        .endpoint_url(endpoint())
        .load()
        .await
}

async fn serve(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("should bind");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, router).await });
    address
}

/// A port nothing listens on right now, for the binary to bind.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("should bind")
        .local_addr()
        .expect("address")
        .port()
}

fn enclave_id() -> EnclaveId {
    EnclaveId::from_commitment([7; 32])
}

/// A mock host: reports an empty queue, attests as [`enclave_id`] and records the jobs it is
/// given without running them; the test finishes them itself.
async fn host(jobs: Arc<Mutex<Vec<JobRequest>>>) -> SocketAddr {
    serve(
        Router::new()
            .route(
                "/capacity",
                get(|| async {
                    Json(Capacity {
                        queued: 0,
                        capacity: 16,
                    })
                }),
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
            )
            .route(
                "/jobs",
                post(move |Json(job): Json<JobRequest>| async move {
                    jobs.lock().expect("lock").push(job);
                    (StatusCode::ACCEPTED, Json(JobAccepted::queued()))
                }),
            ),
    )
    .await
}

/// The proof-verification service, accepting every proof.
async fn proof_verification() -> SocketAddr {
    serve(Router::new().route(proof::VERIFY_PATH, post(|| async { StatusCode::OK }))).await
}

/// Kills the API when the test ends, pass or fail.
struct Api(Child);

impl Drop for Api {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Fresh AWS resources, so runs never share state.
struct Resources {
    s3: aws_sdk_s3::Client,
    dynamodb: aws_sdk_dynamodb::Client,
    bucket: String,
    table: String,
    kms_key_id: String,
}

async fn resources(config: &aws_config::SdkConfig) -> Resources {
    let s3 = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::from(config)
            .force_path_style(true)
            .build(),
    );
    let dynamodb = aws_sdk_dynamodb::Client::new(config);
    let suffix = JobId::new().as_str().replace('-', "");
    let bucket = format!("api-test-{}", &suffix[..12]);
    let table = format!("api-test-{suffix}");

    s3.create_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("bucket should be created");
    dynamodb
        .create_table()
        .table_name(&table)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("id")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .expect("definition should build"),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("id")
                .key_type(KeyType::Hash)
                .build()
                .expect("key should build"),
        )
        .send()
        .await
        .expect("table should be created");
    let kms_key_id = aws_sdk_kms::Client::new(config)
        .create_key()
        .key_spec(KeySpec::EccNistP256)
        .key_usage(KeyUsageType::SignVerify)
        .send()
        .await
        .expect("key should be created")
        .key_metadata
        .expect("metadata")
        .key_id;

    Resources {
        s3,
        dynamodb,
        bucket,
        table,
        kms_key_id,
    }
}

impl Resources {
    async fn delete(&self) {
        if let Ok(objects) = self.s3.list_objects_v2().bucket(&self.bucket).send().await {
            for object in objects.contents() {
                if let Some(key) = object.key() {
                    self.s3
                        .delete_object()
                        .bucket(&self.bucket)
                        .key(key)
                        .send()
                        .await
                        .ok();
                }
            }
        }
        self.s3
            .delete_bucket()
            .bucket(&self.bucket)
            .send()
            .await
            .ok();
        self.dynamodb
            .delete_table()
            .table_name(&self.table)
            .send()
            .await
            .ok();
    }
}

/// Starts the binary and waits until it is ready and has polled the host.
async fn start_api(resources: &Resources, host: SocketAddr, proof: SocketAddr) -> (Api, String) {
    let (port, internal_port) = (free_port(), free_port());
    let child = Command::new(env!("CARGO_BIN_EXE_migration-api"))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("AWS_REGION", "us-east-1")
        .env("AWS_ACCESS_KEY_ID", "test")
        .env("AWS_SECRET_ACCESS_KEY", "test")
        .env("AWS_ENDPOINT_URL", endpoint())
        .env("HTTP_ADDR", format!("127.0.0.1:{port}"))
        .env("INTERNAL_HTTP_ADDR", format!("127.0.0.1:{internal_port}"))
        .env("DYNAMODB_TABLE_NAME", &resources.table)
        .env("PCP_BUCKET", &resources.bucket)
        .env("S3_FORCE_PATH_STYLE", "true")
        .env("PROOF_VERIFICATION_HOST", format!("http://{proof}"))
        .env("PROOF_JWT_KMS_KEY_ID", &resources.kms_key_id)
        .env("HOST_SERVICE", host.ip().to_string())
        .env("HOST_PORT", host.port().to_string())
        .env("CAPACITY_POLL_INTERVAL_SECS", "1")
        .spawn()
        .expect("the API should start");
    let api = Api(child);

    let http = reqwest::Client::new();
    let polled = format!("http://127.0.0.1:{internal_port}/internal/capacity");
    let ready = format!("http://127.0.0.1:{port}/readyz");
    for _ in 0..100 {
        let ok = |url: String| {
            let http = http.clone();
            async move {
                http.get(url)
                    .send()
                    .await
                    .is_ok_and(|response| response.status().is_success())
            }
        };
        if ok(ready.clone()).await && ok(polled.clone()).await {
            return (api, format!("http://127.0.0.1:{port}"));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("the API did not become ready");
}

#[tokio::test]
#[ignore = "needs LocalStack"]
async fn a_migration_runs_from_init_to_download() {
    let config = sdk_config().await;
    let resources = resources(&config).await;
    let jobs = Arc::new(Mutex::new(Vec::new()));
    let (_api, base_url) = start_api(
        &resources,
        host(Arc::clone(&jobs)).await,
        proof_verification().await,
    )
    .await;
    let client = MigrationApiClient::new(&base_url.parse().expect("url")).expect("client");
    let sub = format!("sub-{}", JobId::new());

    // Init pins the job to the host's enclave and hands out an upload URL.
    let lost = client
        .init_migration(DEVICE_KEY, &sub, "YQ==", CHALLENGE_ID)
        .await
        .expect("init should succeed");
    assert!(matches!(
        client.init_migration("other-device", &sub, "YQ==", CHALLENGE_ID).await,
        Err(Error::Api { code, .. }) if code == "migration_in_progress"
    ));
    // The same device, e.g. after losing that response, starts over with a new job.
    let init = client
        .init_migration(DEVICE_KEY, &sub, "YQ==", CHALLENGE_ID)
        .await
        .expect("a repeated init replaces the unclaimed job");
    assert_ne!(init.upload_url, lost.upload_url);
    assert_eq!(init.enclave_id, enclave_id());
    assert_eq!(init.enclave_public_key, "enclave-key");

    // Migrate waits for the upload.
    assert!(matches!(
        client.migrate(DEVICE_KEY, &sub).await,
        Err(Error::Api { code, .. }) if code == "not_uploaded"
    ));
    client
        .upload_pcp(&init.upload_url, PCP.to_vec())
        .await
        .expect("upload should succeed");
    let migrating = client
        .migrate(DEVICE_KEY, &sub)
        .await
        .expect("migrate should dispatch");
    assert_eq!(migrating.status, Status::Migrating);
    assert!(matches!(
        client.init_migration(DEVICE_KEY, &sub, "YQ==", CHALLENGE_ID).await,
        Err(Error::Api { code, .. }) if code == "migration_in_progress"
    ));
    let job = {
        let jobs = jobs.lock().expect("lock");
        assert_eq!(jobs.len(), 1, "the job reaches its host once");
        jobs[0].clone()
    };
    assert_eq!(job.enclave_id, enclave_id());
    assert_eq!(job.device_public_key, DEVICE_KEY);
    assert_eq!(
        client
            .migration_status(DEVICE_KEY, &sub)
            .await
            .expect("status")
            .status,
        Status::Migrating
    );

    // The host's side, through the same storage crate: echo the PCP into the result.
    let bucket = PcpBucket::new(resources.s3.clone(), resources.bucket.clone());
    let pcp = bucket
        .get_pcp(&job.object_key, 1 << 20)
        .await
        .expect("the host reads the upload");
    let result_key = bucket
        .put_result(&job.job_id, pcp.to_vec())
        .await
        .expect("the host writes the result");
    JobTable::new(resources.dynamodb.clone(), resources.table.clone())
        .mark_migrated(&job.job_id, &sub, &result_key, job.deadline - 1)
        .await
        .expect("the host marks the job migrated");

    // Status hands out the result, readable only by the right device.
    let done = client
        .migration_status(DEVICE_KEY, &sub)
        .await
        .expect("status");
    assert_eq!(done.status, Status::Migrated);
    let download = reqwest::get(done.download_url.expect("download url"))
        .await
        .expect("download");
    assert_eq!(download.status(), StatusCode::OK);
    assert_eq!(download.bytes().await.expect("body").as_ref(), PCP);
    assert!(matches!(
        client.migration_status("other-device", &sub).await,
        Err(Error::Api { code, .. }) if code == "device_key_mismatch"
    ));

    // The finished job frees the sub, so the app can start another migration at once.
    client
        .init_migration(DEVICE_KEY, &sub, "YQ==", CHALLENGE_ID)
        .await
        .expect("a finished migration no longer blocks init");

    resources.delete().await;
}
