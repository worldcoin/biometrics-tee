//! End-to-end job run against `LocalStack` with an echoing enclave.
//!
//! Needs `LocalStack` with S3 and `DynamoDB`, e.g. `docker compose -f migration/api/docker-compose.yml
//! up -d localstack`, then `cargo test -p di-migration-host --test localstack -- --ignored`.
//! `LOCALSTACK_ENDPOINT` overrides the default `http://localhost:4566`.

use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType,
    ScalarAttributeType,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use di_migration_enclave_types::{KeyAttestation, MigrateRequest, MigrateResponse};
use di_migration_host::{
    AppState,
    enclave::{self, EnclaveClient, Error},
    queue::JobQueue,
    readiness::Readiness,
    routes,
    store::{BlobStore, DynamoJobStore, JobStore, S3BlobStore, StoreError},
    worker::Worker,
};
use di_migration_primitives::{JobId, Reason, host_api::JobRequest};
use di_migration_storage::{JobTable, PcpBucket, schema::pcp_key};
use tower::ServiceExt;

const PUBLIC_KEY: [u8; 32] = [7; 32];

/// Echoes the blob, as the mock enclave does.
struct EchoEnclave;

#[async_trait]
impl EnclaveClient for EchoEnclave {
    async fn health(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn encryption_key(&self) -> Result<KeyAttestation, Error> {
        Ok(KeyAttestation {
            document: Vec::new(),
            public_key: PUBLIC_KEY.to_vec(),
        })
    }

    async fn migrate(&self, request: MigrateRequest) -> Result<MigrateResponse, Error> {
        Ok(MigrateResponse {
            blob: request.blob.to_vec(),
        })
    }
}

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

async fn status(
    dynamodb: &aws_sdk_dynamodb::Client,
    table: &str,
    job_id: &JobId,
) -> Option<String> {
    dynamodb
        .get_item()
        .table_name(table)
        .key("id", AttributeValue::S(format!("job#{job_id}")))
        .consistent_read(true)
        .send()
        .await
        .expect("GetItem should succeed")
        .item?
        .get("status")?
        .as_s()
        .ok()
        .cloned()
}

#[tokio::test]
#[ignore = "needs LocalStack"]
async fn a_dispatched_job_is_migrated_end_to_end() {
    let config = sdk_config().await;
    let s3 = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::from(&config)
            .force_path_style(true)
            .build(),
    );
    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let suffix = JobId::new().as_str().replace('-', "");
    let bucket = format!("host-test-{}", &suffix[..12]);
    let table = format!("host-test-{suffix}");
    let job_id = JobId::new();

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
    s3.put_object()
        .bucket(&bucket)
        .key(format!("pcp/{job_id}"))
        .body(b"sealed-blob".to_vec().into())
        .send()
        .await
        .expect("PCP should upload");
    dynamodb
        .put_item()
        .table_name(&table)
        .item("id", AttributeValue::S(format!("job#{job_id}")))
        .item("status", AttributeValue::S("migrating".to_owned()))
        .send()
        .await
        .expect("row should be written");

    let enclave_client: Arc<dyn EnclaveClient> = Arc::new(EchoEnclave);
    let blob_store = Arc::new(S3BlobStore::new(
        PcpBucket::new(s3.clone(), bucket.clone()),
        1 << 20,
    ));
    let results: Arc<dyn BlobStore> = blob_store.clone();
    let job_store = Arc::new(DynamoJobStore::new(JobTable::new(
        dynamodb.clone(),
        table.clone(),
    )));
    let queue = Arc::new(JobQueue::new(NonZeroUsize::new(4).expect("non-zero")));
    let readiness = Arc::new(Readiness::new(
        Arc::clone(&enclave_client),
        blob_store.clone(),
        job_store.clone(),
    ));
    let worker = Worker::new(
        Arc::clone(&queue),
        Arc::clone(&enclave_client),
        blob_store,
        job_store.clone(),
    );
    let runner = tokio::spawn(worker.run());
    let state = AppState::new(
        enclave_client,
        Arc::clone(&readiness),
        queue,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    );

    assert!(
        readiness.is_ready().await,
        "LocalStack should pass readiness"
    );

    let body = serde_json::to_string(&JobRequest {
        job_id: job_id.clone(),
        object_key: pcp_key(&job_id),
        sub: "sub".to_owned(),
        device_public_key: "device-key".to_owned(),
        enclave_id: enclave::enclave_id(&PUBLIC_KEY),
    })
    .expect("job should serialize");
    let response = routes::handler()
        .with_state(state)
        .oneshot(
            Request::post("/jobs")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .expect("request should build"),
        )
        .await
        .expect("router should answer");
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let migrated = tokio::time::timeout(Duration::from_secs(10), async {
        while status(&dynamodb, &table, &job_id).await.as_deref() != Some("migrated") {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(migrated.is_ok(), "job should be migrated");

    let result = s3
        .get_object()
        .bucket(&bucket)
        .key(format!("result/{job_id}"))
        .send()
        .await
        .expect("result should exist")
        .body
        .collect()
        .await
        .expect("result should read")
        .into_bytes();
    assert_eq!(result.as_ref(), b"sealed-blob");

    // A retried job's second write keeps the first result.
    results
        .put_result(&job_id, b"second-write".to_vec())
        .await
        .expect("a repeated write should succeed");
    let kept = s3
        .get_object()
        .bucket(&bucket)
        .key(format!("result/{job_id}"))
        .send()
        .await
        .expect("result should exist")
        .body
        .collect()
        .await
        .expect("result should read")
        .into_bytes();
    assert_eq!(kept.as_ref(), b"sealed-blob");

    // A late outcome for a resolved job is refused by the row's condition.
    assert_eq!(
        job_store.mark_failed(&job_id, Reason::Timeout).await,
        Err(StoreError::NotMigrating)
    );
    assert_eq!(
        status(&dynamodb, &table, &job_id).await.as_deref(),
        Some("migrated")
    );

    runner.abort();
    s3.delete_object()
        .bucket(&bucket)
        .key(format!("pcp/{job_id}"))
        .send()
        .await
        .ok();
    s3.delete_object()
        .bucket(&bucket)
        .key(format!("result/{job_id}"))
        .send()
        .await
        .ok();
    s3.delete_bucket().bucket(&bucket).send().await.ok();
    dynamodb.delete_table().table_name(&table).send().await.ok();
}
