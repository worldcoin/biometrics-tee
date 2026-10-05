//! The job lifecycle and the upload check against `LocalStack`, which enforces the transaction
//! conditions the unit tests can only assert the shape of.
//!
//! Needs `LocalStack` with S3 and `DynamoDB`, e.g. `docker compose -f migration/api/docker-compose.yml
//! up -d localstack`, then `cargo test -p di-migration-storage --test localstack -- --ignored`.
//! `LOCALSTACK_ENDPOINT` overrides the default `http://localhost:4566`.

use std::net::{IpAddr, Ipv4Addr};

use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
};
use di_migration_primitives::{EnclaveId, JobId, Reason, Status};
use di_migration_storage::{JobTable, NewJob, PcpBucket, StorageError, schema::pcp_key};

const NOW: u64 = 1_800_000_000;

fn endpoint() -> String {
    std::env::var("LOCALSTACK_ENDPOINT").unwrap_or_else(|_| "http://localhost:4566".to_owned())
}

async fn sdk_config() -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
            "test", "test", None, None, "test",
        ))
        .endpoint_url(endpoint())
        .load()
        .await
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", &JobId::new().as_str().replace('-', "")[..16])
}

async fn table() -> (JobTable, aws_sdk_dynamodb::Client, String) {
    let client = aws_sdk_dynamodb::Client::new(&sdk_config().await);
    let name = unique("storage-test");
    client
        .create_table()
        .table_name(&name)
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
    (JobTable::new(client.clone(), name.clone()), client, name)
}

fn new_job(sub: &str, created_at: u64) -> NewJob {
    NewJob {
        job_id: JobId::new(),
        sub: sub.to_owned(),
        device_public_key: "device-key".to_owned(),
        host_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
        enclave_id: EnclaveId::from_commitment([7; 32]),
        created_at,
        active_until: created_at + 420,
        expires_at: created_at + 172_800,
    }
}

#[tokio::test]
#[ignore = "needs LocalStack"]
async fn the_job_lifecycle_honours_the_sub_lock() {
    let (jobs, client, name) = table().await;

    // An init creates the job and takes the lock.
    let first = new_job("sub-a", NOW);
    jobs.create_job(&first)
        .await
        .expect("first job should be created");
    let latest = jobs.latest_job("sub-a").await.expect("read").expect("job");
    assert_eq!(latest.job_id, first.job_id);
    assert_eq!(latest.status, Status::Created);
    assert_eq!(latest.enclave_id, first.enclave_id);

    // A second init for the same sub is refused while the first is active; another sub is not.
    assert_eq!(
        jobs.create_job(&new_job("sub-a", NOW + 1)).await,
        Err(StorageError::ActiveJob)
    );
    jobs.create_job(&new_job("sub-b", NOW + 1))
        .await
        .expect("another sub is independent");

    // Migrate claims it once, and keeps the lock until the deadline.
    let deadline = NOW + 600;
    jobs.claim(&first.job_id, "sub-a", NOW + 60, deadline)
        .await
        .expect("claim should succeed");
    assert_eq!(
        jobs.claim(&first.job_id, "sub-a", NOW + 60, deadline).await,
        Err(StorageError::NotCreated)
    );
    let latest = jobs.latest_job("sub-a").await.expect("read").expect("job");
    assert_eq!(latest.status, Status::Migrating);
    assert_eq!(latest.deadline, Some(deadline));
    assert_eq!(
        jobs.create_job(&new_job("sub-a", NOW + 500)).await,
        Err(StorageError::ActiveJob),
        "the claimed job stays active until its deadline"
    );

    // A failed dispatch fails the job and releases the lock at once.
    jobs.fail_dispatch(&first.job_id, "sub-a", Reason::EnclaveChanged)
        .await
        .expect("dispatch failure should be recorded");
    let latest = jobs.latest_job("sub-a").await.expect("read").expect("job");
    assert_eq!(latest.status, Status::Failed);
    assert_eq!(latest.reason, Some(Reason::EnclaveChanged));

    let retry = new_job("sub-a", NOW + 501);
    jobs.create_job(&retry)
        .await
        .expect("a new init is allowed after a failed dispatch");
    assert_eq!(
        jobs.latest_job("sub-a")
            .await
            .expect("read")
            .expect("job")
            .job_id,
        retry.job_id
    );

    // The superseded job can no longer be claimed or failed through the lock.
    assert_eq!(
        jobs.claim(&first.job_id, "sub-a", NOW + 60, deadline).await,
        Err(StorageError::NotCreated)
    );

    client.delete_table().table_name(&name).send().await.ok();
}

#[tokio::test]
#[ignore = "needs LocalStack"]
async fn an_expired_init_frees_the_lock() {
    let (jobs, client, name) = table().await;

    let abandoned = new_job("sub-c", NOW);
    jobs.create_job(&abandoned).await.expect("created");

    let after_window = new_job("sub-c", abandoned.active_until + 1);
    jobs.create_job(&after_window)
        .await
        .expect("an init past the previous job's active window is allowed");

    client.delete_table().table_name(&name).send().await.ok();
}

#[tokio::test]
#[ignore = "needs LocalStack"]
async fn a_migrate_after_the_upload_window_is_refused() {
    let (jobs, client, name) = table().await;

    let late = new_job("sub-d", NOW);
    jobs.create_job(&late).await.expect("created");

    assert_eq!(
        jobs.claim(&late.job_id, "sub-d", late.active_until + 1, NOW + 900)
            .await,
        Err(StorageError::UploadWindowPassed)
    );
    let latest = jobs.latest_job("sub-d").await.expect("read").expect("job");
    assert_eq!(latest.status, Status::Created);

    jobs.claim(&late.job_id, "sub-d", late.active_until, NOW + 900)
        .await
        .expect("the last second of the window still claims");

    client.delete_table().table_name(&name).send().await.ok();
}

#[tokio::test]
#[ignore = "needs LocalStack"]
async fn the_upload_check_sees_the_sealed_pcp() {
    let config = sdk_config().await;
    let s3 = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::config::Builder::from(&config)
            .force_path_style(true)
            .build(),
    );
    let bucket = unique("storage-test");
    s3.create_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("bucket should be created");
    let pcps = PcpBucket::new(s3.clone(), bucket.clone());
    let job_id = JobId::new();

    assert!(!pcps.pcp_exists(&job_id).await.expect("HEAD should answer"));

    s3.put_object()
        .bucket(&bucket)
        .key(pcp_key(&job_id))
        .body(b"sealed".to_vec().into())
        .send()
        .await
        .expect("upload");
    assert!(pcps.pcp_exists(&job_id).await.expect("HEAD should answer"));

    s3.delete_object()
        .bucket(&bucket)
        .key(pcp_key(&job_id))
        .send()
        .await
        .ok();
    s3.delete_bucket().bucket(&bucket).send().await.ok();
}
