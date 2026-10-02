use std::{sync::Arc, time::Duration};

use anyhow::Context;
use aws_config::BehaviorVersion;
use clap::Parser;
use di_migration_host::{
    AppState,
    config::Config,
    enclave::PontifexEnclaveClient,
    queue::JobQueue,
    readiness::Readiness,
    store::{DynamoJobStore, S3BlobStore},
    worker::Worker,
};
use di_migration_storage::{JobTable, PcpBucket};

/// Credential and region discovery must not stall startup indefinitely.
const AWS_CONFIG_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init()
        .map_err(|error| anyhow::anyhow!("failed to initialize telemetry: {error:?}"))?;

    let config = Config::parse();
    let migrate_timeout = config.enclave_migrate_timeout();
    let drain_timeout = config.drain_timeout();

    // The SDK's standard retry mode applies: bounded attempts with exponential backoff and jitter.
    let aws_config = tokio::time::timeout(
        AWS_CONFIG_TIMEOUT,
        aws_config::load_defaults(BehaviorVersion::latest()),
    )
    .await
    .context("timed out loading AWS configuration")?;
    anyhow::ensure!(
        aws_config.region().is_some(),
        "AWS region is not configured"
    );

    let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
        .force_path_style(config.s3_force_path_style)
        .build();
    let blob_store = Arc::new(S3BlobStore::new(
        PcpBucket::new(aws_sdk_s3::Client::from_conf(s3_config), config.pcp_bucket),
        config.max_pcp_bytes.get(),
    ));
    let job_store = Arc::new(DynamoJobStore::new(JobTable::new(
        aws_sdk_dynamodb::Client::new(&aws_config),
        config.dynamodb_table_name,
    )));
    let enclave_client = Arc::new(PontifexEnclaveClient::new(
        config.enclave_cid,
        config.enclave_port,
        migrate_timeout,
    ));

    let queue = Arc::new(JobQueue::new(config.queue_capacity));
    let readiness = Arc::new(Readiness::new(
        enclave_client.clone(),
        blob_store.clone(),
        job_store.clone(),
    ));
    let worker = Worker::new(
        Arc::clone(&queue),
        enclave_client.clone(),
        blob_store,
        job_store,
    );
    let state = AppState::new(enclave_client, readiness, queue, config.host_ip);

    di_migration_host::server::start(config.port, state, worker, drain_timeout).await
}
