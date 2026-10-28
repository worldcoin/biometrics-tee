use std::{sync::Arc, time::Duration};

use anyhow::Context;
use aws_config::BehaviorVersion;
use clap::Parser;
use di_migration_enclave_primitives::kms::{self as kms_parent, CREDENTIALS_PORT, TLS_PORT};
use di_migration_host::{
    AppState,
    config::Config,
    enclave::PontifexEnclaveClient,
    job_runner::JobRunner,
    kms_metrics,
    queue::JobQueue,
    readiness::Readiness,
    store::{DynamoJobStore, S3BlobStore},
};
use di_migration_storage::{JobTable, PcpBucket};
use pontifex::{aws_credentials, proxy};

/// Credential and region discovery must not stall startup indefinitely.
const AWS_CONFIG_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut telemetry_config = telemetry_batteries::TelemetryConfig::from_env()
        .map_err(|error| anyhow::anyhow!("failed to load telemetry configuration: {error:?}"))?;
    // The StatsD exporter has no timed flush; sparse job failures must be sent immediately.
    telemetry_config.metrics.statsd.buffer_size = 0;
    // Keep the guard alive until the server stops so buffered spans are flushed.
    let _telemetry = telemetry_batteries::init_with_config(telemetry_config)
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
    let region = aws_config
        .region()
        .context("AWS region is not configured")?;
    let provider = aws_config
        .credentials_provider()
        .context("KMS relay requires a workload credential provider")?;

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
    let job_runner = JobRunner::new(
        Arc::clone(&queue),
        enclave_client.clone(),
        blob_store,
        job_store,
    );
    let state = AppState::new(enclave_client, readiness, queue, config.host_ip);

    let kms_host =
        kms_parent::hostname(region.as_ref()).context("AWS region cannot name a KMS endpoint")?;
    let mut proxy_config = proxy::Config::new(TLS_PORT, kms_host, 443);
    proxy_config.allowed_cid = Some(config.enclave_cid);
    let proxy = proxy::serve(proxy_config, kms_metrics::record_proxy_event);
    let credentials = aws_credentials::router(
        provider,
        config.enclave_cid,
        kms_metrics::record_credentials_result,
    )
    .serve(CREDENTIALS_PORT);

    let server = di_migration_host::server::start(config.port, state, job_runner, drain_timeout);
    // Keep serving the enclave while the HTTP server drains jobs; dropping these
    // futures then closes their connections.
    tokio::select! {
        result = server => result,
        result = proxy => match result {
            Ok(never) => match never {},
            Err(error) => Err(error).context("enclave KMS proxy stopped"),
        },
        result = credentials => {
            result.context("enclave credentials server stopped")?;
            anyhow::bail!("enclave credentials server stopped unexpectedly")
        }
    }
}
