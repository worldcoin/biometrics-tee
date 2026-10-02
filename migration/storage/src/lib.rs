//! The PCP bucket, shared by the Migration API (presigned upload and download) and the host
//! (reading sealed PCPs, writing results), so both use the same keys and limits.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

use std::time::Duration;

use aws_sdk_s3::{
    Client, error::DisplayErrorContext, presigning::PresigningConfig, primitives::ByteStream,
};
use bytes::Bytes;
use di_migration_jobs::{pcp_key, result_key};
use tokio::time::timeout;

/// Readiness must not hang behind a slow S3.
const READINESS_TIMEOUT: Duration = Duration::from_secs(3);

/// Sized for a PCP of tens of MiB within the region.
const OBJECT_TIMEOUT: Duration = Duration::from_secs(60);

/// S3 answers a conditional write with this status when the object already exists.
const PRECONDITION_FAILED: u16 = 412;

/// Failures talking to the bucket.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    /// The call did not finish within its deadline.
    #[error("{operation} timed out")]
    Timeout {
        /// The S3 operation, e.g. `S3 GetObject`.
        operation: &'static str,
    },
    /// The call failed.
    #[error("{operation} failed: {detail}")]
    Failed {
        /// The S3 operation, e.g. `S3 GetObject`.
        operation: &'static str,
        /// The SDK's error, with its source chain.
        detail: String,
    },
    /// The object exceeds the size the caller will buffer.
    #[error("object exceeds the {limit} byte limit")]
    TooLarge {
        /// The ceiling that was exceeded.
        limit: usize,
    },
}

/// The bucket holding sealed PCPs under `pcp/` and migrated results under `result/`.
#[derive(Debug, Clone)]
pub struct PcpBucket {
    client: Client,
    bucket: String,
}

impl PcpBucket {
    /// Wraps `client` for `bucket`; the caller owns client configuration such as path style.
    #[must_use]
    pub const fn new(client: Client, bucket: String) -> Self {
        Self { client, bucket }
    }

    /// Checks the bucket is reachable.
    ///
    /// # Errors
    ///
    /// `HeadBucket` timed out or failed.
    pub async fn check_ready(&self) -> Result<(), StorageError> {
        const OPERATION: &str = "S3 HeadBucket";
        timeout(
            READINESS_TIMEOUT,
            self.client.head_bucket().bucket(&self.bucket).send(),
        )
        .await
        .map_err(|_| StorageError::Timeout {
            operation: OPERATION,
        })?
        .map_err(|error| failed(OPERATION, &error))?;
        Ok(())
    }

    /// A URL the app `PUT`s its sealed PCP to. Signing is local, so this makes no network call.
    ///
    /// # Errors
    ///
    /// `ttl` is not a valid presigning expiry.
    pub async fn presign_upload(
        &self,
        job_id: &str,
        ttl: Duration,
    ) -> Result<String, StorageError> {
        const OPERATION: &str = "S3 presign PutObject";
        let config =
            PresigningConfig::expires_in(ttl).map_err(|error| failed(OPERATION, &error))?;
        Ok(self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(pcp_key(job_id))
            .presigned(config)
            .await
            .map_err(|error| failed(OPERATION, &error))?
            .uri()
            .to_owned())
    }

    /// A URL the app `GET`s the migrated PCP from. Signing is local, so this makes no network call.
    ///
    /// # Errors
    ///
    /// `ttl` is not a valid presigning expiry.
    pub async fn presign_download(
        &self,
        job_id: &str,
        ttl: Duration,
    ) -> Result<String, StorageError> {
        const OPERATION: &str = "S3 presign GetObject";
        let config =
            PresigningConfig::expires_in(ttl).map_err(|error| failed(OPERATION, &error))?;
        Ok(self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(result_key(job_id))
            .presigned(config)
            .await
            .map_err(|error| failed(OPERATION, &error))?
            .uri()
            .to_owned())
    }

    /// Reads the sealed PCP at `object_key`, refusing objects larger than `max_bytes`.
    ///
    /// # Errors
    ///
    /// `GetObject` timed out or failed, or the object exceeds `max_bytes`.
    pub async fn get_pcp(&self, object_key: &str, max_bytes: usize) -> Result<Bytes, StorageError> {
        const OPERATION: &str = "S3 GetObject";
        let too_large = |bytes: u64| bytes > max_bytes as u64;

        let output = timeout(
            OBJECT_TIMEOUT,
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(object_key)
                .send(),
        )
        .await
        .map_err(|_| StorageError::Timeout {
            operation: OPERATION,
        })?
        .map_err(|error| failed(OPERATION, &error))?;

        // Checked before buffering, so an oversized object is never read into memory.
        let declared = output
            .content_length()
            .map_or(0, |length| u64::try_from(length).unwrap_or(u64::MAX));
        if too_large(declared) {
            return Err(StorageError::TooLarge { limit: max_bytes });
        }

        let body = timeout(OBJECT_TIMEOUT, output.body.collect())
            .await
            .map_err(|_| StorageError::Timeout {
                operation: OPERATION,
            })?
            .map_err(|error| StorageError::Failed {
                operation: OPERATION,
                detail: error.to_string(),
            })?
            .into_bytes();
        if too_large(body.len() as u64) {
            return Err(StorageError::TooLarge { limit: max_bytes });
        }

        Ok(body)
    }

    /// Writes the migrated PCP once; a result already there is kept. Returns its key.
    ///
    /// # Errors
    ///
    /// `PutObject` timed out or failed for any reason other than an existing result.
    pub async fn put_result(&self, job_id: &str, blob: Vec<u8>) -> Result<String, StorageError> {
        const OPERATION: &str = "S3 PutObject";
        let key = result_key(job_id);
        let result = timeout(
            OBJECT_TIMEOUT,
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(&key)
                .if_none_match("*")
                .body(ByteStream::from(blob))
                .send(),
        )
        .await
        .map_err(|_| StorageError::Timeout {
            operation: OPERATION,
        })?;

        match result {
            Ok(_) => Ok(key),
            // A retried job already wrote its result; the first one stands.
            Err(error)
                if error
                    .raw_response()
                    .map(|response| response.status().as_u16())
                    == Some(PRECONDITION_FAILED) =>
            {
                Ok(key)
            }
            Err(error) => Err(failed(OPERATION, &error)),
        }
    }
}

fn failed(operation: &'static str, error: &impl std::error::Error) -> StorageError {
    StorageError::Failed {
        operation,
        detail: DisplayErrorContext(error).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{
        Router,
        http::{StatusCode, header},
        routing::{get, put},
    };

    use super::{PcpBucket, StorageError};

    /// Serves `router` on a loopback port and returns its base URL.
    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should bind a loopback port");
        let address = listener.local_addr().expect("should have an address");
        tokio::spawn(async move { axum::serve(listener, router).await });
        format!("http://{address}")
    }

    /// A bucket against `endpoint` with retries off, so failures surface at once.
    fn bucket(endpoint: &str) -> PcpBucket {
        let client = aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::Config::builder()
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .behavior_version(aws_config::BehaviorVersion::latest())
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "test", "test", None, None, "test",
                ))
                .endpoint_url(endpoint)
                .force_path_style(true)
                .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
                .build(),
        );
        PcpBucket::new(client, "pcp-bucket".to_owned())
    }

    #[tokio::test]
    async fn presigned_urls_target_the_shared_keys() {
        let bucket = bucket("http://127.0.0.1:9");
        let ttl = Duration::from_secs(300);

        let upload = bucket
            .presign_upload("job", ttl)
            .await
            .expect("should sign");
        let download = bucket
            .presign_download("job", ttl)
            .await
            .expect("should sign");

        assert!(
            upload.starts_with("http://127.0.0.1:9/pcp-bucket/pcp/job?"),
            "{upload}"
        );
        assert!(
            download.starts_with("http://127.0.0.1:9/pcp-bucket/result/job?"),
            "{download}"
        );
        assert!(upload.contains("X-Amz-Signature="), "{upload}");
    }

    #[tokio::test]
    async fn a_pcp_within_the_limit_is_returned() {
        let address =
            serve(Router::new().route("/pcp-bucket/pcp/job", get(|| async { b"sealed".to_vec() })))
                .await;

        let blob = bucket(&address)
            .get_pcp("pcp/job", 16)
            .await
            .expect("should read");

        assert_eq!(blob.as_ref(), b"sealed");
    }

    /// The declared length is checked before the body is read.
    #[tokio::test]
    async fn an_oversized_pcp_is_refused() {
        let address =
            serve(Router::new().route("/pcp-bucket/pcp/job", get(|| async { vec![0u8; 17] })))
                .await;

        let error = bucket(&address)
            .get_pcp("pcp/job", 16)
            .await
            .expect_err("should refuse");

        assert_eq!(error, StorageError::TooLarge { limit: 16 });
    }

    #[tokio::test]
    async fn a_missing_pcp_is_a_failed_read() {
        let address = serve(Router::new().route(
            "/pcp-bucket/pcp/job",
            get(|| async { StatusCode::NOT_FOUND }),
        ))
        .await;

        let error = bucket(&address)
            .get_pcp("pcp/job", 16)
            .await
            .expect_err("should fail");

        assert!(
            matches!(
                error,
                StorageError::Failed {
                    operation: "S3 GetObject",
                    ..
                }
            ),
            "{error:?}"
        );
    }

    /// A retried job's second write must not fail the job.
    #[tokio::test]
    async fn an_existing_result_is_kept() {
        let address = serve(Router::new().route(
            "/pcp-bucket/result/job",
            put(|| async {
                (
                    StatusCode::PRECONDITION_FAILED,
                    [(header::CONTENT_TYPE, "application/xml")],
                    "<Error><Code>PreconditionFailed</Code></Error>",
                )
            }),
        ))
        .await;

        let key = bucket(&address)
            .put_result("job", b"migrated".to_vec())
            .await
            .expect("should keep the first result");

        assert_eq!(key, "result/job");
    }

    #[tokio::test]
    async fn an_unreachable_bucket_is_not_ready() {
        let error = bucket("http://127.0.0.1:9")
            .check_ready()
            .await
            .expect_err("should fail");

        assert!(
            matches!(
                error,
                StorageError::Failed {
                    operation: "S3 HeadBucket",
                    ..
                }
            ),
            "{error:?}"
        );
    }
}
