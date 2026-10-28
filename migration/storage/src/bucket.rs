//! The PCP bucket: presigned upload and download for the API, reads and writes for the host.

use std::time::Duration;

use aws_sdk_s3::{
    Client, operation::head_object::HeadObjectError, presigning::PresigningConfig,
    primitives::ByteStream,
};
use bytes::Bytes;
use tokio::time::timeout;

use crate::{
    StorageError,
    error::failed,
    schema::{debug_report_key, pcp_key, result_key},
};
use di_migration_primitives::JobId;

/// Readiness and existence checks must not hang behind a slow S3.
const READINESS_TIMEOUT: Duration = Duration::from_secs(3);

/// Sized for a PCP of tens of MiB within the region.
const OBJECT_TIMEOUT: Duration = Duration::from_secs(60);

/// S3 answers a conditional write with this status when the object already exists.
const PRECONDITION_FAILED: u16 = 412;

/// Sealed PCPs under `pcp/`, migrated PCPs under `result/`, and reports under `result/debug-report/`.
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
        job_id: &JobId,
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
        job_id: &JobId,
        ttl: Duration,
    ) -> Result<String, StorageError> {
        self.presign_get(&result_key(job_id), ttl).await
    }

    /// A URL for the encrypted debug report. Signing makes no network call.
    ///
    /// # Errors
    ///
    /// `ttl` is not a valid presigning expiry.
    pub async fn presign_debug_report(
        &self,
        job_id: &JobId,
        ttl: Duration,
    ) -> Result<String, StorageError> {
        self.presign_get(&debug_report_key(job_id), ttl).await
    }

    async fn presign_get(&self, key: &str, ttl: Duration) -> Result<String, StorageError> {
        const OPERATION: &str = "S3 presign GetObject";
        let config =
            PresigningConfig::expires_in(ttl).map_err(|error| failed(OPERATION, &error))?;
        Ok(self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .presigned(config)
            .await
            .map_err(|error| failed(OPERATION, &error))?
            .uri()
            .to_owned())
    }

    /// Whether the app has uploaded the job's sealed PCP.
    ///
    /// # Errors
    ///
    /// `HeadObject` timed out or failed for any reason other than a missing object.
    pub async fn pcp_exists(&self, job_id: &JobId) -> Result<bool, StorageError> {
        self.object_exists(&pcp_key(job_id)).await
    }

    /// Whether the job has an encrypted debug report, regardless of migration status.
    ///
    /// # Errors
    ///
    /// `HeadObject` timed out or failed for any reason other than a missing object.
    pub async fn debug_report_exists(&self, job_id: &JobId) -> Result<bool, StorageError> {
        self.object_exists(&debug_report_key(job_id)).await
    }

    async fn object_exists(&self, key: &str) -> Result<bool, StorageError> {
        const OPERATION: &str = "S3 HeadObject";
        let result = timeout(
            READINESS_TIMEOUT,
            self.client
                .head_object()
                .bucket(&self.bucket)
                .key(key)
                .send(),
        )
        .await
        .map_err(|_| StorageError::Timeout {
            operation: OPERATION,
        })?;

        match result {
            Ok(_) => Ok(true),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(HeadObjectError::is_not_found) =>
            {
                Ok(false)
            }
            Err(error) => Err(failed(OPERATION, &error)),
        }
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
    pub async fn put_result(&self, job_id: &JobId, blob: Vec<u8>) -> Result<String, StorageError> {
        self.put_once(result_key(job_id), blob).await
    }

    /// Writes the encrypted debug report once, keeping any existing report. Returns its key.
    ///
    /// # Errors
    ///
    /// `PutObject` timed out or failed for any reason other than an existing report.
    pub async fn put_debug_report(
        &self,
        job_id: &JobId,
        blob: Vec<u8>,
    ) -> Result<String, StorageError> {
        self.put_once(debug_report_key(job_id), blob).await
    }

    async fn put_once(&self, key: String, blob: Vec<u8>) -> Result<String, StorageError> {
        const OPERATION: &str = "S3 PutObject";
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{
        Router,
        http::{StatusCode, header},
        routing::{get, put},
    };

    use di_migration_primitives::JobId;

    use super::{PcpBucket, StorageError};

    const ID: &str = "3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a";

    fn id() -> JobId {
        ID.parse().expect("uuid")
    }

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
            .presign_upload(&id(), ttl)
            .await
            .expect("should sign");
        let download = bucket
            .presign_download(&id(), ttl)
            .await
            .expect("should sign");
        let debug_report = bucket
            .presign_debug_report(&id(), ttl)
            .await
            .expect("should sign");

        assert!(
            upload.starts_with(&format!("http://127.0.0.1:9/pcp-bucket/pcp/{ID}?")),
            "{upload}"
        );
        assert!(
            download.starts_with(&format!("http://127.0.0.1:9/pcp-bucket/result/{ID}?")),
            "{download}"
        );
        assert!(upload.contains("X-Amz-Signature="), "{upload}");
        assert!(
            debug_report.starts_with(&format!(
                "http://127.0.0.1:9/pcp-bucket/result/debug-report/{ID}?"
            )),
            "{debug_report}"
        );
    }

    #[tokio::test]
    async fn debug_reports_have_their_own_key_and_only_not_found_means_absent() {
        for status in [StatusCode::OK, StatusCode::NOT_FOUND, StatusCode::FORBIDDEN] {
            let address = serve(Router::new().route(
                &format!("/pcp-bucket/result/debug-report/{ID}"),
                axum::routing::head(move || async move { status }),
            ))
            .await;
            let exists = bucket(&address).debug_report_exists(&id()).await;
            match status {
                StatusCode::OK => assert_eq!(exists, Ok(true)),
                StatusCode::NOT_FOUND => assert_eq!(exists, Ok(false)),
                _ => assert!(exists.is_err()),
            }
        }
    }

    #[tokio::test]
    async fn debug_reports_are_written_separately_and_existing_reports_are_kept() {
        for status in [
            StatusCode::OK,
            StatusCode::PRECONDITION_FAILED,
            StatusCode::FORBIDDEN,
        ] {
            let address = serve(Router::new().route(
                &format!("/pcp-bucket/result/debug-report/{ID}"),
                put(
                    move |headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
                        assert_eq!(headers["if-none-match"], "*");
                        assert_eq!(body.as_ref(), b"encrypted report");
                        status
                    },
                ),
            ))
            .await;
            let result = bucket(&address)
                .put_debug_report(&id(), b"encrypted report".to_vec())
                .await;
            if status == StatusCode::FORBIDDEN {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), format!("result/debug-report/{ID}"));
            }
        }
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
            &format!("/pcp-bucket/result/{ID}"),
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
            .put_result(&id(), b"migrated".to_vec())
            .await
            .expect("should keep the first result");

        assert_eq!(key, format!("result/{ID}"));
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
