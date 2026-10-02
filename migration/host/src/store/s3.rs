use async_trait::async_trait;
use bytes::Bytes;
use di_migration_storage::PcpBucket;

use super::{BlobStore, StoreError};

/// The PCP bucket, capped at the size the host will buffer.
#[derive(Debug, Clone)]
pub struct S3BlobStore {
    bucket: PcpBucket,
    max_pcp_bytes: usize,
}

impl S3BlobStore {
    /// Reads at most `max_pcp_bytes` per PCP from `bucket`.
    #[must_use]
    pub const fn new(bucket: PcpBucket, max_pcp_bytes: usize) -> Self {
        Self {
            bucket,
            max_pcp_bytes,
        }
    }
}

#[async_trait]
impl BlobStore for S3BlobStore {
    async fn check_ready(&self) -> Result<(), StoreError> {
        self.bucket.check_ready().await
    }

    async fn get_pcp(&self, object_key: &str) -> Result<Bytes, StoreError> {
        self.bucket.get_pcp(object_key, self.max_pcp_bytes).await
    }

    async fn put_result(&self, job_id: &str, blob: Vec<u8>) -> Result<String, StoreError> {
        self.bucket.put_result(job_id, blob).await
    }
}
