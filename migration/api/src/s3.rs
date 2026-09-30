use std::time::Duration;

use anyhow::Context;
use aws_sdk_s3::{Client, presigning::PresigningConfig};

const READINESS_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct S3 {
    client: Client,
    bucket: String,
    presigned_url_ttl: Duration,
}

impl S3 {
    pub fn new(client: Client, bucket: String, presigned_url_ttl: Duration) -> Self {
        Self {
            client,
            bucket,
            presigned_url_ttl,
        }
    }

    pub async fn check_ready(&self) -> anyhow::Result<()> {
        tokio::time::timeout(
            READINESS_TIMEOUT,
            self.client.head_bucket().bucket(&self.bucket).send(),
        )
        .await
        .context("S3 HeadBucket timed out")?
        .context("S3 HeadBucket failed")?;

        Ok(())
    }

    /// Signs a `PUT` URL for `object_key`; signing is local, so this makes no network call.
    pub async fn presign_put(&self, object_key: &str) -> anyhow::Result<String> {
        let presigning_config = PresigningConfig::expires_in(self.presigned_url_ttl)
            .context("invalid presigned URL expiry")?;

        Ok(self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(object_key)
            .presigned(presigning_config)
            .await
            .context("failed to presign PCP upload URL")?
            .uri()
            .to_owned())
    }
}
