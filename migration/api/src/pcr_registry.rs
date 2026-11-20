use std::time::Duration;

use anyhow::{Context, ensure};
use aws_sdk_s3::{Client, error::DisplayErrorContext};
use base64::{Engine, engine::general_purpose::STANDARD};
use di_migration_primitives::app_api::ApprovedPcrRegistry;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MAX_POINTER_BYTES: usize = 1024;
const MAX_ARTIFACT_BYTES: usize = 256 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct PcrRegistry {
    client: Client,
    bucket: String,
}

#[derive(Deserialize)]
struct Current {
    revision: String,
}

impl PcrRegistry {
    pub fn new(client: Client, bucket: String) -> Self {
        Self { client, bucket }
    }

    pub async fn current(&self) -> anyhow::Result<ApprovedPcrRegistry> {
        tokio::time::timeout(READ_TIMEOUT, self.read_current())
            .await
            .context("reading PCR registry timed out")?
    }

    async fn read_current(&self) -> anyhow::Result<ApprovedPcrRegistry> {
        let pointer = self.read("current.json", MAX_POINTER_BYTES).await?;
        let Current { revision } =
            serde_json::from_slice(&pointer).context("invalid PCR registry pointer")?;
        ensure!(
            revision.len() == 64
                && revision
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
            "PCR registry revision must be a lowercase SHA-256 digest"
        );

        let registry_key = format!("revisions/{revision}/approved-pcrs.json");
        let bundle_key = format!("revisions/{revision}/approved-pcrs.sigstore.json");
        let (registry, bundle) = tokio::try_join!(
            self.read(&registry_key, MAX_ARTIFACT_BYTES),
            self.read(&bundle_key, MAX_ARTIFACT_BYTES),
        )?;
        ensure!(
            format!("{:x}", Sha256::digest(&registry)) == revision,
            "PCR registry hash does not match its revision"
        );

        Ok(ApprovedPcrRegistry {
            registry: STANDARD.encode(registry),
            bundle: STANDARD.encode(bundle),
        })
    }

    async fn read(&self, key: &str, limit: usize) -> anyhow::Result<Vec<u8>> {
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|error| {
                anyhow::anyhow!("S3 GetObject {key}: {}", DisplayErrorContext(&error))
            })?;
        let mut body = output.body;
        let mut bytes = Vec::new();
        while let Some(chunk) = body
            .try_next()
            .await
            .with_context(|| format!("reading S3 GetObject body for {key}"))?
        {
            ensure!(
                chunk.len() <= limit - bytes.len(),
                "S3 object {key} exceeds {limit} bytes"
            );
            bytes.extend_from_slice(&chunk);
        }
        ensure!(!bytes.is_empty(), "S3 object {key} is empty");
        Ok(bytes)
    }
}
