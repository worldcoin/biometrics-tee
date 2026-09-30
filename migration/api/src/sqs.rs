use std::time::Duration;

use anyhow::Context;
use aws_sdk_sqs::{Client, types::QueueAttributeName};

const READINESS_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct Sqs {
    client: Client,
    queue_url: String,
}

impl Sqs {
    pub fn new(client: Client, queue_url: String) -> Self {
        Self { client, queue_url }
    }

    pub async fn check_ready(&self) -> anyhow::Result<()> {
        let response = tokio::time::timeout(
            READINESS_TIMEOUT,
            self.client
                .get_queue_attributes()
                .queue_url(&self.queue_url)
                .attribute_names(QueueAttributeName::QueueArn)
                .send(),
        )
        .await
        .context("SQS GetQueueAttributes timed out")?
        .context("SQS GetQueueAttributes failed")?;
        anyhow::ensure!(
            response
                .attributes()
                .is_some_and(|attributes| attributes.contains_key(&QueueAttributeName::QueueArn)),
            "SQS GetQueueAttributes response missing QueueArn"
        );

        Ok(())
    }
}
