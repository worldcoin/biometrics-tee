use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use aws_sdk_dynamodb::{Client, types::AttributeValue};

const READINESS_TIMEOUT: Duration = Duration::from_secs(3);
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct Db {
    client: Client,
    table_name: String,
}

impl Db {
    pub fn new(client: Client, table_name: String) -> Self {
        Self { client, table_name }
    }

    pub async fn check_ready(&self) -> anyhow::Result<()> {
        tokio::time::timeout(
            READINESS_TIMEOUT,
            self.client
                .describe_table()
                .table_name(&self.table_name)
                .send(),
        )
        .await
        .context("DynamoDB DescribeTable timed out")?
        .context("DynamoDB DescribeTable failed")?;

        Ok(())
    }

    /// Records a migration the client has not uploaded a PCP for yet.
    pub async fn put_migration(
        &self,
        migration_id: &str,
        sub: &str,
        object_key: &str,
    ) -> anyhow::Result<()> {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs();

        tokio::time::timeout(
            WRITE_TIMEOUT,
            self.client
                .put_item()
                .table_name(&self.table_name)
                .item("migration_id", AttributeValue::S(migration_id.to_owned()))
                .item("sub", AttributeValue::S(sub.to_owned()))
                .item("object_key", AttributeValue::S(object_key.to_owned()))
                .item("created_at", AttributeValue::N(created_at.to_string()))
                .condition_expression("attribute_not_exists(migration_id)")
                .send(),
        )
        .await
        .context("DynamoDB PutItem timed out")?
        .context("DynamoDB PutItem failed")?;

        Ok(())
    }
}
