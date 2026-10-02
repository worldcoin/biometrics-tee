//! The job table: the conditional state transitions both services share.

use std::time::Duration;

use aws_sdk_dynamodb::{
    Client, error::DisplayErrorContext, operation::update_item::UpdateItemError,
    types::AttributeValue,
};
use tokio::time::timeout;

use crate::{
    StorageError,
    layout::{Reason, Status, attributes, row_id},
};

/// Readiness must not hang behind a slow `DynamoDB`.
const READINESS_TIMEOUT: Duration = Duration::from_secs(3);

/// A single-item update; anything slower is an outage.
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);

/// The migration job table.
#[derive(Debug, Clone)]
pub struct JobTable {
    client: Client,
    table_name: String,
}

impl JobTable {
    /// Wraps `client` for `table_name`.
    #[must_use]
    pub const fn new(client: Client, table_name: String) -> Self {
        Self { client, table_name }
    }

    /// Moves a `migrating` row to `status`, setting `extra` alongside. A row in any other state
    /// was already resolved, e.g. timed out, so it is left alone.
    async fn finish(
        &self,
        job_id: &str,
        status: Status,
        extra: (&'static str, String),
    ) -> Result<(), StorageError> {
        const OPERATION: &str = "DynamoDB UpdateItem";
        let result = timeout(
            WRITE_TIMEOUT,
            self.client
                .update_item()
                .table_name(&self.table_name)
                .key(attributes::ID, AttributeValue::S(row_id(job_id)))
                .update_expression("SET #status = :status, #extra = :extra")
                .condition_expression("#status = :migrating")
                .expression_attribute_names("#status", attributes::STATUS)
                .expression_attribute_names("#extra", extra.0)
                .expression_attribute_values(":status", string(status.as_str()))
                .expression_attribute_values(":extra", AttributeValue::S(extra.1))
                .expression_attribute_values(":migrating", string(Status::Migrating.as_str()))
                .send(),
        )
        .await
        .map_err(|_| StorageError::Timeout {
            operation: OPERATION,
        })?;

        match result {
            Ok(_) => Ok(()),
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(UpdateItemError::is_conditional_check_failed_exception) =>
            {
                Err(StorageError::NotMigrating)
            }
            Err(error) => Err(StorageError::Failed {
                operation: OPERATION,
                detail: DisplayErrorContext(&error).to_string(),
            }),
        }
    }
}

fn string(value: &str) -> AttributeValue {
    AttributeValue::S(value.to_owned())
}

impl JobTable {
    /// Checks the table is reachable.
    ///
    /// # Errors
    ///
    /// `DescribeTable` timed out or failed.
    pub async fn check_ready(&self) -> Result<(), StorageError> {
        const OPERATION: &str = "DynamoDB DescribeTable";
        timeout(
            READINESS_TIMEOUT,
            self.client
                .describe_table()
                .table_name(&self.table_name)
                .send(),
        )
        .await
        .map_err(|_| StorageError::Timeout {
            operation: OPERATION,
        })?
        .map_err(|error| StorageError::Failed {
            operation: OPERATION,
            detail: DisplayErrorContext(&error).to_string(),
        })?;
        Ok(())
    }

    /// Marks a `migrating` job `migrated` with its result key.
    ///
    /// # Errors
    ///
    /// [`StorageError::NotMigrating`] when the row was resolved elsewhere, or the update failed.
    pub async fn mark_migrated(&self, job_id: &str, result_key: &str) -> Result<(), StorageError> {
        self.finish(
            job_id,
            Status::Migrated,
            (attributes::RESULT_KEY, result_key.to_owned()),
        )
        .await
    }

    /// Marks a `migrating` job `failed` with its reason.
    ///
    /// # Errors
    ///
    /// [`StorageError::NotMigrating`] when the row was resolved elsewhere, or the update failed.
    pub async fn mark_failed(&self, job_id: &str, reason: Reason) -> Result<(), StorageError> {
        self.finish(
            job_id,
            Status::Failed,
            (attributes::REASON, reason.as_str().to_owned()),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::JobTable;
    use crate::{Reason, StorageError};
    use axum::{
        Router,
        http::{StatusCode, header},
        routing::post,
    };

    const AMZ_JSON: &str = "application/x-amz-json-1.0";

    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should bind a loopback port");
        let address = listener.local_addr().expect("should have an address");
        tokio::spawn(async move { axum::serve(listener, router).await });
        format!("http://{address}")
    }

    /// A client against `endpoint` with retries off, so failures surface at once.
    fn dynamodb_client(endpoint: &str) -> aws_sdk_dynamodb::Client {
        aws_sdk_dynamodb::Client::from_conf(
            aws_sdk_dynamodb::Config::builder()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .behavior_version(aws_config::BehaviorVersion::latest())
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                    "test", "test", None, None, "test",
                ))
                .endpoint_url(endpoint)
                .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
                .build(),
        )
    }

    /// A `DynamoDB` stand-in that records each request body and answers with `status` and `body`.
    async fn fake(
        status: StatusCode,
        body: &'static str,
    ) -> (JobTable, Arc<Mutex<Vec<serde_json::Value>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let address = serve(Router::new().route(
            "/",
            post(move |request: String| {
                let recorder = Arc::clone(&recorder);
                async move {
                    recorder
                        .lock()
                        .expect("lock should hold")
                        .push(serde_json::from_str(&request).expect("request should be JSON"));
                    (status, [(header::CONTENT_TYPE, AMZ_JSON)], body)
                }
            }),
        ))
        .await;
        (
            JobTable::new(dynamodb_client(&address), "jobs".to_owned()),
            seen,
        )
    }

    #[tokio::test]
    async fn a_migrated_job_records_its_result_only_while_migrating() {
        let (store, seen) = fake(StatusCode::OK, "{}").await;

        store
            .mark_migrated("abc", "result/abc")
            .await
            .expect("should update");

        let request = seen.lock().expect("lock should hold")[0].clone();
        assert_eq!(request["Key"]["id"]["S"], "job#abc");
        assert_eq!(request["ConditionExpression"], "#status = :migrating");
        assert_eq!(
            request["ExpressionAttributeValues"][":status"]["S"],
            "migrated"
        );
        assert_eq!(
            request["ExpressionAttributeValues"][":extra"]["S"],
            "result/abc"
        );
        assert_eq!(request["ExpressionAttributeNames"]["#extra"], "result_key");
    }

    #[tokio::test]
    async fn a_failed_job_records_its_reason() {
        let (store, seen) = fake(StatusCode::OK, "{}").await;

        store
            .mark_failed("abc", Reason::EnclaveError)
            .await
            .expect("should update");

        let request = seen.lock().expect("lock should hold")[0].clone();
        assert_eq!(
            request["ExpressionAttributeValues"][":status"]["S"],
            "failed"
        );
        assert_eq!(
            request["ExpressionAttributeValues"][":extra"]["S"],
            "enclave_error"
        );
        assert_eq!(request["ExpressionAttributeNames"]["#extra"], "reason");
    }

    /// A job resolved elsewhere first, e.g. timed out, is not overwritten.
    #[tokio::test]
    async fn a_job_no_longer_migrating_is_left_alone() {
        let (store, _) = fake(
            StatusCode::BAD_REQUEST,
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException","message":"The conditional request failed"}"#,
        )
        .await;

        let error = store
            .mark_migrated("abc", "result/abc")
            .await
            .expect_err("should skip");

        assert_eq!(error, StorageError::NotMigrating);
    }

    #[tokio::test]
    async fn an_unreachable_table_is_not_ready() {
        let store = JobTable::new(dynamodb_client("http://127.0.0.1:9"), "jobs".to_owned());

        let error = store.check_ready().await.expect_err("should fail");

        assert!(
            matches!(
                error,
                StorageError::Failed {
                    operation: "DynamoDB DescribeTable",
                    ..
                }
            ),
            "{error:?}"
        );
    }
}
