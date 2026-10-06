//! The job table: the conditional state transitions both services share.

use std::{collections::HashMap, net::IpAddr, time::Duration};

use aws_sdk_dynamodb::{
    Client,
    error::DisplayErrorContext,
    operation::transact_write_items::TransactWriteItemsError,
    types::{AttributeValue, Put, TransactWriteItem, Update},
};
use tokio::time::timeout;

use crate::{
    StorageError,
    error::failed,
    schema::{attributes, lock_id, row_id},
};
use di_migration_primitives::{EnclaveId, JobId, Reason, Status};

/// Readiness must not hang behind a slow `DynamoDB`.
const READINESS_TIMEOUT: Duration = Duration::from_secs(3);

/// A single-item update or a two-item transaction; anything slower is an outage.
const WRITE_TIMEOUT: Duration = Duration::from_secs(3);

/// A single-item read.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

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

    /// Moves a `migrating` row to `status`, setting `extra` alongside, and releases its `sub`'s
    /// lock so the app can init again. A row past its deadline already reads as `timeout`, and
    /// one in any other state was resolved elsewhere, so both are left alone.
    async fn finish(
        &self,
        job_id: &JobId,
        sub: &str,
        status: Status,
        extra: (&'static str, String),
        now: u64,
    ) -> Result<(), StorageError> {
        const OPERATION: &str = "DynamoDB TransactWriteItems";
        let job_row = Update::builder()
            .table_name(&self.table_name)
            .key(attributes::ID, string(&row_id(job_id)))
            .update_expression("SET #status = :status, #extra = :extra")
            .condition_expression("#status = :migrating AND #deadline >= :now")
            .expression_attribute_names("#status", attributes::STATUS)
            .expression_attribute_names("#extra", extra.0)
            .expression_attribute_names("#deadline", attributes::DEADLINE)
            .expression_attribute_values(":status", string(status.as_str()))
            .expression_attribute_values(":extra", AttributeValue::S(extra.1))
            .expression_attribute_values(":migrating", string(Status::Migrating.as_str()))
            .expression_attribute_values(":now", number(now))
            .build()
            .map_err(|error| failed(OPERATION, &error))?;

        match self
            .transact([
                TransactWriteItem::builder().update(job_row).build(),
                self.retarget_lock(sub, job_id, 0, None)?,
            ])
            .await?
        {
            Transaction::Committed => Ok(()),
            Transaction::Rejected(_) => Err(StorageError::NotMigrating),
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

    /// Marks a `migrating` job `migrated` with its result key, and frees its `sub`.
    ///
    /// # Errors
    ///
    /// [`StorageError::NotMigrating`] when the row was resolved elsewhere or is past its
    /// deadline at `now`, or the write failed.
    pub async fn mark_migrated(
        &self,
        job_id: &JobId,
        sub: &str,
        result_key: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        self.finish(
            job_id,
            sub,
            Status::Migrated,
            (attributes::RESULT_KEY, result_key.to_owned()),
            now,
        )
        .await
    }

    /// Marks a `migrating` job `failed` with its reason, and frees its `sub`.
    ///
    /// # Errors
    ///
    /// [`StorageError::NotMigrating`] when the row was resolved elsewhere or is past its
    /// deadline at `now`, or the write failed.
    pub async fn mark_failed(
        &self,
        job_id: &JobId,
        sub: &str,
        reason: Reason,
        now: u64,
    ) -> Result<(), StorageError> {
        self.finish(
            job_id,
            sub,
            Status::Failed,
            (attributes::REASON, reason.as_str().to_owned()),
            now,
        )
        .await
    }
}

/// A job to create at init, together with its account's lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJob {
    /// The new job's ID.
    pub job_id: JobId,
    /// The account the ownership proof was verified for.
    pub sub: String,
    /// The app's attested device key; later calls must be signed by it.
    pub device_public_key: String,
    /// The host the job is pinned to.
    pub host_ip: IpAddr,
    /// The enclave boot the app will seal the PCP to.
    pub enclave_id: EnclaveId,
    /// Unix seconds now.
    pub created_at: u64,
    /// Unix seconds until which the job blocks another init for the same `sub` and may still be
    /// claimed: the upload window. Migrate extends it to the deadline.
    pub active_until: u64,
    /// Unix seconds after which `DynamoDB` deletes the rows.
    pub expires_at: u64,
}

/// A stored job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    /// The job's ID.
    pub job_id: JobId,
    /// Its lifecycle state.
    pub status: Status,
    /// Why it failed, once `failed`.
    pub reason: Option<Reason>,
    /// The app's attested device key.
    pub device_public_key: String,
    /// The host the job is pinned to.
    pub host_ip: IpAddr,
    /// The enclave boot the PCP is sealed to.
    pub enclave_id: EnclaveId,
    /// Unix seconds the job was created.
    pub created_at: u64,
    /// Unix seconds after which a `migrating` job reads as `failed (timeout)`; set at migrate.
    pub deadline: Option<u64>,
    /// S3 key of the result, once `migrated`.
    pub result_key: Option<String>,
}

/// A transaction item failed its condition.
const CONDITIONAL_CHECK_FAILED: &str = "ConditionalCheckFailed";

impl JobTable {
    /// Creates `job` and points its `sub`'s lock at it, unless another job for the `sub` is still
    /// active. Both rows are written in one transaction.
    ///
    /// # Errors
    ///
    /// [`StorageError::ActiveJob`] when the `sub` has an active job, or the write failed.
    pub async fn create_job(&self, job: &NewJob) -> Result<(), StorageError> {
        const OPERATION: &str = "DynamoDB TransactWriteItems";
        let job_row = Put::builder()
            .table_name(&self.table_name)
            .item(attributes::ID, string(&row_id(&job.job_id)))
            .item(attributes::STATUS, string(Status::Created.as_str()))
            .item(
                attributes::DEVICE_PUBLIC_KEY,
                string(&job.device_public_key),
            )
            .item(attributes::HOST_IP, string(&job.host_ip.to_string()))
            .item(attributes::ENCLAVE_ID, string(job.enclave_id.as_str()))
            .item(attributes::CREATED_AT, number(job.created_at))
            .item(attributes::TTL, number(job.expires_at))
            .condition_expression("attribute_not_exists(#id)")
            .expression_attribute_names("#id", attributes::ID)
            .build()
            .map_err(|error| failed(OPERATION, &error))?;
        let lock_row = Put::builder()
            .table_name(&self.table_name)
            .item(attributes::ID, string(&lock_id(&job.sub)))
            .item(attributes::JOB_ID, string(job.job_id.as_str()))
            .item(attributes::ACTIVE_UNTIL, number(job.active_until))
            .item(attributes::TTL, number(job.expires_at))
            .condition_expression("attribute_not_exists(#id) OR #active_until < :now")
            .expression_attribute_names("#id", attributes::ID)
            .expression_attribute_names("#active_until", attributes::ACTIVE_UNTIL)
            .expression_attribute_values(":now", number(job.created_at))
            .build()
            .map_err(|error| failed(OPERATION, &error))?;

        let outcome = self
            .transact([
                TransactWriteItem::builder().put(job_row).build(),
                TransactWriteItem::builder().put(lock_row).build(),
            ])
            .await?;
        match outcome {
            Transaction::Committed => Ok(()),
            Transaction::Rejected(failed_items) if failed_items == [false, true] => {
                Err(StorageError::ActiveJob)
            }
            Transaction::Rejected(_) => Err(StorageError::Failed {
                operation: OPERATION,
                detail: "job ID already exists".to_owned(),
            }),
        }
    }

    /// The latest job for `sub`, active or not, until its rows expire.
    ///
    /// # Errors
    ///
    /// A read timed out or failed, or a stored row is malformed.
    pub async fn latest_job(&self, sub: &str) -> Result<Option<JobRecord>, StorageError> {
        let Some(lock) = self.get(&lock_id(sub)).await? else {
            return Ok(None);
        };
        let job_id: JobId = text(&lock, attributes::JOB_ID)?
            .parse()
            .map_err(|_| malformed(attributes::JOB_ID))?;
        let Some(row) = self.get(&row_id(&job_id)).await? else {
            return Ok(None);
        };

        Ok(Some(JobRecord {
            status: text(&row, attributes::STATUS)?
                .parse()
                .map_err(|_| malformed(attributes::STATUS))?,
            reason: optional_text(&row, attributes::REASON)
                .map(|reason| reason.parse().map_err(|_| malformed(attributes::REASON)))
                .transpose()?,
            device_public_key: text(&row, attributes::DEVICE_PUBLIC_KEY)?.to_owned(),
            host_ip: text(&row, attributes::HOST_IP)?
                .parse()
                .map_err(|_| malformed(attributes::HOST_IP))?,
            enclave_id: EnclaveId::try_from(text(&row, attributes::ENCLAVE_ID)?.to_owned())
                .map_err(|_| malformed(attributes::ENCLAVE_ID))?,
            created_at: unsigned(&row, attributes::CREATED_AT)?
                .ok_or_else(|| malformed(attributes::CREATED_AT))?,
            deadline: unsigned(&row, attributes::DEADLINE)?,
            result_key: optional_text(&row, attributes::RESULT_KEY).map(str::to_owned),
            job_id,
        }))
    }

    /// Moves a `created` job to `migrating` with `deadline`, and keeps its `sub`'s lock active
    /// until then. Committed before dispatch, so a retried migrate never starts the job twice.
    /// Only allowed until the lock's upload window ends, which bounds how long an admitted job
    /// stays invisible to admission.
    ///
    /// # Errors
    ///
    /// [`StorageError::UploadWindowPassed`] when `now` is past the upload window,
    /// [`StorageError::NotCreated`] when the job already left `created` or a newer job for the
    /// `sub` took the lock, or the write failed.
    pub async fn claim(
        &self,
        job_id: &JobId,
        sub: &str,
        now: u64,
        deadline: u64,
    ) -> Result<(), StorageError> {
        const OPERATION: &str = "DynamoDB TransactWriteItems";
        let job_row = Update::builder()
            .table_name(&self.table_name)
            .key(attributes::ID, string(&row_id(job_id)))
            .update_expression("SET #status = :migrating, #deadline = :deadline")
            .condition_expression("#status = :created")
            .expression_attribute_names("#status", attributes::STATUS)
            .expression_attribute_names("#deadline", attributes::DEADLINE)
            .expression_attribute_values(":migrating", string(Status::Migrating.as_str()))
            .expression_attribute_values(":created", string(Status::Created.as_str()))
            .expression_attribute_values(":deadline", number(deadline))
            .build()
            .map_err(|error| failed(OPERATION, &error))?;

        match self
            .transact([
                TransactWriteItem::builder().update(job_row).build(),
                self.retarget_lock(sub, job_id, deadline, Some(now))?,
            ])
            .await?
        {
            Transaction::Committed => Ok(()),
            Transaction::Rejected(failed_items) if failed_items == [false, true] => {
                Err(StorageError::UploadWindowPassed)
            }
            Transaction::Rejected(_) => Err(StorageError::NotCreated),
        }
    }

    /// Fails a `migrating` job the API could not hand to its host, and releases its `sub`'s lock
    /// so the app can init again at once.
    ///
    /// # Errors
    ///
    /// [`StorageError::NotMigrating`] when the job was resolved elsewhere, or the write failed.
    pub async fn fail_dispatch(
        &self,
        job_id: &JobId,
        sub: &str,
        reason: Reason,
    ) -> Result<(), StorageError> {
        const OPERATION: &str = "DynamoDB TransactWriteItems";
        let job_row = Update::builder()
            .table_name(&self.table_name)
            .key(attributes::ID, string(&row_id(job_id)))
            .update_expression("SET #status = :failed, #reason = :reason")
            .condition_expression("#status = :migrating")
            .expression_attribute_names("#status", attributes::STATUS)
            .expression_attribute_names("#reason", attributes::REASON)
            .expression_attribute_values(":failed", string(Status::Failed.as_str()))
            .expression_attribute_values(":migrating", string(Status::Migrating.as_str()))
            .expression_attribute_values(":reason", string(reason.as_str()))
            .build()
            .map_err(|error| failed(OPERATION, &error))?;

        match self
            .transact([
                TransactWriteItem::builder().update(job_row).build(),
                self.retarget_lock(sub, job_id, 0, None)?,
            ])
            .await?
        {
            Transaction::Committed => Ok(()),
            Transaction::Rejected(_) => Err(StorageError::NotMigrating),
        }
    }

    /// Sets the `sub`'s lock to stay active until `active_until`, if it still points to `job_id`
    /// and, given `active_at`, is still active then.
    fn retarget_lock(
        &self,
        sub: &str,
        job_id: &JobId,
        active_until: u64,
        active_at: Option<u64>,
    ) -> Result<TransactWriteItem, StorageError> {
        let mut lock_row = Update::builder()
            .table_name(&self.table_name)
            .key(attributes::ID, string(&lock_id(sub)))
            .update_expression("SET #active_until = :active_until")
            .condition_expression("#job_id = :job_id")
            .expression_attribute_names("#active_until", attributes::ACTIVE_UNTIL)
            .expression_attribute_names("#job_id", attributes::JOB_ID)
            .expression_attribute_values(":active_until", number(active_until))
            .expression_attribute_values(":job_id", string(job_id.as_str()));
        if let Some(now) = active_at {
            lock_row = lock_row
                .condition_expression("#job_id = :job_id AND #active_until >= :now")
                .expression_attribute_values(":now", number(now));
        }
        let lock_row = lock_row
            .build()
            .map_err(|error| failed("DynamoDB TransactWriteItems", &error))?;
        Ok(TransactWriteItem::builder().update(lock_row).build())
    }

    /// Runs `items` as one transaction; a failed condition is a [`Transaction::Rejected`] that
    /// says which items failed.
    async fn transact(&self, items: [TransactWriteItem; 2]) -> Result<Transaction, StorageError> {
        const OPERATION: &str = "DynamoDB TransactWriteItems";
        let result = timeout(
            WRITE_TIMEOUT,
            self.client
                .transact_write_items()
                .set_transact_items(Some(items.to_vec()))
                .send(),
        )
        .await
        .map_err(|_| StorageError::Timeout {
            operation: OPERATION,
        })?;

        match result {
            Ok(_) => Ok(Transaction::Committed),
            Err(error) => match error.as_service_error() {
                Some(TransactWriteItemsError::TransactionCanceledException(canceled))
                    if canceled
                        .cancellation_reasons()
                        .iter()
                        .any(|reason| reason.code() == Some(CONDITIONAL_CHECK_FAILED)) =>
                {
                    Ok(Transaction::Rejected(
                        canceled
                            .cancellation_reasons()
                            .iter()
                            .map(|reason| reason.code() == Some(CONDITIONAL_CHECK_FAILED))
                            .collect(),
                    ))
                }
                _ => Err(StorageError::Failed {
                    operation: OPERATION,
                    detail: DisplayErrorContext(&error).to_string(),
                }),
            },
        }
    }

    /// Reads one row by key, strongly consistent so a fresh write is always seen.
    async fn get(&self, id: &str) -> Result<Option<Row>, StorageError> {
        const OPERATION: &str = "DynamoDB GetItem";
        timeout(
            READ_TIMEOUT,
            self.client
                .get_item()
                .table_name(&self.table_name)
                .key(attributes::ID, string(id))
                .consistent_read(true)
                .send(),
        )
        .await
        .map_err(|_| StorageError::Timeout {
            operation: OPERATION,
        })?
        .map(|output| output.item)
        .map_err(|error| StorageError::Failed {
            operation: OPERATION,
            detail: DisplayErrorContext(&error).to_string(),
        })
    }
}

/// How a two-item transaction ended.
enum Transaction {
    Committed,
    /// Which items failed their condition, in order.
    Rejected(Vec<bool>),
}

type Row = HashMap<String, AttributeValue>;

fn number(value: u64) -> AttributeValue {
    AttributeValue::N(value.to_string())
}

const fn malformed(attribute: &'static str) -> StorageError {
    StorageError::Malformed { attribute }
}

fn optional_text<'a>(row: &'a Row, attribute: &str) -> Option<&'a str> {
    row.get(attribute)?.as_s().ok().map(String::as_str)
}

fn text<'a>(row: &'a Row, attribute: &'static str) -> Result<&'a str, StorageError> {
    optional_text(row, attribute).ok_or_else(|| malformed(attribute))
}

fn unsigned(row: &Row, attribute: &'static str) -> Result<Option<u64>, StorageError> {
    row.get(attribute)
        .map(|value| {
            value
                .as_n()
                .ok()
                .and_then(|number| number.parse().ok())
                .ok_or_else(|| malformed(attribute))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::JobTable;
    use di_migration_primitives::{JobId, Reason};

    use crate::StorageError;

    const ID: &str = "3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a";

    fn id() -> JobId {
        ID.parse().expect("uuid")
    }
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
            .mark_migrated(&id(), "sub", "result/abc", 100)
            .await
            .expect("should update");

        let items = seen.lock().expect("lock should hold")[0]["TransactItems"].clone();
        let request = &items[0]["Update"];
        assert_eq!(request["Key"]["id"]["S"], format!("job#{ID}"));
        assert_eq!(
            request["ConditionExpression"],
            "#status = :migrating AND #deadline >= :now"
        );
        assert_eq!(request["ExpressionAttributeValues"][":now"]["N"], "100");
        assert_eq!(
            request["ExpressionAttributeValues"][":status"]["S"],
            "migrated"
        );
        assert_eq!(
            request["ExpressionAttributeValues"][":extra"]["S"],
            "result/abc"
        );
        assert_eq!(request["ExpressionAttributeNames"]["#extra"], "result_key");
        let lock = &items[1]["Update"];
        assert_eq!(
            lock["ExpressionAttributeValues"][":active_until"]["N"], "0",
            "the sub is free again"
        );
    }

    #[tokio::test]
    async fn a_failed_job_records_its_reason() {
        let (store, seen) = fake(StatusCode::OK, "{}").await;

        store
            .mark_failed(&id(), "sub", Reason::EnclaveError, 100)
            .await
            .expect("should update");

        let request =
            seen.lock().expect("lock should hold")[0]["TransactItems"][0]["Update"].clone();
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

    /// A job resolved elsewhere first, or past its deadline, is not overwritten.
    #[tokio::test]
    async fn a_job_no_longer_migrating_is_left_alone() {
        let (store, _) = fake(
            StatusCode::BAD_REQUEST,
            r#"{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","message":"canceled","CancellationReasons":[{"Code":"ConditionalCheckFailed"},{"Code":"None"}]}"#,
        )
        .await;

        let error = store
            .mark_migrated(&id(), "sub", "result/abc", 100)
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
