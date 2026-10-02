//! Errors shared by the bucket and the job table.

use aws_sdk_s3::error::DisplayErrorContext;

/// Failures talking to the bucket or the job table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StorageError {
    /// The call did not finish within its deadline.
    #[error("{operation} timed out")]
    Timeout {
        /// The AWS operation, e.g. `S3 GetObject`.
        operation: &'static str,
    },
    /// The call failed.
    #[error("{operation} failed: {detail}")]
    Failed {
        /// The AWS operation, e.g. `S3 GetObject`.
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
    /// The job row is no longer `migrating`, e.g. it timed out first; the write was skipped.
    #[error("job is no longer migrating")]
    NotMigrating,
}

/// Wraps an SDK error with its source chain.
pub fn failed(operation: &'static str, error: &impl std::error::Error) -> StorageError {
    StorageError::Failed {
        operation,
        detail: DisplayErrorContext(error).to_string(),
    }
}
