//! The migration job row and object layout shared by the Migration API and the host, so both
//! read and write the same `DynamoDB` attributes and S3 keys.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

/// `DynamoDB` attribute names of a job row.
pub mod attributes {
    /// Hash key; see [`super::row_id`].
    pub const ID: &str = "id";
    /// One of [`super::Status`].
    pub const STATUS: &str = "status";
    /// One of [`super::Reason`], set on `failed`.
    pub const REASON: &str = "reason";
    /// S3 key of the migrated PCP, set on `migrated`.
    pub const RESULT_KEY: &str = "result_key";
}

/// The row's hash key; prefixed because the table also holds signup locks.
#[must_use]
pub fn row_id(job_id: &str) -> String {
    format!("job#{job_id}")
}

/// S3 key the app uploads the sealed PCP to.
#[must_use]
pub fn pcp_key(job_id: &str) -> String {
    format!("pcp/{job_id}")
}

/// S3 key the host writes the migrated PCP to.
#[must_use]
pub fn result_key(job_id: &str) -> String {
    format!("result/{job_id}")
}

/// A job's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Init done; the app has not called migrate yet.
    Created,
    /// Dispatched to a host.
    Migrating,
    /// The result is in S3.
    Migrated,
    /// Terminal failure; see [`Reason`].
    Failed,
}

impl Status {
    /// The value stored in the row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Migrating => "migrating",
            Self::Migrated => "migrated",
            Self::Failed => "failed",
        }
    }
}

/// Why a job failed; machine-readable for the app, so values never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The host was over its safety cap.
    HostBusy,
    /// The enclave restarted, so the PCP was sealed to a key that no longer exists.
    EnclaveChanged,
    /// The enclave rejected or failed the migration.
    EnclaveError,
    /// Reading the PCP or writing the result failed.
    S3Error,
    /// The job did not finish before its deadline.
    Timeout,
}

impl Reason {
    /// The value stored in the row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostBusy => "host_busy",
            Self::EnclaveChanged => "enclave_changed",
            Self::EnclaveError => "enclave_error",
            Self::S3Error => "s3_error",
            Self::Timeout => "timeout",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Reason, Status, pcp_key, result_key, row_id};

    #[test]
    fn keys_follow_the_shared_layout() {
        assert_eq!(row_id("abc"), "job#abc");
        assert_eq!(pcp_key("abc"), "pcp/abc");
        assert_eq!(result_key("abc"), "result/abc");
    }

    /// Pins the stored values; the app and API branch on them.
    #[test]
    fn stored_values_are_stable() {
        let statuses = [
            (Status::Created, "created"),
            (Status::Migrating, "migrating"),
            (Status::Migrated, "migrated"),
            (Status::Failed, "failed"),
        ];
        for (status, value) in statuses {
            assert_eq!(status.as_str(), value);
        }

        let reasons = [
            (Reason::HostBusy, "host_busy"),
            (Reason::EnclaveChanged, "enclave_changed"),
            (Reason::EnclaveError, "enclave_error"),
            (Reason::S3Error, "s3_error"),
            (Reason::Timeout, "timeout"),
        ];
        for (reason, value) in reasons {
            assert_eq!(reason.as_str(), value);
        }
    }
}
