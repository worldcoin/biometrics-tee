//! How jobs are stored: the job row's key and attributes, and the S3 keys of its objects.

use di_migration_primitives::JobId;

/// `DynamoDB` attribute names of a job row.
pub mod attributes {
    /// Hash key; see [`super::row_id`].
    pub const ID: &str = "id";
    /// One of [`di_migration_primitives::Status`].
    pub const STATUS: &str = "status";
    /// One of [`di_migration_primitives::Reason`], set on `failed`.
    pub const REASON: &str = "reason";
    /// S3 key of the migrated PCP, set on `migrated`.
    pub const RESULT_KEY: &str = "result_key";
}

/// The row's hash key; prefixed because the table also holds signup locks.
#[must_use]
pub fn row_id(job_id: &JobId) -> String {
    format!("job#{job_id}")
}

/// S3 key the app uploads the sealed PCP to.
#[must_use]
pub fn pcp_key(job_id: &JobId) -> String {
    format!("pcp/{job_id}")
}

/// S3 key the host writes the migrated PCP to.
#[must_use]
pub fn result_key(job_id: &JobId) -> String {
    format!("result/{job_id}")
}

#[cfg(test)]
mod tests {
    use di_migration_primitives::JobId;

    use super::{pcp_key, result_key, row_id};

    #[test]
    fn keys_follow_the_shared_layout() {
        let id: JobId = "3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a"
            .parse()
            .expect("uuid");

        assert_eq!(row_id(&id), format!("job#{id}"));
        assert_eq!(pcp_key(&id), format!("pcp/{id}"));
        assert_eq!(result_key(&id), format!("result/{id}"));
    }
}
