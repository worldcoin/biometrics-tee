//! How jobs are stored: the job row's key and attributes, and the S3 keys of its objects.

use di_migration_primitives::JobId;
use sha2::{Digest as _, Sha256};

/// `DynamoDB` attribute names of job and lock rows.
pub mod attributes {
    /// Hash key; see [`super::row_id`] and [`super::lock_id`].
    pub const ID: &str = "id";
    /// One of [`di_migration_primitives::Status`].
    pub const STATUS: &str = "status";
    /// One of [`di_migration_primitives::Reason`], set on `failed`.
    pub const REASON: &str = "reason";
    /// S3 key of the migrated PCP, set on `migrated`.
    pub const RESULT_KEY: &str = "result_key";
    /// The app's attested device key.
    pub const DEVICE_PUBLIC_KEY: &str = "device_public_key";
    /// The host the job is pinned to.
    pub const HOST_IP: &str = "host_ip";
    /// The enclave boot the PCP is sealed to.
    pub const ENCLAVE_ID: &str = "enclave_id";
    /// Unix seconds the job was created.
    pub const CREATED_AT: &str = "created_at";
    /// Unix seconds after which a `migrating` job reads as `failed (timeout)`.
    pub const DEADLINE: &str = "deadline";
    /// Unix seconds after which `DynamoDB` deletes the row.
    pub const TTL: &str = "ttl";
    /// On a lock row: the job it points to.
    pub const JOB_ID: &str = "job_id";
    /// On a lock row: Unix seconds until which it blocks a new job for the same `sub`.
    pub const ACTIVE_UNTIL: &str = "active_until";
}

/// The job row's hash key; prefixed because the table also holds `sub` locks.
#[must_use]
pub fn row_id(job_id: &JobId) -> String {
    format!("job#{job_id}")
}

/// The lock row's hash key. One per `sub`: it points to the account's latest job and blocks a
/// second one while that job is active. Hashed so `sub` never appears in a key.
#[must_use]
pub fn lock_id(sub: &str) -> String {
    format!("sub#{}", hex::encode(Sha256::digest(sub.as_bytes())))
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

    use super::{lock_id, pcp_key, result_key, row_id};

    #[test]
    fn keys_follow_the_shared_layout() {
        let id: JobId = "3f0c5e2a-8a51-4c47-9d8e-0b9f3c1d2e4a"
            .parse()
            .expect("uuid");

        assert_eq!(row_id(&id), format!("job#{id}"));
        assert_eq!(pcp_key(&id), format!("pcp/{id}"));
        assert_eq!(result_key(&id), format!("result/{id}"));
    }

    /// Pins the hash: both services must derive the same lock for one account.
    #[test]
    fn the_lock_key_hashes_the_sub() {
        assert_eq!(
            lock_id("sub"),
            "sub#ddc6e2b224d0fd821669202258386936fc9ce2899e215eec6322b95f8dd96d6a"
        );
    }
}
