//! An enclave boot's identity.

use std::fmt::{self, Write as _};

use serde::{Deserialize, Serialize};

/// Hex of the boot's channel-key commitment. It changes exactly when the key does, and the
/// attestation document carries the commitment, so the app can check it without trusting the
/// host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EnclaveId(String);

/// The value is not 32 bytes of lower-case hex.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("enclave_id is not 64 lower-case hex characters")]
pub struct InvalidEnclaveId;

impl EnclaveId {
    /// The ID for a key commitment.
    #[must_use]
    pub fn from_commitment(commitment: [u8; 32]) -> Self {
        Self(
            commitment
                .iter()
                .fold(String::with_capacity(64), |mut hex, byte| {
                    let _ = write!(hex, "{byte:02x}");
                    hex
                }),
        )
    }

    /// The hex form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EnclaveId {
    type Error = InvalidEnclaveId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let valid = value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if valid {
            Ok(Self(value))
        } else {
            Err(InvalidEnclaveId)
        }
    }
}

impl From<EnclaveId> for String {
    fn from(id: EnclaveId) -> Self {
        id.0
    }
}

impl fmt::Display for EnclaveId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::EnclaveId;

    #[test]
    fn a_commitment_becomes_lower_case_hex() {
        let id = EnclaveId::from_commitment([0xab; 32]);

        assert_eq!(id.as_str(), "ab".repeat(32));
        assert_eq!(EnclaveId::try_from(id.as_str().to_owned()), Ok(id));
    }

    #[test]
    fn anything_else_is_rejected() {
        for value in [
            "ab".repeat(31),
            "AB".repeat(32),
            "zz".repeat(32),
            String::new(),
        ] {
            assert!(EnclaveId::try_from(value.clone()).is_err(), "{value}");
        }
    }
}
