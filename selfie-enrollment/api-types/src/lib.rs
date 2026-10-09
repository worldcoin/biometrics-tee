//! Public enrollment wire messages and test-admission verification. No biometric plaintext.
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = MAX_IMAGE_BYTES + 8192;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 + 8192;
pub const MAX_CONTROL_BYTES: usize = 32 * 1024;
pub const MAX_TICKET_BYTES: usize = 2048;
pub const PROFILE: &str = "selfie-enrollment/vanilla-selfie/v1";
pub const CHANNEL_DOMAIN: &str = "selfie-enrollment/embedding/v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub attestation: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionChallenge {
    pub audience: String,
    pub nonce: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ServerMessage {
    Admission(AdmissionChallenge),
    Assignment(Assignment),
    Error { code: ErrorCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    #[error("invalid enrollment message")]
    InvalidMessage,
    #[error("admission rejected")]
    Unauthorized,
    #[error("enrollment service at capacity")]
    Busy,
    #[error("enrollment deadline exceeded")]
    Timeout,
    #[error("enclave unavailable")]
    Unavailable,
    #[error("assignment no longer usable")]
    ReassignRequired,
}

/// P256 signature over a domain-separated, unambiguous tuple. Private signing keys
/// belong to the test issuer, never browser code or this service.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTicket {
    pub expires_at: u64,
    pub signature: String,
}

pub fn ticket_message(challenge: &AdmissionChallenge, expires_at: u64) -> Vec<u8> {
    serde_json::to_vec(&(
        "selfie-enrollment/admission/v1",
        &challenge.audience,
        challenge.nonce,
        expires_at,
    ))
    .expect("fixed tuple serialization cannot fail")
}

pub fn verify_ticket(
    key: &VerifyingKey,
    challenge: &AdmissionChallenge,
    ticket: &AdmissionTicket,
    now: u64,
) -> Result<(), ErrorCode> {
    if ticket.expires_at <= now
        || ticket.expires_at.saturating_sub(now) > 60
        || ticket.signature.len() != 128
        || challenge.audience.len() > 256
    {
        return Err(ErrorCode::Unauthorized);
    }
    let bytes = hex::decode(&ticket.signature).map_err(|_| ErrorCode::Unauthorized)?;
    let signature = Signature::from_slice(&bytes).map_err(|_| ErrorCode::Unauthorized)?;
    key.verify(&ticket_message(challenge, ticket.expires_at), &signature)
        .map_err(|_| ErrorCode::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};
    #[test]
    fn tickets_bind_connection_audience_and_expiry() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let challenge = AdmissionChallenge {
            audience: "stage".into(),
            nonce: [9; 32],
        };
        let signature: Signature = key.sign(&ticket_message(&challenge, 120));
        let ticket = AdmissionTicket {
            expires_at: 120,
            signature: hex::encode(signature.to_bytes()),
        };
        assert!(verify_ticket(key.verifying_key(), &challenge, &ticket, 100).is_ok());
        for now in [59, 120, 121] {
            assert!(verify_ticket(key.verifying_key(), &challenge, &ticket, now).is_err());
        }
        let mut swapped = challenge.clone();
        swapped.nonce[0] ^= 1;
        assert!(verify_ticket(key.verifying_key(), &swapped, &ticket, 100).is_err());
        swapped = challenge;
        swapped.audience = "prod".into();
        assert!(verify_ticket(key.verifying_key(), &swapped, &ticket, 100).is_err());
    }
}
