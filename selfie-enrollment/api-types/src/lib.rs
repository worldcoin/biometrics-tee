//! Public enrollment messages. One assignment, then one sealed request and response.
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = MAX_IMAGE_BYTES + 8192;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 + 8192;
pub const MAX_CONTROL_BYTES: usize = 32 * 1024;
pub const PROFILE: &str = "selfie-enrollment/vanilla-selfie/v1";
pub const CHANNEL_DOMAIN: &str = "selfie-enrollment/embedding/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub attestation: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    AssignmentRequest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostMessage {
    Assignment(Assignment),
}

/// The same error envelope used by Flamingo.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub allow_retry: bool,
    pub error: ErrorBody,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
}
impl From<ErrorCode> for ErrorEnvelope {
    fn from(code: ErrorCode) -> Self {
        Self {
            allow_retry: !matches!(code, ErrorCode::InvalidMessage),
            error: ErrorBody {
                code,
                message: code.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    #[error("invalid enrollment message")]
    InvalidMessage,
    #[error("enrollment service at capacity")]
    Busy,
    #[error("enrollment deadline exceeded")]
    Timeout,
    #[error("enclave unavailable")]
    Unavailable,
    #[error("assignment no longer usable")]
    ReassignRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_frames_match_flamingos_flat_wire_format() {
        assert_eq!(
            serde_json::to_value(ClientMessage::AssignmentRequest).unwrap(),
            serde_json::json!({"type":"assignment_request"})
        );
        let assignment = HostMessage::Assignment(Assignment {
            attestation: "AQ==".into(),
            public_key: "Ag==".into(),
        });
        let json =
            serde_json::json!({"type":"assignment","attestation":"AQ==","public_key":"Ag=="});
        assert_eq!(serde_json::to_value(&assignment).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<HostMessage>(json).unwrap(),
            assignment
        );
        let error = serde_json::to_value(ErrorEnvelope::from(ErrorCode::ReassignRequired)).unwrap();
        assert_eq!(error["allowRetry"], true);
        assert_eq!(error["error"]["code"], "reassign_required");
        assert!(serde_json::from_str::<ClientMessage>(r#"{"type":"unknown"}"#).is_err());
    }
}
