//! Authenticated shadow-evaluation messages. These results never authorize enrollment.
use crate::{Error, PADDED_RESULT_BYTES, decode, decode_padded, encode, encode_padded};
use hmac::{Hmac, Mac};
use selfie_enrollment_api_types::{MAX_IMAGE_BYTES, MAX_REQUEST_BYTES};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const PROFILE: &str = "poseguard-shadow-v1";
pub const VERSION: u32 = 3;
pub const MAX_EXCHANGES: u32 = selfie_enrollment_api_types::MAX_POSEGUARD_EXCHANGES;
pub const SESSION_TTL_SECS: u64 = 120;
const REPLY_DOMAIN: &[u8] = b"selfie-enrollment/poseguard-shadow-v1/reply\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct PoseTarget {
    pub pitch: i16,
    pub yaw: i16,
}
impl PoseTarget {
    pub fn validate(&self) -> Result<(), Error> {
        if !(-20..=20).contains(&self.pitch) || !(-35..=35).contains(&self.yaw) {
            return Err(Error);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub nonce: [u8; 32],
    pub action: Action,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Begin {
        auth_key: [u8; 32],
    },
    Submit {
        session_id: [u8; 32],
        sequence: u32,
        #[serde(with = "serde_bytes")]
        image: Vec<u8>,
    },
    Cancel {
        session_id: [u8; 32],
        sequence: u32,
    },
}
impl Request {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        let bytes = encode(self)?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error);
        }
        let request: Self = decode(bytes)?;
        request.validate()?;
        Ok(request)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION || self.nonce == [0; 32] {
            return Err(Error);
        }
        match &self.action {
            Action::Begin { auth_key } if *auth_key == [0; 32] => Err(Error),
            Action::Submit {
                session_id,
                sequence,
                image,
            } => {
                validate_session(session_id, *sequence)?;
                if image.is_empty() || image.len() > MAX_IMAGE_BYTES {
                    return Err(Error);
                }
                Ok(())
            }
            Action::Cancel {
                session_id,
                sequence,
            } => validate_session(session_id, *sequence),
            Action::Begin { .. } => Ok(()),
        }
    }
}
fn validate_session(session: &[u8; 32], sequence: u32) -> Result<(), Error> {
    if *session == [0; 32] || !(1..MAX_EXCHANGES).contains(&sequence) {
        return Err(Error);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    InvalidImage,
    QualityRejected,
    PoseMismatch,
    IdentityMismatch,
    AnalysisFailed,
    Expired,
    AttemptsExhausted,
    Cancelled,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Capture {
        target: Option<PoseTarget>,
        challenge_index: u32,
        sequence_attempt: u32,
        retry: Option<Rejection>,
    },
    Complete {
        passed: bool,
        reason: Option<Rejection>,
    },
}
impl Outcome {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
    fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Capture {
                target,
                challenge_index,
                sequence_attempt,
                retry,
            } => {
                if *challenge_index >= 3
                    || !(1..=3).contains(sequence_attempt)
                    || (target.is_none() && *challenge_index != 0)
                    || retry.is_some_and(|reason| {
                        !matches!(
                            reason,
                            Rejection::InvalidImage
                                | Rejection::QualityRejected
                                | Rejection::PoseMismatch
                        )
                    })
                {
                    return Err(Error);
                }
                if let Some(target) = target {
                    target.validate()?;
                }
            }
            Self::Complete { passed, reason } if *passed != reason.is_none() => return Err(Error),
            Self::Complete { .. } => {}
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub nonce: [u8; 32],
    pub session_id: [u8; 32],
    pub next_sequence: u32,
    pub outcome: Outcome,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
    tag: [u8; 32],
}
impl Reply {
    fn validate(&self) -> Result<(), Error> {
        if self.nonce == [0; 32]
            || self.session_id == [0; 32]
            || !(1..=MAX_EXCHANGES).contains(&self.next_sequence)
            || (self.next_sequence == MAX_EXCHANGES && !self.outcome.is_complete())
        {
            return Err(Error);
        }
        self.outcome.validate()
    }
    pub fn encode_authenticated(&self, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        let payload = encode(self)?;
        let mut mac = authenticator(key)?;
        mac.update(&payload);
        let envelope = Envelope {
            payload: payload.to_vec(),
            tag: mac.finalize().into_bytes().into(),
        };
        encode_padded(&envelope, PADDED_RESULT_BYTES)
    }
    pub fn decode_authenticated(
        bytes: &[u8],
        key: &[u8; 32],
        expected_nonce: &[u8; 32],
    ) -> Result<Self, Error> {
        let envelope: Envelope = decode_padded(bytes, PADDED_RESULT_BYTES)?;
        let mut mac = authenticator(key)?;
        mac.update(&envelope.payload);
        mac.verify_slice(&envelope.tag).map_err(|_| Error)?;
        let reply: Self = decode(&envelope.payload)?;
        reply.validate()?;
        if reply.nonce != *expected_nonce {
            return Err(Error);
        }
        Ok(reply)
    }
}
fn authenticator(key: &[u8; 32]) -> Result<Hmac<Sha256>, Error> {
    if *key == [0; 32] {
        return Err(Error);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error)?;
    mac.update(REPLY_DOMAIN);
    Ok(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reply() -> Reply {
        Reply {
            nonce: [1; 32],
            session_id: [2; 32],
            next_sequence: 1,
            outcome: Outcome::Capture {
                target: None,
                challenge_index: 0,
                sequence_attempt: 1,
                retry: None,
            },
        }
    }
    #[test]
    fn replies_require_the_session_key_and_current_request_nonce() {
        let bytes = reply().encode_authenticated(&[3; 32]).unwrap();
        assert!(Reply::decode_authenticated(&bytes, &[3; 32], &[1; 32]).is_ok());
        assert!(Reply::decode_authenticated(&bytes, &[4; 32], &[1; 32]).is_err());
        assert!(Reply::decode_authenticated(&bytes, &[3; 32], &[9; 32]).is_err());
        let mut envelope: Envelope = decode_padded(&bytes, PADDED_RESULT_BYTES).unwrap();
        envelope.payload[0] ^= 1;
        let tampered = encode_padded(&envelope, PADDED_RESULT_BYTES).unwrap();
        assert!(Reply::decode_authenticated(&tampered, &[3; 32], &[1; 32]).is_err());
        envelope.tag[0] ^= 1;
        let tampered = encode_padded(&envelope, PADDED_RESULT_BYTES).unwrap();
        assert!(Reply::decode_authenticated(&tampered, &[3; 32], &[1; 32]).is_err());
    }
    #[test]
    fn rejects_inconsistent_verdicts_and_out_of_range_targets() {
        for outcome in [
            Outcome::Complete {
                passed: true,
                reason: Some(Rejection::AnalysisFailed),
            },
            Outcome::Complete {
                passed: false,
                reason: None,
            },
            Outcome::Capture {
                target: Some(PoseTarget { pitch: 21, yaw: 0 }),
                challenge_index: 0,
                sequence_attempt: 1,
                retry: None,
            },
            Outcome::Capture {
                target: None,
                challenge_index: 0,
                sequence_attempt: 4,
                retry: None,
            },
        ] {
            let mut reply = reply();
            reply.outcome = outcome;
            assert!(reply.encode_authenticated(&[3; 32]).is_err());
        }
    }
    #[test]
    fn request_versions_bounds_and_secret_fields_are_validated() {
        let mut request = Request {
            version: VERSION,
            nonce: [1; 32],
            action: Action::Begin { auth_key: [2; 32] },
        };
        assert!(matches!(
            crate::Request::decode(&request.encode().unwrap()),
            Ok(crate::Request::PoseGuard(_))
        ));
        request.action = Action::Submit {
            session_id: [2; 32],
            sequence: 1,
            image: vec![1],
        };
        let mut bytes = request.encode().unwrap();
        bytes.push(0);
        assert!(Request::decode(&bytes).is_err());
        request.action = Action::Submit {
            session_id: [2; 32],
            sequence: 1,
            image: vec![0; MAX_IMAGE_BYTES + 1],
        };
        assert!(request.encode().is_err());
        request.action = Action::Cancel {
            session_id: [2; 32],
            sequence: MAX_EXCHANGES,
        };
        assert!(request.encode().is_err());
        request.action = Action::Begin { auth_key: [0; 32] };
        assert!(request.encode().is_err());
    }
}
