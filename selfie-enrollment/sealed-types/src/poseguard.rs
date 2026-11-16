//! Session-bound batch enrollment and authenticated replies over the sealed channel.
use crate::{EnrollmentResult, Error, PADDED_RESULT_BYTES, decode, decode_padded};
use hmac::{Hmac, Mac};
use selfie_enrollment_api_types::{
    MAX_BATCH_IMAGE_BYTES, MAX_BATCH_REQUEST_BYTES, MAX_CONTROL_BYTES, MAX_IMAGE_BYTES,
    PADDED_ENROLLMENT_RESULT_BYTES, POSEGUARD_CHALLENGE_COUNT, POSEGUARD_SESSION_TTL_SECS,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const VERSION: u32 = 3;
const TAG_BYTES: usize = 32;
const REPLY_DOMAIN: &[u8] = b"selfie-enrollment/poseguard-batch-v1/reply\0";

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
pub struct CaptureBatch {
    #[serde(with = "serde_bytes")]
    pub central_png: Vec<u8>,
    pub challenges: [ChallengeImage; POSEGUARD_CHALLENGE_COUNT],
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct ChallengeImage(#[serde(with = "serde_bytes")] pub Vec<u8>);
impl CaptureBatch {
    pub fn validate(&self) -> Result<(), Error> {
        if !self.central_png.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(Error);
        }
        let images = std::iter::once(&self.central_png).chain(self.challenges.iter().map(|c| &c.0));
        let mut total = 0_usize;
        for image in images {
            if image.is_empty() || image.len() > MAX_IMAGE_BYTES {
                return Err(Error);
            }
            total = total.checked_add(image.len()).ok_or(Error)?;
        }
        if total > MAX_BATCH_IMAGE_BYTES {
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
#[derive(Serialize, Deserialize, Zeroize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Begin {
        sub: String,
        custody_public_key: [u8; 32],
        auth_key: [u8; 32],
    },
    Submit {
        session_id: [u8; 32],
        capture: CaptureBatch,
    },
    Cancel {
        session_id: [u8; 32],
    },
}
impl Request {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        let limit = match &self.action {
            Action::Submit { capture, .. } => {
                capture.central_png.len()
                    + capture.challenges.iter().map(|c| c.0.len()).sum::<usize>()
                    + 4096
            }
            _ => MAX_CONTROL_BYTES,
        };
        crate::encode_bounded(self, limit)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_BATCH_REQUEST_BYTES {
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
            Action::Begin {
                sub,
                auth_key,
                custody_public_key,
            } => {
                if sub.is_empty()
                    || sub.len() > 66
                    || *auth_key == [0; 32]
                    || *custody_public_key == [0; 32]
                {
                    return Err(Error);
                }
            }
            Action::Submit {
                session_id,
                capture,
            } => {
                if *session_id == [0; 32] {
                    return Err(Error);
                }
                capture.validate()?;
            }
            Action::Cancel { session_id } if *session_id == [0; 32] => return Err(Error),
            Action::Cancel { .. } => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub session_id: [u8; 32],
    pub targets: [PoseTarget; POSEGUARD_CHALLENGE_COUNT],
    pub expires_in_ms: u64,
}
#[derive(Serialize, Deserialize, Zeroize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Challenge { challenge: Challenge },
    Enrollment { result: EnrollmentResult },
    Cancelled,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub nonce: [u8; 32],
    pub session_id: [u8; 32],
    pub outcome: Outcome,
}
impl Reply {
    fn size(&self) -> usize {
        match self.outcome {
            Outcome::Enrollment { .. } => PADDED_ENROLLMENT_RESULT_BYTES,
            _ => PADDED_RESULT_BYTES,
        }
    }
    fn validate(&self) -> Result<(), Error> {
        if self.nonce == [0; 32] || self.session_id == [0; 32] {
            return Err(Error);
        }
        match &self.outcome {
            Outcome::Challenge { challenge } => {
                if challenge.session_id != self.session_id
                    || challenge.expires_in_ms == 0
                    || challenge.expires_in_ms > POSEGUARD_SESSION_TTL_SECS * 1000
                {
                    return Err(Error);
                }
                for target in &challenge.targets {
                    target.validate()?;
                }
            }
            Outcome::Enrollment { result } => result.validate()?,
            Outcome::Cancelled => {}
        }
        Ok(())
    }
    pub fn encode_authenticated(&self, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        let size = self.size();
        let mut bytes = Zeroizing::new(vec![0; size + TAG_BYTES]);
        let mut remaining = &mut bytes[4..size];
        ciborium::into_writer(self, &mut remaining).map_err(|_| Error)?;
        let length = u32::try_from(size - 4 - remaining.len()).map_err(|_| Error)?;
        bytes[..4].copy_from_slice(&length.to_be_bytes());
        let mut mac = authenticator(key)?;
        mac.update(&bytes[..size]);
        bytes[size..].copy_from_slice(&mac.finalize().into_bytes());
        Ok(bytes)
    }
    pub fn decode_authenticated(
        bytes: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<Self, Error> {
        let size = bytes.len().checked_sub(TAG_BYTES).ok_or(Error)?;
        if size != PADDED_RESULT_BYTES && size != PADDED_ENROLLMENT_RESULT_BYTES {
            return Err(Error);
        }
        let mut mac = authenticator(key)?;
        mac.update(&bytes[..size]);
        mac.verify_slice(&bytes[size..]).map_err(|_| Error)?;
        let reply: Self = decode_padded(&bytes[..size], size)?;
        reply.validate()?;
        if reply.nonce != *nonce || reply.size() != size {
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
    fn batch() -> CaptureBatch {
        CaptureBatch {
            central_png: b"\x89PNG\r\n\x1a\ncentral".to_vec(),
            challenges: std::array::from_fn(|i| ChallengeImage(vec![i as u8 + 1])),
        }
    }
    fn submit() -> Request {
        Request {
            version: VERSION,
            nonce: [1; 32],
            action: Action::Submit {
                session_id: [2; 32],
                capture: batch(),
            },
        }
    }
    #[test]
    fn exactly_three_challenges_and_no_client_targets() {
        let request = submit();
        assert!(Request::decode(&request.encode().unwrap()).is_ok());
        let mut value = serde_json::to_value(&request).unwrap();
        for count in [0, 2, 4] {
            value["action"]["capture"]["challenges"] = serde_json::json!(vec![vec![1]; count]);
            let bytes = crate::encode(&value).unwrap();
            assert!(Request::decode(&bytes).is_err());
        }
        let mut value = serde_json::to_value(&request).unwrap();
        value["action"]["capture"]["targets"] = serde_json::json!([{"pitch":0,"yaw":0}]);
        assert!(Request::decode(&crate::encode(&value).unwrap()).is_err());
    }
    #[test]
    fn central_png_and_per_image_limits_are_enforced_before_encoding() {
        let mut request = submit();
        let Action::Submit { capture, .. } = &mut request.action else {
            unreachable!()
        };
        capture.central_png = b"jpeg".to_vec();
        assert!(request.encode().is_err());
        let mut request = submit();
        let Action::Submit { capture, .. } = &mut request.action else {
            unreachable!()
        };
        capture.challenges[1].0 = vec![0; MAX_IMAGE_BYTES + 1];
        assert!(request.encode().is_err());
        let mut request = submit();
        let Action::Submit { capture, .. } = &mut request.action else {
            unreachable!()
        };
        capture.challenges[2].0.clear();
        assert!(request.encode().is_err());
    }
    #[test]
    fn four_maximum_images_fit_the_batch_transport_budget() {
        let mut request = submit();
        let Action::Submit { capture, .. } = &mut request.action else {
            unreachable!()
        };
        capture.central_png.resize(MAX_IMAGE_BYTES, 0);
        for image in &mut capture.challenges {
            image.0.resize(MAX_IMAGE_BYTES, 1);
        }
        let bytes = request.encode().unwrap();
        assert!(bytes.len() > MAX_BATCH_IMAGE_BYTES);
        assert!(bytes.len() + 4096 <= MAX_BATCH_REQUEST_BYTES);
        assert!(Request::decode(&bytes).is_ok());
    }
    #[test]
    fn replies_require_authentication_nonce_and_valid_padding() {
        let reply = Reply {
            nonce: [1; 32],
            session_id: [2; 32],
            outcome: Outcome::Challenge {
                challenge: Challenge {
                    session_id: [2; 32],
                    targets: [PoseTarget { pitch: 15, yaw: 25 }; 3],
                    expires_in_ms: 90_000,
                },
            },
        };
        let key = [3; 32];
        let bytes = reply.encode_authenticated(&key).unwrap();
        assert_eq!(bytes.len(), PADDED_RESULT_BYTES + TAG_BYTES);
        assert!(Reply::decode_authenticated(&bytes, &key, &reply.nonce).is_ok());
        assert!(Reply::decode_authenticated(&bytes, &[4; 32], &reply.nonce).is_err());
        assert!(Reply::decode_authenticated(&bytes, &key, &[5; 32]).is_err());
        let mut changed = bytes.to_vec();
        changed[100] ^= 1;
        assert!(Reply::decode_authenticated(&changed, &key, &reply.nonce).is_err());
        assert!(
            Reply::decode_authenticated(&bytes[..bytes.len() - 1], &key, &reply.nonce).is_err()
        );
    }
}
