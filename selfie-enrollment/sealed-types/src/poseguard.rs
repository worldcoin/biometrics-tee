use crate::{Error, MAX_SUB_BYTES, decode, decode_padded, encode, encode_padded};
use selfie_enrollment_api_types::{
    ENROLLMENT_PROTOCOL_VERSION, MAX_CONTROL_BYTES, MAX_IMAGE_BYTES, MAX_POSEGUARD_REQUEST_BYTES,
    POSEGUARD_CHALLENGE_COUNT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An image paired with its issued target angles in degrees.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PoseGuardCapture {
    #[serde(with = "serde_bytes")]
    pub image: Vec<u8>,
    pub target_pitch: f32,
    pub target_yaw: f32,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PoseGuardEnrollmentRequest {
    pub version: u32,
    pub operation: EnrollmentOperation,
    #[serde(with = "serde_bytes")]
    pub central_png: Vec<u8>,
    pub captures: [PoseGuardCapture; POSEGUARD_CHALLENGE_COUNT],
    pub sub: String,
    #[serde(with = "serde_bytes")]
    pub custody_public_key: Vec<u8>,
    pub challenge_token: [u8; 32],
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub enum EnrollmentOperation {
    #[serde(rename = "enroll_with_poseguard")]
    EnrollWithPoseGuard,
    #[serde(rename = "generate_poseguard_targets")]
    GeneratePoseGuardTargets,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct PoseGuardTarget {
    pub target_pitch: f32,
    pub target_yaw: f32,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct GeneratePoseGuardTargetsRequest {
    pub version: u32,
    pub operation: EnrollmentOperation,
    pub sub: String,
    #[serde(with = "serde_bytes")]
    pub custody_public_key: Vec<u8>,
    pub nonce: [u8; 32],
}

impl GeneratePoseGuardTargetsRequest {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        encode(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_CONTROL_BYTES {
            return Err(Error);
        }
        let request: Self = decode(bytes)?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.version != ENROLLMENT_PROTOCOL_VERSION
            || self.operation != EnrollmentOperation::GeneratePoseGuardTargets
            || self.sub.is_empty()
            || self.sub.len() > MAX_SUB_BYTES
            || self.custody_public_key.len() != 32
            || self.nonce == [0; 32]
        {
            return Err(Error);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PoseGuardChallenge {
    pub challenge_token: [u8; 32],
    pub targets: [PoseGuardTarget; POSEGUARD_CHALLENGE_COUNT],
    /// Unix seconds for display; the enclave enforces a monotonic deadline.
    pub expires_at: u64,
}

impl PoseGuardChallenge {
    /// Binds the response to this request, identity and the assigned enclave boot.
    pub fn attestation_nonce(
        &self,
        request: &GeneratePoseGuardTargetsRequest,
        channel_commitment: &[u8; 32],
    ) -> Result<[u8; 32], Error> {
        request.validate()?;
        self.validate()?;
        let bytes = encode(&(
            "selfie-enrollment/poseguard-targets/v1",
            request,
            channel_commitment,
            self,
        ))?;
        Ok(Sha256::digest(&bytes).into())
    }

    fn validate(&self) -> Result<(), Error> {
        if self.challenge_token == [0; 32] || self.expires_at == 0 {
            return Err(Error);
        }
        for target in &self.targets {
            if !(-20.0..=20.0).contains(&target.target_pitch)
                || !(-35.0..=35.0).contains(&target.target_yaw)
            {
                return Err(Error);
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PoseGuardTargetsResult {
    pub challenge: PoseGuardChallenge,
    #[serde(with = "serde_bytes")]
    pub attestation: Vec<u8>,
}

impl PoseGuardTargetsResult {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.challenge.validate()?;
        encode_padded(self, MAX_CONTROL_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let result: Self = decode_padded(bytes, MAX_CONTROL_BYTES)?;
        result.challenge.validate()?;
        Ok(result)
    }
}

impl PoseGuardEnrollmentRequest {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        let limit = self.central_png.len()
            + self
                .captures
                .iter()
                .map(|capture| capture.image.len())
                .sum::<usize>()
            + 4096;
        let mut writer = BoundedWriter {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        };
        ciborium::into_writer(self, &mut writer).map_err(|_| Error)?;
        Ok(writer.bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_POSEGUARD_REQUEST_BYTES {
            return Err(Error);
        }
        let request: Self = decode(bytes)?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.version != ENROLLMENT_PROTOCOL_VERSION
            || self.operation != EnrollmentOperation::EnrollWithPoseGuard
            || self.challenge_token == [0; 32]
            || !self.central_png.starts_with(b"\x89PNG\r\n\x1a\n")
            || self.central_png.len() > MAX_IMAGE_BYTES
            || self.sub.is_empty()
            || self.sub.len() > MAX_SUB_BYTES
            || self.custody_public_key.len() != 32
        {
            return Err(Error);
        }
        for capture in &self.captures {
            capture.validate()?;
        }
        Ok(())
    }
}

impl PoseGuardCapture {
    pub fn validate(&self) -> Result<(), Error> {
        if self.image.is_empty()
            || self.image.len() > MAX_IMAGE_BYTES
            || !(-20.0..=20.0).contains(&self.target_pitch)
            || !(-35.0..=35.0).contains(&self.target_yaw)
        {
            return Err(Error);
        }
        Ok(())
    }
}

struct BoundedWriter {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::other("enrollment request too large"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EmbeddingRequest, EnrollmentRequest, Request, encode};
    use selfie_enrollment_api_types::{
        ENROLLMENT_PROTOCOL_VERSION, MAX_REQUEST_BYTES, PROTOCOL_VERSION,
    };

    #[test]
    fn challenge_attestation_binds_targets_identity_freshness_and_enclave_boot() {
        let mut input = GeneratePoseGuardTargetsRequest {
            version: ENROLLMENT_PROTOCOL_VERSION,
            operation: EnrollmentOperation::GeneratePoseGuardTargets,
            sub: "0x1f".into(),
            custody_public_key: vec![7; 32],
            nonce: [8; 32],
        };
        let mut challenge = PoseGuardChallenge {
            challenge_token: [9; 32],
            expires_at: 123,
            targets: [PoseGuardTarget {
                target_pitch: 15.0,
                target_yaw: 25.0,
            }; 3],
        };
        let digest = challenge.attestation_nonce(&input, &[1; 32]).unwrap();
        assert_ne!(
            digest,
            challenge.attestation_nonce(&input, &[2; 32]).unwrap()
        );
        input.sub = "0x20".into();
        assert_ne!(
            digest,
            challenge.attestation_nonce(&input, &[1; 32]).unwrap()
        );
        input.sub = "0x1f".into();
        input.custody_public_key[0] ^= 1;
        assert_ne!(
            digest,
            challenge.attestation_nonce(&input, &[1; 32]).unwrap()
        );
        input.custody_public_key[0] ^= 1;
        input.nonce[0] ^= 1;
        assert_ne!(
            digest,
            challenge.attestation_nonce(&input, &[1; 32]).unwrap()
        );
        input.nonce[0] ^= 1;
        challenge.challenge_token[0] ^= 1;
        assert_ne!(
            digest,
            challenge.attestation_nonce(&input, &[1; 32]).unwrap()
        );
        challenge.challenge_token[0] ^= 1;
        challenge.expires_at += 1;
        assert_ne!(
            digest,
            challenge.attestation_nonce(&input, &[1; 32]).unwrap()
        );
        challenge.expires_at -= 1;
        challenge.targets[0].target_pitch += 1.0;
        assert_ne!(
            digest,
            challenge.attestation_nonce(&input, &[1; 32]).unwrap()
        );
    }

    #[test]
    fn target_generation_uses_the_existing_version_and_a_bounded_response() {
        let mut input = GeneratePoseGuardTargetsRequest {
            version: ENROLLMENT_PROTOCOL_VERSION,
            operation: EnrollmentOperation::GeneratePoseGuardTargets,
            sub: "0x1f".into(),
            custody_public_key: vec![7; 32],
            nonce: [8; 32],
        };
        assert!(matches!(
            Request::decode(&input.encode().unwrap()).unwrap(),
            Request::GeneratePoseGuardTargets(_)
        ));
        input.operation = EnrollmentOperation::EnrollWithPoseGuard;
        assert!(input.encode().is_err());
        input.operation = EnrollmentOperation::GeneratePoseGuardTargets;
        input.nonce = [0; 32];
        assert!(input.encode().is_err());
        let mut result = PoseGuardTargetsResult {
            challenge: PoseGuardChallenge {
                challenge_token: [9; 32],
                expires_at: 123,
                targets: [PoseGuardTarget {
                    target_pitch: 15.0,
                    target_yaw: 25.0,
                }; 3],
            },
            attestation: vec![1; 100],
        };
        let bytes = result.encode().unwrap();
        assert_eq!(bytes.len(), MAX_CONTROL_BYTES);
        assert!(PoseGuardTargetsResult::decode(&bytes).is_ok());
        assert!(PoseGuardTargetsResult::decode(&bytes[..bytes.len() - 1]).is_err());
        result.attestation.resize(MAX_CONTROL_BYTES, 1);
        assert!(result.encode().is_err());
    }

    #[test]
    fn batch_roundtrips_above_the_legacy_limit_without_relaxing_legacy_requests() {
        let mut request = request();
        for capture in &mut request.captures {
            capture.image.resize(MAX_IMAGE_BYTES / 2, 1);
        }
        let encoded = request.encode().unwrap();
        assert!(encoded.len() > MAX_REQUEST_BYTES);
        let Ok(Request::PoseGuardEnrollment(decoded)) = Request::decode(&encoded) else {
            panic!("expected PoseGuard")
        };
        assert_eq!(decoded.central_png, request.central_png);
        for (actual, expected) in decoded.captures.iter().zip(&request.captures) {
            assert_eq!(actual.image, expected.image);
            assert_eq!(actual.target_pitch, expected.target_pitch);
            assert_eq!(actual.target_yaw, expected.target_yaw);
        }
        let legacy = EnrollmentRequest {
            version: ENROLLMENT_PROTOCOL_VERSION,
            image: vec![1; MAX_IMAGE_BYTES + 1],
            sub: "0x1f".into(),
            custody_public_key: vec![7; 32],
        };
        assert!(Request::decode(&encode(&legacy).unwrap()).is_err());
        let embedding = EmbeddingRequest {
            version: PROTOCOL_VERSION,
            image: vec![1; MAX_IMAGE_BYTES + 1],
        };
        assert!(Request::decode(&encode(&embedding).unwrap()).is_err());
        let mut trailing = request.encode().unwrap();
        trailing.push(0);
        assert!(Request::decode(&trailing).is_err());
    }

    #[test]
    fn poseguard_keeps_enrollment_version_and_requires_its_operation_tag() {
        let bytes = request().encode().unwrap();
        let mut value: ciborium::Value = decode(&bytes).unwrap();
        let ciborium::Value::Map(fields) = &mut value else {
            panic!()
        };
        let field = |name| {
            fields
                .iter()
                .find(|(key, _)| key.as_text() == Some(name))
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(
            field("version"),
            ciborium::Value::Integer(ENROLLMENT_PROTOCOL_VERSION.into())
        );
        assert_eq!(
            field("operation"),
            ciborium::Value::Text("enroll_with_poseguard".into())
        );
        for (version, operation) in [
            (ENROLLMENT_PROTOCOL_VERSION, None),
            (ENROLLMENT_PROTOCOL_VERSION, Some("unknown")),
            (PROTOCOL_VERSION, Some("enroll_with_poseguard")),
            (3, Some("enroll_with_poseguard")),
        ] {
            let mut value: ciborium::Value = decode(&bytes).unwrap();
            let ciborium::Value::Map(fields) = &mut value else {
                panic!()
            };
            fields.retain(|(key, _)| !matches!(key.as_text(), Some("version" | "operation")));
            fields.push(("version".into(), version.into()));
            if let Some(operation) = operation {
                fields.push(("operation".into(), operation.into()));
            }
            assert!(Request::decode(&encode(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn rejects_bad_images_targets_counts_and_metadata() {
        for change in [
            (|r: &mut PoseGuardEnrollmentRequest| r.central_png.clear())
                as fn(&mut PoseGuardEnrollmentRequest),
            |r| r.central_png.resize(MAX_IMAGE_BYTES + 1, 0),
            |r| r.captures[0].image.clear(),
            |r| r.captures[0].image.resize(MAX_IMAGE_BYTES + 1, 0),
            |r| r.captures[0].target_pitch = f32::NAN,
            |r| r.captures[0].target_yaw = f32::INFINITY,
            |r| r.captures[0].target_pitch = 20.1,
            |r| r.captures[0].target_yaw = -35.1,
            |r| r.sub.clear(),
            |r| r.custody_public_key.clear(),
            |r| r.version = PROTOCOL_VERSION,
        ] {
            let mut request = request();
            change(&mut request);
            assert!(request.encode().is_err());
            assert!(PoseGuardEnrollmentRequest::decode(&encode(&request).unwrap()).is_err());
        }
        for count in [2, 4] {
            let mut value: ciborium::Value = decode(&request().encode().unwrap()).unwrap();
            let ciborium::Value::Map(fields) = &mut value else {
                panic!()
            };
            let (_, ciborium::Value::Array(captures)) = fields
                .iter_mut()
                .find(|(key, _)| key.as_text() == Some("captures"))
                .unwrap()
            else {
                panic!()
            };
            captures.resize(count, captures[0].clone());
            assert!(Request::decode(&encode(&value).unwrap()).is_err());
        }
    }

    fn request() -> PoseGuardEnrollmentRequest {
        PoseGuardEnrollmentRequest {
            version: ENROLLMENT_PROTOCOL_VERSION,
            operation: EnrollmentOperation::EnrollWithPoseGuard,
            central_png: b"\x89PNG\r\n\x1a\nfixture".to_vec(),
            captures: std::array::from_fn(|i| PoseGuardCapture {
                image: vec![i as u8 + 1],
                target_pitch: 10.0 + i as f32,
                target_yaw: -20.0 - i as f32,
            }),
            sub: "0x1f".into(),
            custody_public_key: vec![7; 32],
            challenge_token: [1; 32],
        }
    }
}
