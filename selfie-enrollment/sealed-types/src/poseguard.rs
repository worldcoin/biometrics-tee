use crate::{Error, MAX_SUB_BYTES, decode};
use selfie_enrollment_api_types::{
    MAX_IMAGE_BYTES, MAX_POSEGUARD_REQUEST_BYTES, POSEGUARD_CHALLENGE_COUNT,
    POSEGUARD_ENROLLMENT_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Caller-supplied target angles in degrees, evaluated by the worker.
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
    #[serde(with = "serde_bytes")]
    pub central_png: Vec<u8>,
    pub captures: [PoseGuardCapture; POSEGUARD_CHALLENGE_COUNT],
    pub sub: String,
    #[serde(with = "serde_bytes")]
    pub custody_public_key: Vec<u8>,
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
        if self.version != POSEGUARD_ENROLLMENT_PROTOCOL_VERSION
            || !self.central_png.starts_with(b"\x89PNG\r\n\x1a\n")
            || self.central_png.len() > MAX_IMAGE_BYTES
            || self.sub.is_empty()
            || self.sub.len() > MAX_SUB_BYTES
            || self.custody_public_key.len() != 32
        {
            return Err(Error);
        }
        for capture in &self.captures {
            if capture.image.is_empty()
                || capture.image.len() > MAX_IMAGE_BYTES
                || !(-20.0..=20.0).contains(&capture.target_pitch)
                || !(-35.0..=35.0).contains(&capture.target_yaw)
            {
                return Err(Error);
            }
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
            |r| r.version = ENROLLMENT_PROTOCOL_VERSION,
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
            version: POSEGUARD_ENROLLMENT_PROTOCOL_VERSION,
            central_png: b"\x89PNG\r\n\x1a\nfixture".to_vec(),
            captures: std::array::from_fn(|i| PoseGuardCapture {
                image: vec![i as u8 + 1],
                target_pitch: 10.0 + i as f32,
                target_yaw: -20.0 - i as f32,
            }),
            sub: "0x1f".into(),
            custody_public_key: vec![7; 32],
        }
    }
}
