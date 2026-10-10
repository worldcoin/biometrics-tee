//! Plaintext types used only by the client and enclave. Sensitive buffers are redacted and erased.
use selfie_enrollment_api_types::{MAX_IMAGE_BYTES, MAX_REQUEST_BYTES, PROFILE, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io::Cursor;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const PADDED_RESULT_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingRequest {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub image: Vec<u8>,
}
impl EmbeddingRequest {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        encode(self)
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
        if self.version != PROTOCOL_VERSION
            || self.image.is_empty()
            || self.image.len() > MAX_IMAGE_BYTES
        {
            return Err(Error);
        }
        Ok(())
    }
}

/// The executable digest is SHA-384 of the verified binary, not the S3 archive hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
pub struct WorkerIdentity {
    pub profile: String,
    pub executable_sha384: String,
}
impl WorkerIdentity {
    pub fn validate(&self) -> Result<(), Error> {
        if self.profile != PROFILE
            || self.executable_sha384.len() != 96
            || !self
                .executable_sha384
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.executable_sha384.bytes().all(|b| b == b'0')
        {
            return Err(Error);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        encode(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 512 {
            return Err(Error);
        }
        let result: Self = decode(bytes)?;
        result.validate()?;
        Ok(result)
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Embedding {
    /// Existing worker vector encoding, retained verbatim.
    pub vector: String,
    pub embedding_type: String,
    pub version: String,
    pub inference_backend: String,
    pub worker: WorkerIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    InvalidImage,
    QualityRejected,
    ExtractionFailed,
    Busy,
    InvalidRequest,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum EmbeddingResult {
    Success { embedding: Embedding },
    Failed { reason: Failure },
}
impl EmbeddingResult {
    fn validate(&self) -> Result<(), Error> {
        if let Self::Success { embedding: e } = self {
            e.worker.validate()?;
            if e.vector.is_empty()
                || e.vector.len() > 4096
                || e.embedding_type.is_empty()
                || e.embedding_type.len() > 128
                || e.version.is_empty()
                || e.version.len() > 128
                || e.inference_backend.is_empty()
                || e.inference_backend.len() > 128
            {
                return Err(Error);
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        let body = encode(self)?;
        if body.len() > PADDED_RESULT_BYTES - 4 {
            return Err(Error);
        }
        let mut padded = Zeroizing::new(vec![0; PADDED_RESULT_BYTES]);
        padded[..4].copy_from_slice(&(body.len() as u32).to_be_bytes());
        padded[4..4 + body.len()].copy_from_slice(&body);
        Ok(padded)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PADDED_RESULT_BYTES {
            return Err(Error);
        }
        let size = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error)?) as usize;
        if size > PADDED_RESULT_BYTES - 4 || bytes[4 + size..].iter().any(|&b| b != 0) {
            return Err(Error);
        }
        let result: Self = decode(&bytes[4..4 + size])?;
        result.validate()?;
        Ok(result)
    }
}
#[derive(Debug, thiserror::Error)]
#[error("invalid enrollment plaintext")]
pub struct Error;
fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buffer = Zeroizing::new(Vec::new());
    ciborium::into_writer(value, &mut *buffer).map_err(|_| Error)?;
    Ok(buffer)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::from_reader(&mut cursor).map_err(|_| Error)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error);
    }
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_rejects_empty_oversized_and_trailing_bytes() {
        let mut request = EmbeddingRequest {
            version: 1,
            image: vec![1],
        };
        let mut encoded = request.encode().unwrap();
        assert!(EmbeddingRequest::decode(&encoded).is_ok());
        encoded.push(0);
        assert!(EmbeddingRequest::decode(&encoded).is_err());
        request.image.clear();
        assert!(request.encode().is_err());
        request.image.resize(MAX_IMAGE_BYTES + 1, 0);
        assert!(request.encode().is_err());
    }
    #[test]
    fn responses_are_padded_and_reject_corruption() {
        let response = EmbeddingResult::Failed {
            reason: Failure::InvalidImage,
        };
        let mut encoded = response.encode().unwrap();
        assert_eq!(encoded.len(), PADDED_RESULT_BYTES);
        assert!(EmbeddingResult::decode(&encoded).is_ok());
        encoded[PADDED_RESULT_BYTES - 1] = 1;
        assert!(EmbeddingResult::decode(&encoded).is_err());
        assert!(EmbeddingResult::decode(&encoded[..8]).is_err());
    }
}
