//! Plaintext types used only by the client and enclave. Sensitive buffers are redacted and erased.
use selfie_enrollment_api_types::{
    ENROLLMENT_PROTOCOL_VERSION, MAX_ENCRYPTED_PCP_BYTES, MAX_IMAGE_BYTES, MAX_REQUEST_BYTES,
    PADDED_ENROLLMENT_RESULT_BYTES, PROTOCOL_VERSION,
};
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

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct FaceEmbedding {
    /// Existing worker vector encoding, retained verbatim.
    pub embedding: String,
    pub embedding_type: String,
    pub embedding_version: String,
    pub embedding_inference_backend: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    InvalidImage,
    QualityRejected,
    ExtractionFailed,
    InvalidRequest,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum EmbeddingResult {
    Success { embedding: FaceEmbedding },
    Failed { reason: Failure },
}
impl EmbeddingResult {
    fn validate(&self) -> Result<(), Error> {
        if let Self::Success { embedding: e } = self
            && (e.embedding.is_empty()
                || e.embedding.len() > 4096
                || e.embedding_type.is_empty()
                || e.embedding_type.len() > 128
                || e.embedding_version.is_empty()
                || e.embedding_version.len() > 128
                || e.embedding_inference_backend.is_empty()
                || e.embedding_inference_backend.len() > 128)
        {
            return Err(Error);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        encode_padded(self, PADDED_RESULT_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let result: Self = decode_padded(bytes, PADDED_RESULT_BYTES)?;
        result.validate()?;
        Ok(result)
    }
}

/// The attested v2 web enrollment fields in submission order (signup-service#2400). The
/// browser adds `world_id_challenge_id` and the `world_id_ownership_proof` part after them.
pub const ENROLLMENT_FIELDS: [&str; 12] = [
    "contract_version",
    "sub",
    "capture_id",
    "timestamp",
    "face_embedding_shares_0",
    "face_embedding_shares_1",
    "face_embedding_shares_2",
    "face_embedding_version",
    "face_embedding_type",
    "face_embedding_inference_backend",
    "pcp_version",
    "associated_data_hash",
];
/// signup-service's per-field limit for capture text fields.
const MAX_ENROLLMENT_FIELD_BYTES: usize = 8192;
/// `0x` plus at most 64 hex digits.
const MAX_SUB_BYTES: usize = 66;
/// Standard base64 of the 12,000-byte maximum Nitro document.
const MAX_ATTESTATION_HEADER_BYTES: usize = 16_000;
const CUSTODY_PUBLIC_KEY_BYTES: usize = 32;
const SEALED_BOX_OVERHEAD_BYTES: usize = 48;

/// One capture to enroll. The canonical subject is checked by the enclave before extraction.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub version: u32,
    #[serde(with = "serde_bytes")]
    pub image: Vec<u8>,
    /// The browser's World ID 4.0 subject, in signup-service's canonical form.
    pub sub: String,
    /// X25519 key the PCP is sealed to. The private key stays in the user's wallet.
    #[serde(with = "serde_bytes")]
    pub custody_public_key: Vec<u8>,
}
impl EnrollmentRequest {
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
        if self.version != ENROLLMENT_PROTOCOL_VERSION
            || self.image.is_empty()
            || self.image.len() > MAX_IMAGE_BYTES
            || self.sub.is_empty()
            || self.sub.len() > MAX_SUB_BYTES
            || self.custody_public_key.len() != CUSTODY_PUBLIC_KEY_BYTES
        {
            return Err(Error);
        }
        Ok(())
    }
}

/// A request on the sealed channel, selected by its `version`.
pub enum Request {
    Embedding(EmbeddingRequest),
    Enrollment(EnrollmentRequest),
}
impl Request {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error);
        }
        #[derive(Deserialize)]
        struct Version {
            version: u32,
        }
        let Version { version } = decode(bytes)?;
        match version {
            PROTOCOL_VERSION => EmbeddingRequest::decode(bytes).map(Self::Embedding),
            ENROLLMENT_PROTOCOL_VERSION => EnrollmentRequest::decode(bytes).map(Self::Enrollment),
            _ => Err(Error),
        }
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentField {
    pub name: String,
    pub value: String,
}

/// What the enclave returns for submission. Shares and the PCP are encrypted; the image,
/// embedding and plaintext shares never leave the enclave.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBundle {
    /// [`ENROLLMENT_FIELDS`] in order, as multipart text values.
    pub fields: Vec<EnrollmentField>,
    /// Standard base64 COSE_Sign1 for the `X-Nitro-Attestation` header.
    pub attestation_header: String,
    /// The user's Face PCP, sealed to the request's custody key.
    #[serde(with = "serde_bytes")]
    pub encrypted_custody: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentResult {
    Success { enrollment: EnrollmentBundle },
    Failed { reason: Failure },
}
impl EnrollmentResult {
    fn validate(&self) -> Result<(), Error> {
        let Self::Success { enrollment } = self else {
            return Ok(());
        };
        let fields_valid = enrollment.fields.len() == ENROLLMENT_FIELDS.len()
            && enrollment
                .fields
                .iter()
                .zip(ENROLLMENT_FIELDS)
                .all(|(field, name)| {
                    field.name == name
                        && !field.value.is_empty()
                        && field.value.len() <= MAX_ENROLLMENT_FIELD_BYTES
                });
        let header = &enrollment.attestation_header;
        let header_valid = !header.is_empty()
            && header.len() <= MAX_ATTESTATION_HEADER_BYTES
            && header
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        let custody = enrollment.encrypted_custody.len();
        if !fields_valid
            || !header_valid
            || !(SEALED_BOX_OVERHEAD_BYTES + 1..=MAX_ENCRYPTED_PCP_BYTES).contains(&custody)
        {
            return Err(Error);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.validate()?;
        encode_padded(self, PADDED_ENROLLMENT_RESULT_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let result: Self = decode_padded(bytes, PADDED_ENROLLMENT_RESULT_BYTES)?;
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
/// A big-endian `u32` body length, the body, then zeros up to exactly `size` bytes.
fn encode_padded<T: Serialize>(value: &T, size: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let body = encode(value)?;
    if body.len() > size - 4 {
        return Err(Error);
    }
    let mut padded = Zeroizing::new(vec![0; size]);
    padded[..4].copy_from_slice(&(body.len() as u32).to_be_bytes());
    padded[4..4 + body.len()].copy_from_slice(&body);
    Ok(padded)
}
fn decode_padded<T: DeserializeOwned>(bytes: &[u8], size: usize) -> Result<T, Error> {
    if bytes.len() != size {
        return Err(Error);
    }
    let length = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Error)?) as usize;
    if length > size - 4 || bytes[4 + length..].iter().any(|&b| b != 0) {
        return Err(Error);
    }
    decode(&bytes[4..4 + length])
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
    fn face_pcp_success_schema_roundtrips() {
        // Frozen CBOR using the existing Face PCP embedding field names.
        let body = b"\xa2fstatusgsuccessiembedding\xa4iembeddingdAQ==nembedding_typex\x19ghostfacenet_flipped_meanqembedding_versione2.0.0x\x1bembedding_inference_backendkface-engine";
        let mut frame = vec![0; PADDED_RESULT_BYTES];
        frame[..4].copy_from_slice(&(body.len() as u32).to_be_bytes());
        frame[4..4 + body.len()].copy_from_slice(body);
        let result = EmbeddingResult::decode(&frame).unwrap();
        let EmbeddingResult::Success { embedding } = &result else {
            panic!("expected embedding")
        };
        assert_eq!(embedding.embedding, "AQ==");
        assert_eq!(embedding.embedding_type, "ghostfacenet_flipped_mean");
        assert_eq!(embedding.embedding_version, "2.0.0");
        assert_eq!(embedding.embedding_inference_backend, "face-engine");
        assert_eq!(&*result.encode().unwrap(), &frame);
    }
    fn enrollment_request() -> EnrollmentRequest {
        EnrollmentRequest {
            version: ENROLLMENT_PROTOCOL_VERSION,
            image: vec![1],
            sub: "0x1f".into(),
            custody_public_key: vec![7; 32],
        }
    }
    fn bundle() -> EnrollmentBundle {
        EnrollmentBundle {
            fields: ENROLLMENT_FIELDS
                .iter()
                .map(|name| EnrollmentField {
                    name: (*name).into(),
                    value: "v".into(),
                })
                .collect(),
            attestation_header: "ZG9j".into(),
            encrypted_custody: vec![9; 64],
        }
    }
    #[test]
    fn requests_are_selected_by_version() {
        let embedding = EmbeddingRequest {
            version: PROTOCOL_VERSION,
            image: vec![1],
        };
        assert!(matches!(
            Request::decode(&embedding.encode().unwrap()),
            Ok(Request::Embedding(_))
        ));
        let encoded = enrollment_request().encode().unwrap();
        let Ok(Request::Enrollment(decoded)) = Request::decode(&encoded) else {
            panic!("expected an enrollment request")
        };
        assert_eq!(decoded.sub, "0x1f");
        assert_eq!(decoded.custody_public_key, vec![7; 32]);
        let mut unknown = enrollment_request();
        unknown.version = 3;
        assert!(Request::decode(&encode(&unknown).unwrap()).is_err());
        // An enrollment payload labelled version 1 is not accepted as an embedding request.
        let mut mislabelled = enrollment_request();
        mislabelled.version = PROTOCOL_VERSION;
        assert!(Request::decode(&encode(&mislabelled).unwrap()).is_err());
    }
    #[test]
    fn enrollment_requests_reject_bad_keys_subjects_and_images() {
        for change in [
            (|r: &mut EnrollmentRequest| r.custody_public_key.pop())
                as fn(&mut EnrollmentRequest) -> _,
            |r| {
                r.sub.clear();
                None
            },
            |r| {
                r.sub = format!("0x{}", "f".repeat(65));
                None
            },
            |r| {
                r.image.clear();
                None
            },
        ] {
            let mut request = enrollment_request();
            change(&mut request);
            assert!(request.encode().is_err());
        }
    }
    #[test]
    fn enrollment_results_are_padded_and_validated() {
        let result = EnrollmentResult::Success {
            enrollment: bundle(),
        };
        let mut encoded = result.encode().unwrap();
        assert_eq!(encoded.len(), PADDED_ENROLLMENT_RESULT_BYTES);
        let decoded = EnrollmentResult::decode(&encoded).unwrap();
        let EnrollmentResult::Success { enrollment } = &decoded else {
            panic!("expected an enrollment")
        };
        assert_eq!(enrollment.fields.len(), 12);
        assert_eq!(enrollment.encrypted_custody, vec![9; 64]);
        let failed = EnrollmentResult::Failed {
            reason: Failure::QualityRejected,
        };
        assert_eq!(
            failed.encode().unwrap().len(),
            PADDED_ENROLLMENT_RESULT_BYTES
        );
        encoded[PADDED_ENROLLMENT_RESULT_BYTES - 1] = 1;
        assert!(EnrollmentResult::decode(&encoded).is_err());

        let mut reordered = bundle();
        reordered.fields.swap(0, 1);
        let mut missing = bundle();
        missing.fields.pop();
        let mut empty = bundle();
        empty.fields[3].value.clear();
        let mut header = bundle();
        header.attestation_header = "not base64!".into();
        let mut pcp = bundle();
        pcp.encrypted_custody = vec![0; MAX_ENCRYPTED_PCP_BYTES + 1];
        for enrollment in [reordered, missing, empty, header, pcp] {
            assert!(EnrollmentResult::Success { enrollment }.encode().is_err());
        }
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
