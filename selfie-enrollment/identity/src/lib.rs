//! Assembles signup-service's v4-only web enrollment, `PUT /api/v2/identity`, for one
//! Selfie Check capture inside the enclave (signup-service#2400, contract version 2).
//!
//! The capture is bound to the browser's World ID 4.0 subject. One per-capture Nitro
//! document signs the running worker SHA-384 in [`user_data`] and a canonical capture
//! digest in its `nonce`. The document travels in an HTTP header, outside the body it
//! binds; verification detects changes to the bound capture fields. The enclave produces
//! only the attested capture fields. The browser adds its v4 challenge and ownership proof,
//! which are not attested, and submits the request itself; a retry can carry a fresh proof
//! for the same capture. Share recipients, the capture clock and the attestor are supplied
//! by the caller. Sensitive types deliberately do not implement `Debug`.

pub mod custody;
mod poseidon;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crypto_box::PublicKey;
use embedding_shares::FaceShare;
use rand::{CryptoRng, Rng};
use selfie_enrollment_api_types::MAX_IMAGE_BYTES;
use selfie_enrollment_sealed_types::FaceEmbedding;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const USER_DATA_VERSION: u8 = 1;
/// Version byte and running-worker SHA-384. The request digest is the signed nonce.
pub const USER_DATA_BYTES: usize = 1 + 48;
pub const NONCE_BYTES: usize = 32;
/// Standard base64 of the binary COSE_Sign1 document; never a multipart body field.
pub const ATTESTATION_HEADER: &str = "x-nitro-attestation";
/// Base64 expands to at most 16,000 bytes, leaving room for the header name under
/// the staging ALB's 16 KiB single-header limit. Shared with signup-service.
pub const MAX_ATTESTATION_DOCUMENT_BYTES: usize = 12_000;
const MAX_IDENTIFIER_BYTES: usize = 128;
/// signup-service's v2 web identity route; the method and path are part of the signed digest.
pub const IDENTITY_METHOD: &str = "PUT";
pub const IDENTITY_PATH: &str = "/api/v2/identity";
/// The `contract_version` form value for this payload layout.
pub const CONTRACT_VERSION: &str = "2";
const BINDING_DOMAIN: &[u8] = b"web-authenticator:face-enrollment:v2";
/// signup-service accepts `0x` plus up to 64 hex digits and requires its minimal lowercase form.
const MAX_SUB_HEX_DIGITS: usize = 64;
/// A sealed box's ephemeral public key and tag; signup-service rejects shorter shares.
const SEALED_BOX_OVERHEAD_BYTES: usize = 48;
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

pub struct Inputs<'a> {
    pub capture: Capture<'a>,
    /// The browser's World ID 4.0 subject, in canonical form only (see [`validate_sub`]).
    /// The subject is signed, so it is never normalized here; strip leading zeros beforehand.
    pub sub: &'a str,
    pub pcp_version: &'a str,
    /// Face-AMPC party keys 0, 1, 2. The caller authenticates their provenance.
    pub recipient_keys: &'a [PublicKey; 3],
    /// SHA-384 of the running worker executable, which the PCRs do not measure.
    pub worker_sha384: &'a [u8; 48],
}

pub struct Capture<'a> {
    pub capture_id: Uuid,
    /// Unix seconds from a clock the enclave trusts, never one the host or browser supplies.
    pub captured_at: u64,
    /// The PNG image `embedding` was extracted from; retained in the associated data.
    pub image_png: &'a [u8],
    pub embedding: &'a FaceEmbedding,
}

/// Produces a fresh per-capture Nitro attestation over both signed fields.
pub trait CaptureAttestor {
    /// Returns a COSE_Sign1 document with exactly these `nonce` and `user_data` values.
    /// Leave its optional `public_key` empty; channel-key attestation is separate.
    ///
    /// # Errors
    /// Returns [`AttestationFailed`] when the secure module rejects the request.
    fn attest(
        &self,
        nonce: &[u8; NONCE_BYTES],
        user_data: &[u8; USER_DATA_BYTES],
    ) -> Result<Vec<u8>, AttestationFailed>;
}

#[derive(Debug, thiserror::Error)]
#[error("capture attestation failed")]
pub struct AttestationFailed;

/// Failures contain no biometric, share, subject or proof values.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid enrollment input: {0}")]
    InvalidInput(&'static str),
    #[error(transparent)]
    Shares(#[from] embedding_shares::Error),
    #[error("failed to hash {0}")]
    Hash(&'static str),
    #[error(transparent)]
    Attestation(#[from] AttestationFailed),
    #[error("invalid capture attestation document length")]
    InvalidAttestationDocument,
}

pub struct IdentityEnrollment {
    pub form: Form,
    /// COSE_Sign1 document, sent as standard base64 in [`ATTESTATION_HEADER`].
    pub tee_attestation_document: Vec<u8>,
    /// What `associated_data_hash` commits to. Contains the image, embedding and plaintext shares.
    pub associated_data: AssociatedData,
}

impl IdentityEnrollment {
    /// Encodes the document for [`ATTESTATION_HEADER`]; it is excluded from [`Form::parts`].
    #[must_use]
    pub fn attestation_header(&self) -> String {
        STANDARD.encode(&self.tee_attestation_document)
    }
}

/// The attested capture fields. The attestation document is transported separately in a
/// header. The browser adds `world_id_challenge_id` and the `world_id_ownership_proof` file
/// part after these when it submits; neither is part of the attested digest.
#[derive(Clone)]
pub struct Form {
    pub contract_version: String,
    pub sub: String,
    pub capture_id: String,
    pub timestamp: String,
    /// Standard padded base64 of each party's sealed share; the digest binds the decoded bytes.
    pub face_embedding_shares: [String; 3],
    pub face_embedding_version: String,
    pub face_embedding_type: String,
    pub face_embedding_inference_backend: String,
    pub pcp_version: String,
    pub associated_data_hash: String,
}

impl Form {
    /// The attested fields in submission and [`binding_digest`] order.
    #[must_use]
    pub fn parts(&self) -> [(&'static str, &[u8]); 12] {
        let [share_0, share_1, share_2] = &self.face_embedding_shares;
        [
            ("contract_version", self.contract_version.as_bytes()),
            ("sub", self.sub.as_bytes()),
            ("capture_id", self.capture_id.as_bytes()),
            ("timestamp", self.timestamp.as_bytes()),
            ("face_embedding_shares_0", share_0.as_bytes()),
            ("face_embedding_shares_1", share_1.as_bytes()),
            ("face_embedding_shares_2", share_2.as_bytes()),
            (
                "face_embedding_version",
                self.face_embedding_version.as_bytes(),
            ),
            ("face_embedding_type", self.face_embedding_type.as_bytes()),
            (
                "face_embedding_inference_backend",
                self.face_embedding_inference_backend.as_bytes(),
            ),
            ("pcp_version", self.pcp_version.as_bytes()),
            ("associated_data_hash", self.associated_data_hash.as_bytes()),
        ]
    }
}

/// Oxide's `FaceAssociatedData` with its single embedding.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AssociatedData {
    pub pcp_version: String,
    pub embedding: FaceEmbedding,
    pub image_png: Vec<u8>,
    pub capture_id: String,
    pub captured_at: u64,
    pub shares: [FaceShare; 3],
}

/// Builds the enrollment for one successful extraction and attests it once.
///
/// Basic inputs and the embedding are validated before sharing. Inputs and shares are
/// validated before requesting attestation. Supply an RNG seeded from fresh entropy in production.
///
/// # Errors
/// Rejects malformed inputs, unsupported embeddings and unsuitable recipient keys; propagates
/// hashing and attestation failures.
pub fn assemble<R: Rng + CryptoRng>(
    inputs: &Inputs<'_>,
    attestor: &dyn CaptureAttestor,
    rng: &mut R,
) -> Result<IdentityEnrollment, Error> {
    validate(inputs)?;
    let capture = &inputs.capture;
    let shares = embedding_shares::generate(capture.embedding, inputs.pcp_version, rng)?;
    let face_embedding_shares = embedding_shares::encrypt(&shares, inputs.recipient_keys, rng)?;
    let associated_data = AssociatedData {
        pcp_version: inputs.pcp_version.to_owned(),
        embedding: FaceEmbedding {
            embedding: capture.embedding.embedding.clone(),
            embedding_type: capture.embedding.embedding_type.clone(),
            embedding_version: capture.embedding.embedding_version.clone(),
            embedding_inference_backend: capture.embedding.embedding_inference_backend.clone(),
        },
        image_png: capture.image_png.to_vec(),
        capture_id: capture.capture_id.to_string(),
        captured_at: capture.captured_at,
        shares,
    };
    let form = Form {
        contract_version: CONTRACT_VERSION.to_owned(),
        sub: inputs.sub.to_owned(),
        capture_id: associated_data.capture_id.clone(),
        timestamp: capture.captured_at.to_string(),
        face_embedding_shares,
        face_embedding_version: capture.embedding.embedding_version.clone(),
        face_embedding_type: capture.embedding.embedding_type.clone(),
        face_embedding_inference_backend: capture.embedding.embedding_inference_backend.clone(),
        pcp_version: inputs.pcp_version.to_owned(),
        // `0x` plus 64 lowercase hex digits, as signup-service requires.
        associated_data_hash: poseidon::associated_data(&associated_data)
            .ok_or(Error::Hash("associated data"))?
            .to_string(),
    };
    let tee_attestation_document =
        attestor.attest(&binding_digest(&form)?, &user_data(inputs.worker_sha384))?;
    if tee_attestation_document.is_empty()
        || tee_attestation_document.len() > MAX_ATTESTATION_DOCUMENT_BYTES
    {
        return Err(Error::InvalidAttestationDocument);
    }
    Ok(IdentityEnrollment {
        form,
        tee_attestation_document,
        associated_data,
    })
}

/// Canonical capture SHA-256, carried in the Nitro document's signed `nonce`.
/// Hash [`BINDING_DOMAIN`], then `@method` and `@path`, then each [`Form::parts`] entry. Each name and value is prefixed by its big-endian `u32` byte length. Shares are
/// bound as their decoded ciphertext bytes. The v4 challenge and proof, multipart
/// boundaries, header encoding and the attestation document itself are excluded.
///
/// # Errors
/// Returns [`Error::InvalidInput`] if a share is not canonical standard base64 of at least a
/// sealed box's overhead.
pub fn binding_digest(form: &Form) -> Result<[u8; NONCE_BYTES], Error> {
    let mut binding = Sha256::new();
    binding.update(BINDING_DOMAIN);
    let mut write = |name: &[u8], value: &[u8]| {
        for field in [name, value] {
            // Every field is bounded far below `u32::MAX` by validation and the share format.
            binding.update((field.len() as u32).to_be_bytes());
            binding.update(field);
        }
    };
    write(b"@method", IDENTITY_METHOD.as_bytes());
    write(b"@path", IDENTITY_PATH.as_bytes());
    for (name, value) in form.parts() {
        if name.starts_with("face_embedding_shares_") {
            let sealed = STANDARD
                .decode(value)
                .ok()
                .filter(|sealed| {
                    sealed.len() >= SEALED_BOX_OVERHEAD_BYTES
                        && STANDARD.encode(sealed).as_bytes() == value
                })
                .ok_or(Error::InvalidInput("face_embedding_shares"))?;
            write(name.as_bytes(), &sealed);
        } else {
            write(name.as_bytes(), value);
        }
    }
    Ok(binding.finalize().into())
}

/// Signed release metadata, checked with PCR0/1/2 against one approved release.
#[must_use]
pub fn user_data(worker_sha384: &[u8; 48]) -> [u8; USER_DATA_BYTES] {
    let mut value = [0; USER_DATA_BYTES];
    value[0] = USER_DATA_VERSION;
    value[1..].copy_from_slice(worker_sha384);
    value
}

/// Checks a v4 subject before extraction or assembly: signup-service's canonical form only.
///
/// # Errors
/// Returns [`Error::InvalidInput`] for a non-canonical subject.
pub fn validate_sub(sub: &str) -> Result<(), Error> {
    if is_canonical_sub(sub) {
        Ok(())
    } else {
        Err(Error::InvalidInput("sub"))
    }
}

fn validate(inputs: &Inputs<'_>) -> Result<(), Error> {
    let capture = &inputs.capture;
    if !is_identifier(inputs.pcp_version) {
        return Err(Error::InvalidInput("pcp_version"));
    }
    validate_sub(inputs.sub)?;
    if capture.capture_id.is_nil() {
        return Err(Error::InvalidInput("capture_id"));
    }
    if capture.captured_at == 0 {
        return Err(Error::InvalidInput("timestamp"));
    }
    if !capture.image_png.starts_with(PNG_SIGNATURE) || capture.image_png.len() > MAX_IMAGE_BYTES {
        return Err(Error::InvalidInput("image_png"));
    }
    Ok(())
}

/// signup-service's canonical v4 subject: `0x`, then 1 to 64 lowercase hex digits without a
/// leading zero, and nonzero, so its `ValidateAndNormalizeSub` returns the value unchanged.
fn is_canonical_sub(sub: &str) -> bool {
    sub.strip_prefix("0x").is_some_and(|digits| {
        (1..=MAX_SUB_HEX_DIGITS).contains(&digits.len())
            && !digits.starts_with('0')
            && digits
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// Non-empty printable ASCII, so a value cannot escape its multipart part.
fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::SecretKey;
    use rand::{SeedableRng, rngs::StdRng};
    use std::cell::{Cell, RefCell};

    const WORKER: [u8; 48] = [0x5a; 48];
    /// `face/app-api/nitro/testdata/web-v2.json` from signup-service#2400 at
    /// `88b1fb3d510b9e25710ba1dc4403017464c4f306`.
    const SIGNUP_FIXTURE: &str = include_str!("../tests/fixtures/enrollment-v2.json");

    #[derive(Default)]
    struct RecordingAttestor {
        calls: Cell<usize>,
        user_data: RefCell<Vec<u8>>,
        nonce: RefCell<Vec<u8>>,
    }
    impl CaptureAttestor for RecordingAttestor {
        fn attest(
            &self,
            nonce: &[u8; NONCE_BYTES],
            user_data: &[u8; USER_DATA_BYTES],
        ) -> Result<Vec<u8>, AttestationFailed> {
            *self.nonce.borrow_mut() = nonce.to_vec();
            self.calls.set(self.calls.get() + 1);
            *self.user_data.borrow_mut() = user_data.to_vec();
            Ok(b"document".to_vec())
        }
    }

    struct Fixture {
        embedding: FaceEmbedding,
        image: Vec<u8>,
        secret_keys: [SecretKey; 3],
        public_keys: [PublicKey; 3],
    }
    impl Fixture {
        fn new(rng: &mut StdRng) -> Self {
            let mut vector = (512_u64).to_le_bytes().to_vec();
            for index in 0..512_u16 {
                vector.extend_from_slice(&(f32::from(index % 15) * 0.02 - 0.14).to_le_bytes());
            }
            let secret_keys = std::array::from_fn(|_| SecretKey::generate(rng));
            Self {
                embedding: FaceEmbedding {
                    embedding: STANDARD.encode(vector),
                    embedding_type: "ghostfacenet_flipped_mean".into(),
                    embedding_version: "2.0.0".into(),
                    embedding_inference_backend: "face-engine".into(),
                },
                image: [PNG_SIGNATURE, b"image"].concat(),
                public_keys: secret_keys.each_ref().map(SecretKey::public_key),
                secret_keys,
            }
        }
        fn inputs(&self) -> Inputs<'_> {
            Inputs {
                capture: Capture {
                    capture_id: Uuid::from_u128(0x6f96_19ff_8b86_4d01_b42d_00cf_4fc9_64ff),
                    captured_at: 1_700_000_000,
                    image_png: &self.image,
                    embedding: &self.embedding,
                },
                sub: "0x1f",
                pcp_version: "1",
                recipient_keys: &self.public_keys,
                worker_sha384: &WORKER,
            }
        }
    }

    fn assembled() -> (Fixture, Form) {
        let mut rng = StdRng::seed_from_u64(7);
        let fixture = Fixture::new(&mut rng);
        let form = assemble(&fixture.inputs(), &RecordingAttestor::default(), &mut rng)
            .unwrap()
            .form;
        (fixture, form)
    }

    #[test]
    fn the_attestation_signs_the_capture_and_shares_open_to_the_associated_data() {
        let mut rng = StdRng::seed_from_u64(7);
        let fixture = Fixture::new(&mut rng);
        let attestor = RecordingAttestor::default();
        let enrollment = assemble(&fixture.inputs(), &attestor, &mut rng).unwrap();
        let form = &enrollment.form;

        assert_eq!(attestor.calls.get(), 1);
        assert_eq!(enrollment.tee_attestation_document, b"document");
        assert_eq!(*attestor.user_data.borrow(), user_data(&WORKER));
        assert_eq!(*attestor.nonce.borrow(), binding_digest(form).unwrap());
        assert_eq!(
            STANDARD.decode(enrollment.attestation_header()).unwrap(),
            b"document"
        );
        assert_eq!(form.contract_version, "2");
        assert_eq!(form.sub, "0x1f");
        assert_eq!(form.capture_id, "6f9619ff-8b86-4d01-b42d-00cf4fc964ff");
        assert_eq!(form.timestamp, "1700000000");
        assert_eq!(form.face_embedding_type, "ghostfacenet_flipped_mean");
        assert_eq!(
            form.associated_data_hash,
            poseidon::associated_data(&enrollment.associated_data)
                .unwrap()
                .to_string()
        );
        // signup-service: exactly `0x` plus 32 lowercase hex bytes.
        let hash = form.associated_data_hash.strip_prefix("0x").unwrap();
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        for party in 0..3 {
            let sealed = STANDARD.decode(&form.face_embedding_shares[party]).unwrap();
            assert!(sealed.len() >= SEALED_BOX_OVERHEAD_BYTES);
            let opened = fixture.secret_keys[party].unseal(&sealed).unwrap();
            let share = &enrollment.associated_data.shares[party];
            assert_eq!(
                opened,
                format!(r#"{{"version":"1","share_data":"{}"}}"#, share.share_data).as_bytes()
            );
        }
        let names: Vec<_> = form.parts().iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
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
            ]
        );
    }

    #[test]
    fn every_returned_part_is_attested() {
        let (_, form) = assembled();
        let original = binding_digest(&form).unwrap();
        assert_ne!(user_data(&[0; 48]), user_data(&WORKER));
        for index in 0..form.parts().len() {
            let mut changed = form.clone();
            match index {
                0 => changed.contract_version.push('0'),
                1 => changed.sub.push('0'),
                2 => changed.capture_id.push('0'),
                3 => changed.timestamp.push('0'),
                4..=6 => {
                    let share = &mut changed.face_embedding_shares[index - 4];
                    let mut sealed = STANDARD.decode(&*share).unwrap();
                    sealed[0] ^= 1;
                    *share = STANDARD.encode(sealed);
                }
                7 => changed.face_embedding_version.push('0'),
                8 => changed.face_embedding_type.push('0'),
                9 => changed.face_embedding_inference_backend.push('0'),
                10 => changed.pcp_version.push('0'),
                _ => changed.associated_data_hash.push('0'),
            }
            assert_ne!(
                binding_digest(&changed).unwrap(),
                original,
                "{}",
                form.parts()[index].0
            );
        }
    }

    #[test]
    fn the_binding_matches_signup_services_v2_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(SIGNUP_FIXTURE).unwrap();
        let fields = fixture["fields"].as_object().unwrap();
        let field = |name: &str| fields[name].as_str().unwrap().to_owned();
        let form = Form {
            contract_version: field("contract_version"),
            sub: field("sub"),
            capture_id: field("capture_id"),
            timestamp: field("timestamp"),
            face_embedding_shares: std::array::from_fn(|party| {
                field(&format!("face_embedding_shares_{party}"))
            }),
            face_embedding_version: field("face_embedding_version"),
            face_embedding_type: field("face_embedding_type"),
            face_embedding_inference_backend: field("face_embedding_inference_backend"),
            pcp_version: field("pcp_version"),
            associated_data_hash: field("associated_data_hash"),
        };
        // signup-service's fixture lists exactly the attested fields the enclave returns.
        assert_eq!(fields.len(), form.parts().len());
        for (name, _) in form.parts() {
            assert!(fields.contains_key(name), "{name}");
        }
        assert_eq!(form.contract_version, CONTRACT_VERSION);
        let digest = hex::encode(binding_digest(&form).unwrap());
        assert_eq!(digest, fixture["nonce_hex"].as_str().unwrap());
        assert_eq!(
            digest,
            "f572ab09e3f8a451b4b075352b30d29e711274dd0ab4ea4a99a2be95e7a951a5"
        );
        let user_data = user_data(&WORKER);
        assert_eq!(user_data[0], USER_DATA_VERSION);
        assert_eq!(user_data[1..49], WORKER);
    }

    #[test]
    fn non_canonical_share_encodings_are_not_attested() {
        let (_, form) = assembled();
        let short = STANDARD.encode([1; SEALED_BOX_OVERHEAD_BYTES - 1]);
        for share in ["", "not base64", "AQ", "AQ==\n", short.as_str()] {
            let mut changed = form.clone();
            changed.face_embedding_shares[1] = share.into();
            assert!(
                matches!(
                    binding_digest(&changed),
                    Err(Error::InvalidInput("face_embedding_shares"))
                ),
                "{share:?}"
            );
        }
    }

    #[test]
    fn validate_sub_matches_the_assembly_check() {
        assert!(validate_sub("0x1f").is_ok());
        assert!(matches!(
            validate_sub("0x01f"),
            Err(Error::InvalidInput("sub"))
        ));
    }

    #[test]
    fn only_canonical_subjects_are_accepted() {
        let max = format!("0x{}", "f".repeat(64));
        for sub in ["0x1", "0x1f", "0xabcdef0123456789", max.as_str()] {
            assert!(is_canonical_sub(sub), "{sub}");
        }
        let too_long = format!("0x1{}", "0".repeat(64));
        for sub in [
            "",
            "0x",
            "0x0",
            "0x01",
            "0x001f",
            "0X1f",
            "0x1F",
            "1f",
            "0x1g",
            " 0x1f",
            "0x1f\r\n",
            too_long.as_str(),
        ] {
            assert!(!is_canonical_sub(sub), "{sub:?}");
        }
    }

    #[test]
    fn invalid_inputs_are_rejected_before_attesting() {
        let mut rng = StdRng::seed_from_u64(7);
        let fixture = Fixture::new(&mut rng);
        let attestor = RecordingAttestor::default();
        macro_rules! rejects {
            ($field:literal, |$inputs:ident| $change:expr) => {{
                let mut $inputs = fixture.inputs();
                $change;
                assert!(
                    matches!(
                        assemble(&$inputs, &attestor, &mut rng),
                        Err(Error::InvalidInput($field))
                    ),
                    $field
                );
            }};
        }
        rejects!("pcp_version", |i| i.pcp_version = "1 2");
        rejects!("sub", |i| i.sub = "0x1f\r\n");
        // A padded field-element subject must be minimized before it is attested.
        rejects!(
            "sub",
            |i| i.sub = "0x000000000000000000000000000000000000000000000000000000000000001f"
        );
        rejects!("sub", |i| i.sub = "0x0");
        rejects!("capture_id", |i| i.capture.capture_id = Uuid::nil());
        rejects!("timestamp", |i| i.capture.captured_at = 0);
        rejects!("image_png", |i| i.capture.image_png = b"\xff\xd8\xff");

        let duplicate = [
            fixture.public_keys[0].clone(),
            fixture.public_keys[0].clone(),
            fixture.public_keys[2].clone(),
        ];
        let mut inputs = fixture.inputs();
        inputs.recipient_keys = &duplicate;
        assert!(matches!(
            assemble(&inputs, &attestor, &mut rng),
            Err(Error::Shares(embedding_shares::Error::InvalidRecipient {
                party: 1
            }))
        ));
        assert_eq!(attestor.calls.get(), 0);
    }

    #[test]
    fn attestation_failure_returns_no_enrollment() {
        struct Failing;
        impl CaptureAttestor for Failing {
            fn attest(
                &self,
                _: &[u8; NONCE_BYTES],
                _: &[u8; USER_DATA_BYTES],
            ) -> Result<Vec<u8>, AttestationFailed> {
                Err(AttestationFailed)
            }
        }
        let mut rng = StdRng::seed_from_u64(7);
        let fixture = Fixture::new(&mut rng);
        assert!(matches!(
            assemble(&fixture.inputs(), &Failing, &mut rng),
            Err(Error::Attestation(_))
        ));
    }

    #[test]
    fn empty_or_oversized_attestation_documents_are_rejected() {
        struct SizedDocument(usize);
        impl CaptureAttestor for SizedDocument {
            fn attest(
                &self,
                _: &[u8; NONCE_BYTES],
                _: &[u8; USER_DATA_BYTES],
            ) -> Result<Vec<u8>, AttestationFailed> {
                Ok(vec![0; self.0])
            }
        }
        let mut rng = StdRng::seed_from_u64(7);
        let fixture = Fixture::new(&mut rng);
        let largest = assemble(
            &fixture.inputs(),
            &SizedDocument(MAX_ATTESTATION_DOCUMENT_BYTES),
            &mut rng,
        )
        .unwrap();
        assert_eq!(largest.attestation_header().len(), 16_000);
        assert!(ATTESTATION_HEADER.len() + 2 + largest.attestation_header().len() + 2 < 16 * 1024);
        for length in [0, MAX_ATTESTATION_DOCUMENT_BYTES + 1] {
            assert!(matches!(
                assemble(&fixture.inputs(), &SizedDocument(length), &mut rng),
                Err(Error::InvalidAttestationDocument)
            ));
        }
    }

    #[test]
    fn custody_roundtrip_preserves_the_attested_data_and_exact_shares() {
        use std::collections::BTreeMap;
        use std::io::Read;
        let mut rng = StdRng::seed_from_u64(19);
        let fixture = Fixture::new(&mut rng);
        let enrollment =
            assemble(&fixture.inputs(), &RecordingAttestor::default(), &mut rng).unwrap();
        let key = SecretKey::generate(&mut rng);
        let encrypted = custody::encrypt(&enrollment, &key.public_key(), &mut rng).unwrap();
        assert!(SecretKey::generate(&mut rng).unseal(&encrypted).is_err());
        let mut changed = encrypted.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(key.unseal(&changed).is_err());
        let plaintext = key.unseal(&encrypted).unwrap();
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(plaintext.as_slice()));
        let mut files = BTreeMap::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            assert!(files.insert(name, bytes).is_none());
        }
        assert!(!files.contains_key("credential.json"));
        assert!(!files.contains_key("signed_hashes_attestation_gw.sign"));
        let manifest: serde_json::Value = serde_json::from_slice(&files["manifest.json"]).unwrap();
        assert_eq!(
            manifest,
            serde_json::json!({
                "pcp_version": enrollment.form.pcp_version,
                "associated_data_hash": enrollment.form.associated_data_hash,
            }),
        );
        let info: serde_json::Value =
            serde_json::from_slice(&files["associated_data/info.json"]).unwrap();
        let mut embeddings: Vec<FaceEmbedding> =
            serde_json::from_slice(&files["associated_data/face_embeddings.json"]).unwrap();
        let data = AssociatedData {
            id_commitment: info["id_commitment"].as_str().unwrap().into(),
            pcp_version: manifest["pcp_version"].as_str().unwrap().into(),
            embedding: embeddings.remove(0),
            image_png: files["associated_data/face_image.png"].clone(),
            capture_id: info["capture_id"].as_str().unwrap().into(),
            captured_at: info["captured_at"].as_u64().unwrap(),
            shares: std::array::from_fn(|party| {
                let share: serde_json::Value = serde_json::from_slice(
                    &files[&format!("associated_data/face_ampc_share_{party}.json")],
                )
                .unwrap();
                assert_eq!(
                    share["share_data"],
                    enrollment.associated_data.shares[party].share_data
                );
                FaceShare {
                    version: share["version"].as_str().unwrap().into(),
                    share_data: share["share_data"].as_str().unwrap().into(),
                }
            }),
        };
        assert_eq!(
            poseidon::associated_data(&data).unwrap().to_string(),
            enrollment.form.associated_data_hash
        );
        let body: serde_json::Value = serde_json::from_slice(&files["enrollment.json"]).unwrap();
        assert_eq!(body["id_commitment"], enrollment.id_commitment);
        assert_eq!(
            body["parts"].as_array().unwrap().len(),
            enrollment.form.parts().len()
        );
        for ((name, value), part) in enrollment
            .form
            .parts()
            .iter()
            .zip(body["parts"].as_array().unwrap())
        {
            assert_eq!(part["name"], *name);
            assert_eq!(
                STANDARD
                    .decode(part["value_base64"].as_str().unwrap())
                    .unwrap(),
                *value
            );
        }
        assert_eq!(
            files["attestation/nitro.cose"],
            enrollment.tee_attestation_document
        );
    }

    #[test]
    fn custody_rejects_a_bad_key_and_mutated_associated_data() {
        let mut rng = StdRng::seed_from_u64(19);
        let fixture = Fixture::new(&mut rng);
        let mut enrollment =
            assemble(&fixture.inputs(), &RecordingAttestor::default(), &mut rng).unwrap();
        assert!(matches!(
            custody::encrypt(&enrollment, &PublicKey::from([0; 32]), &mut rng),
            Err(custody::Error::InvalidRecipient)
        ));
        let key = SecretKey::generate(&mut rng);
        enrollment.associated_data.image_png.push(0);
        assert!(matches!(
            custody::encrypt(&enrollment, &key.public_key(), &mut rng),
            Err(custody::Error::InconsistentEnrollment)
        ));
    }
}
