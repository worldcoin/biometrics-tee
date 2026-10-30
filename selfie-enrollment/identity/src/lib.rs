//! Assembles `PUT /api/v1/web/identity` for one Selfie Check capture inside the enclave.
//!
//! The form keeps signup-service's mobile face fields and Oxide's Poseidon2 hashes. One
//! per-capture Nitro document signs the running worker SHA-384 in [`user_data`] and a
//! canonical request digest in its `nonce`. The document travels in an HTTP header,
//! outside the body it binds, so the relaying host cannot change enrollment fields.
//! Share recipients, the capture clock, the v3 identity and the attestor are supplied by the
//! caller. Sensitive types deliberately do not implement `Debug`.

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
/// Matches signup-service's bound and accommodates Oxide's measured 570,464-byte proof.
pub const MAX_OWNERSHIP_PROOF_BYTES: usize = 768 * 1024;
/// Standard base64 of the binary COSE_Sign1 document; never a multipart body field.
pub const ATTESTATION_HEADER: &str = "x-tee-attestation";
/// Application bound; the submitting proxy must accept the base64-expanded header.
pub const MAX_ATTESTATION_DOCUMENT_BYTES: usize = 16 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const BINDING_DOMAIN: &[u8] = b"web-authenticator:identity:v1";
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

pub struct Inputs<'a> {
    pub capture: Capture<'a>,
    pub subject: Subject<'a>,
    /// The enclave-held v3 identity commitment, in Oxide's `Identity::commitment()` string form.
    pub id_commitment: &'a str,
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

/// The browser's World ID 4.0 subject and enrollment-purpose ownership proof. Forwarded
/// unverified; signup-service verifies the proof.
pub struct Subject<'a> {
    pub sub: &'a str,
    pub challenge_id: Uuid,
    pub ownership_proof: &'a [u8],
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
    /// The `idComm` query parameter.
    pub id_commitment: String,
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

/// Enrollment body fields. The attestation document is transported separately in a header.
#[derive(Clone)]
pub struct Form {
    pub capture_id: String,
    pub timestamp: String,
    pub face_embedding_shares: [String; 3],
    pub face_embedding_shares_hashes: [String; 3],
    pub face_embedding_version: String,
    pub face_embedding_type: String,
    pub face_embedding_inference_backend: String,
    pub pcp_version: String,
    pub id_commitment_hash: String,
    pub associated_data_hash: String,
    pub sub: String,
    pub world_id_challenge_id: String,
    pub world_id_ownership_proof: Vec<u8>,
}

impl Form {
    /// Parts in submission order. `world_id_ownership_proof` is a binary file part.
    #[must_use]
    pub fn parts(&self) -> [(&'static str, &[u8]); 17] {
        let [share_0, share_1, share_2] = &self.face_embedding_shares;
        let [hash_0, hash_1, hash_2] = &self.face_embedding_shares_hashes;
        [
            ("capture_id", self.capture_id.as_bytes()),
            ("timestamp", self.timestamp.as_bytes()),
            ("face_embedding_shares_0", share_0.as_bytes()),
            ("face_embedding_shares_1", share_1.as_bytes()),
            ("face_embedding_shares_2", share_2.as_bytes()),
            ("face_embedding_shares_0_hash", hash_0.as_bytes()),
            ("face_embedding_shares_1_hash", hash_1.as_bytes()),
            ("face_embedding_shares_2_hash", hash_2.as_bytes()),
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
            ("id_commitment_hash", self.id_commitment_hash.as_bytes()),
            ("associated_data_hash", self.associated_data_hash.as_bytes()),
            ("sub", self.sub.as_bytes()),
            (
                "world_id_challenge_id",
                self.world_id_challenge_id.as_bytes(),
            ),
            ("world_id_ownership_proof", &self.world_id_ownership_proof),
        ]
    }
}

/// Oxide's `FaceAssociatedData` with its single embedding. The hash excludes `id_commitment`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AssociatedData {
    pub id_commitment: String,
    pub pcp_version: String,
    pub embedding: FaceEmbedding,
    pub image_png: Vec<u8>,
    pub capture_id: String,
    pub captured_at: u64,
    pub shares: [FaceShare; 3],
}

/// Builds the enrollment for one successful extraction and attests it once.
///
/// Basic inputs and the embedding are validated before sharing. All failures precede
/// attestation. Supply an RNG seeded from fresh entropy in production.
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
    let Inputs {
        capture, subject, ..
    } = inputs;
    let shares = embedding_shares::generate(capture.embedding, inputs.pcp_version, rng)?;
    let face_embedding_shares = embedding_shares::encrypt(&shares, inputs.recipient_keys, rng)?;
    let associated_data = AssociatedData {
        id_commitment: inputs.id_commitment.to_owned(),
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
    let share_hash = |share| {
        poseidon::share(share)
            .map(|hash| hash.to_string())
            .ok_or(Error::Hash("face embedding share"))
    };
    let form = Form {
        capture_id: associated_data.capture_id.clone(),
        timestamp: capture.captured_at.to_string(),
        face_embedding_shares,
        face_embedding_shares_hashes: [
            share_hash(&associated_data.shares[0])?,
            share_hash(&associated_data.shares[1])?,
            share_hash(&associated_data.shares[2])?,
        ],
        face_embedding_version: capture.embedding.embedding_version.clone(),
        face_embedding_type: capture.embedding.embedding_type.clone(),
        face_embedding_inference_backend: capture.embedding.embedding_inference_backend.clone(),
        pcp_version: inputs.pcp_version.to_owned(),
        id_commitment_hash: poseidon::id_commitment(inputs.id_commitment)
            .ok_or(Error::Hash("identity commitment"))?
            .to_string(),
        associated_data_hash: poseidon::associated_data(&associated_data)
            .ok_or(Error::Hash("associated data"))?
            .to_string(),
        sub: subject.sub.to_owned(),
        world_id_challenge_id: subject.challenge_id.to_string(),
        world_id_ownership_proof: subject.ownership_proof.to_vec(),
    };
    let tee_attestation_document = attestor.attest(
        &binding_digest(inputs.id_commitment, &form),
        &user_data(inputs.worker_sha384),
    )?;
    if tee_attestation_document.is_empty()
        || tee_attestation_document.len() > MAX_ATTESTATION_DOCUMENT_BYTES
    {
        return Err(Error::InvalidAttestationDocument);
    }
    Ok(IdentityEnrollment {
        id_commitment: inputs.id_commitment.to_owned(),
        form,
        tee_attestation_document,
        associated_data,
    })
}

/// Canonical enrollment-body SHA-256, carried in the Nitro document's signed `nonce`.
/// Hash [`BINDING_DOMAIN`], then `idComm` and each [`Form::parts`] entry. Each name
/// and value is prefixed by its big-endian `u32` byte length. Multipart boundaries,
/// header encoding and the attestation document itself are excluded.
#[must_use]
pub fn binding_digest(id_commitment: &str, form: &Form) -> [u8; NONCE_BYTES] {
    let mut binding = Sha256::new();
    binding.update(BINDING_DOMAIN);
    let parts = std::iter::once(("idComm", id_commitment.as_bytes())).chain(form.parts());
    for (name, value) in parts {
        for field in [name.as_bytes(), value] {
            // Every field is bounded far below `u32::MAX` by validation and the share format.
            binding.update((field.len() as u32).to_be_bytes());
            binding.update(field);
        }
    }
    binding.finalize().into()
}

/// Signed release metadata, checked with PCR0/1/2 against one approved release.
#[must_use]
pub fn user_data(worker_sha384: &[u8; 48]) -> [u8; USER_DATA_BYTES] {
    let mut value = [0; USER_DATA_BYTES];
    value[0] = USER_DATA_VERSION;
    value[1..].copy_from_slice(worker_sha384);
    value
}

fn validate(inputs: &Inputs<'_>) -> Result<(), Error> {
    let Inputs {
        capture, subject, ..
    } = inputs;
    if !is_identifier(inputs.id_commitment) {
        return Err(Error::InvalidInput("id_commitment"));
    }
    if !is_identifier(inputs.pcp_version) {
        return Err(Error::InvalidInput("pcp_version"));
    }
    if !is_identifier(subject.sub) {
        return Err(Error::InvalidInput("sub"));
    }
    if subject.challenge_id.is_nil() {
        return Err(Error::InvalidInput("world_id_challenge_id"));
    }
    if subject.ownership_proof.is_empty()
        || subject.ownership_proof.len() > MAX_OWNERSHIP_PROOF_BYTES
    {
        return Err(Error::InvalidInput("world_id_ownership_proof"));
    }
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
    const ID_COMMITMENT: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000123";

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
                subject: Subject {
                    sub: "0x1f",
                    challenge_id: Uuid::from_u128(0x1234),
                    ownership_proof: b"proof",
                },
                id_commitment: ID_COMMITMENT,
                pcp_version: "1",
                recipient_keys: &self.public_keys,
                worker_sha384: &WORKER,
            }
        }
    }

    #[test]
    fn the_attestation_signs_the_submitted_parts_and_shares_open_to_their_hashes() {
        let mut rng = StdRng::seed_from_u64(7);
        let fixture = Fixture::new(&mut rng);
        let attestor = RecordingAttestor::default();
        let enrollment = assemble(&fixture.inputs(), &attestor, &mut rng).unwrap();
        let form = &enrollment.form;

        assert_eq!(attestor.calls.get(), 1);
        assert_eq!(enrollment.tee_attestation_document, b"document");
        assert_eq!(*attestor.user_data.borrow(), user_data(&WORKER));
        assert_eq!(
            *attestor.nonce.borrow(),
            binding_digest(ID_COMMITMENT, form)
        );
        assert_eq!(
            STANDARD.decode(enrollment.attestation_header()).unwrap(),
            b"document"
        );
        assert_eq!(enrollment.id_commitment, ID_COMMITMENT);
        assert_eq!(form.capture_id, "6f9619ff-8b86-4d01-b42d-00cf4fc964ff");
        assert_eq!(form.timestamp, "1700000000");
        assert_eq!(form.face_embedding_type, "ghostfacenet_flipped_mean");
        assert_eq!(
            form.world_id_challenge_id,
            Uuid::from_u128(0x1234).to_string()
        );
        assert_eq!(
            form.associated_data_hash,
            poseidon::associated_data(&enrollment.associated_data)
                .unwrap()
                .to_string()
        );
        for party in 0..3 {
            let sealed = STANDARD.decode(&form.face_embedding_shares[party]).unwrap();
            let opened = fixture.secret_keys[party].unseal(&sealed).unwrap();
            let share = &enrollment.associated_data.shares[party];
            assert_eq!(
                opened,
                format!(r#"{{"version":"1","share_data":"{}"}}"#, share.share_data).as_bytes()
            );
            assert_eq!(
                form.face_embedding_shares_hashes[party],
                poseidon::share(share).unwrap().to_string()
            );
        }
    }

    #[test]
    fn changing_any_part_or_the_identity_changes_the_attested_binding() {
        let mut rng = StdRng::seed_from_u64(7);
        let fixture = Fixture::new(&mut rng);
        let form = assemble(&fixture.inputs(), &RecordingAttestor::default(), &mut rng)
            .unwrap()
            .form;
        let original = binding_digest(ID_COMMITMENT, &form);
        assert_ne!(binding_digest("0x1", &form), original);
        assert_ne!(user_data(&[0; 48]), user_data(&WORKER));
        for index in 0..form.parts().len() {
            let mut changed = form.clone();
            let field = match index {
                0 => &mut changed.capture_id,
                1 => &mut changed.timestamp,
                2..=4 => &mut changed.face_embedding_shares[index - 2],
                5..=7 => &mut changed.face_embedding_shares_hashes[index - 5],
                8 => &mut changed.face_embedding_version,
                9 => &mut changed.face_embedding_type,
                10 => &mut changed.face_embedding_inference_backend,
                11 => &mut changed.pcp_version,
                12 => &mut changed.id_commitment_hash,
                13 => &mut changed.associated_data_hash,
                14 => &mut changed.sub,
                15 => &mut changed.world_id_challenge_id,
                _ => {
                    changed.world_id_ownership_proof.push(0);
                    assert_ne!(binding_digest(ID_COMMITMENT, &changed), original);
                    continue;
                }
            };
            field.push('0');
            assert_ne!(
                binding_digest(ID_COMMITMENT, &changed),
                original,
                "{}",
                form.parts()[index].0
            );
        }
    }

    #[test]
    fn the_binding_layout_is_frozen() {
        let form = Form {
            capture_id: "6f9619ff-8b86-4d01-b42d-00cf4fc964ff".into(),
            timestamp: "1700000000".into(),
            face_embedding_shares: ["c0".into(), "c1".into(), "c2".into()],
            face_embedding_shares_hashes: ["h0".into(), "h1".into(), "h2".into()],
            face_embedding_version: "2.0.0".into(),
            face_embedding_type: "ghostfacenet_flipped_mean".into(),
            face_embedding_inference_backend: "face-engine".into(),
            pcp_version: "1".into(),
            id_commitment_hash: "0x01".into(),
            associated_data_hash: "0x02".into(),
            sub: "0x1f".into(),
            world_id_challenge_id: "00000000-0000-0000-0000-000000001234".into(),
            world_id_ownership_proof: b"proof".to_vec(),
        };
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/enrollment-v1.json")).unwrap();
        assert_eq!(
            fixture["domain"],
            std::str::from_utf8(BINDING_DOMAIN).unwrap()
        );
        assert_eq!(fixture["id_commitment"], ID_COMMITMENT);
        assert_eq!(
            fixture["parts"].as_array().unwrap().len(),
            form.parts().len()
        );
        for ((name, value), part) in form
            .parts()
            .iter()
            .zip(fixture["parts"].as_array().unwrap())
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
            fixture["nonce_hex"],
            hex::encode(binding_digest(ID_COMMITMENT, &form))
        );
        assert_eq!(fixture["user_data_hex"], hex::encode(user_data(&WORKER)));
        let user_data = user_data(&WORKER);
        assert_eq!(user_data[0], USER_DATA_VERSION);
        assert_eq!(user_data[1..49], WORKER);
        assert_eq!(
            hex::encode(binding_digest(ID_COMMITMENT, &form)),
            "aaea0b04e1c35d62ff90f66898b3f949b7f105ac8d80bd10e7bd824e6815c652"
        );
    }

    #[test]
    fn invalid_inputs_are_rejected_before_attesting() {
        let mut rng = StdRng::seed_from_u64(7);
        let fixture = Fixture::new(&mut rng);
        let attestor = RecordingAttestor::default();
        let oversized_proof = vec![1; MAX_OWNERSHIP_PROOF_BYTES + 1];
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
        rejects!("id_commitment", |i| i.id_commitment = "");
        rejects!("pcp_version", |i| i.pcp_version = "1 2");
        rejects!("sub", |i| i.subject.sub = "0x1f\r\n");
        rejects!("world_id_challenge_id", |i| i.subject.challenge_id =
            Uuid::nil());
        rejects!("world_id_ownership_proof", |i| i.subject.ownership_proof =
            b"");
        rejects!("world_id_ownership_proof", |i| i.subject.ownership_proof =
            &oversized_proof);
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
    fn real_size_proofs_and_the_agreed_boundary_are_accepted() {
        let mut rng = StdRng::seed_from_u64(7);
        let fixture = Fixture::new(&mut rng);
        for size in [
            570_464,
            MAX_OWNERSHIP_PROOF_BYTES,
            MAX_OWNERSHIP_PROOF_BYTES + 1,
        ] {
            let proof = vec![0xa0; size];
            let mut inputs = fixture.inputs();
            inputs.subject.ownership_proof = &proof;
            let attestor = RecordingAttestor::default();
            let result = assemble(&inputs, &attestor, &mut rng);
            if size <= MAX_OWNERSHIP_PROOF_BYTES {
                assert_eq!(result.unwrap().form.world_id_ownership_proof, proof);
                assert_eq!(attestor.calls.get(), 1);
            } else {
                assert!(matches!(
                    result,
                    Err(Error::InvalidInput("world_id_ownership_proof"))
                ));
                assert_eq!(attestor.calls.get(), 0);
            }
        }
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
        for length in [0, MAX_ATTESTATION_DOCUMENT_BYTES + 1] {
            assert!(matches!(
                assemble(&fixture.inputs(), &SizedDocument(length), &mut rng),
                Err(Error::InvalidAttestationDocument)
            ));
        }
    }
}
