//! Serializes and encrypts custody data inside the enclave. Only ciphertext leaves this API.
//!
//! The authenticated enrollment channel must supply the user's custody public key.
//! This helper checks its cryptographic suitability, not ownership or provenance.

use std::io::{self, Cursor, Write};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crypto_box::PublicKey;
use flate2::{Compression, write::GzEncoder};
use rand::{CryptoRng, Rng};
use serde::Serialize;
use tar::{Builder, Header};
use zeroize::Zeroizing;

use crate::{
    IdentityEnrollment, MAX_ATTESTATION_DOCUMENT_BYTES, MAX_OWNERSHIP_PROOF_BYTES, poseidon,
};
use selfie_enrollment_api_types::MAX_IMAGE_BYTES;

pub const FORMAT: &str = "web-face-custody-v1";
/// Includes image, base64 ownership proof, bounded metadata, archive and encryption overhead.
pub const MAX_PACKAGE_BYTES: usize = MAX_IMAGE_BYTES + MAX_OWNERSHIP_PROOF_BYTES * 2 + 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid custody recipient")]
    InvalidRecipient,
    #[error("custody data does not match enrollment")]
    InconsistentEnrollment,
    #[error("custody package exceeds its limit")]
    TooLarge,
    #[error("custody package serialization failed")]
    Serialization,
    #[error("custody package encryption failed")]
    Encryption,
}

#[derive(Serialize)]
struct Info<'a> {
    id_commitment: &'a str,
    capture_id: &'a str,
    captured_at: u64,
}

#[derive(Serialize)]
struct Manifest<'a> {
    format: &'static str,
    pcp_version: &'a str,
    associated_data_hash: &'a str,
}

#[derive(Serialize)]
struct Part<'a> {
    name: &'a str,
    value_base64: String,
}

#[derive(Serialize)]
struct Enrollment<'a> {
    id_commitment: &'a str,
    parts: Vec<Part<'a>>,
}

/// Creates a libsodium-compatible sealed box containing a gzip-compressed tar archive.
/// Reuses the exact data and plaintext shares produced by `assemble`; never generates shares.
/// No credential or legacy Gateway signature is fabricated. Credential import happens later.
/// Owned plaintext serialization buffers are erased on drop.
///
/// # Errors
/// Rejects unsuitable keys, mismatched/oversized data, serialization or encryption failures.
pub fn encrypt<R: Rng + CryptoRng>(
    enrollment: &IdentityEnrollment,
    custody_key: &PublicKey,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    embedding_shares::validate_recipients(std::slice::from_ref(custody_key))
        .map_err(|_| Error::InvalidRecipient)?;
    let data = &enrollment.associated_data;
    if data.image_png.len() > MAX_IMAGE_BYTES
        || enrollment.form.world_id_ownership_proof.len() > MAX_OWNERSHIP_PROOF_BYTES
        || enrollment.tee_attestation_document.len() > MAX_ATTESTATION_DOCUMENT_BYTES
        || enrollment
            .form
            .parts()
            .iter()
            .any(|(name, value)| *name != "world_id_ownership_proof" && value.len() > 8192)
        || data.embedding.embedding.len() > 4096
        || data
            .shares
            .iter()
            .any(|share| share.version.len() > 128 || share.share_data.len() > 2048)
    {
        return Err(Error::TooLarge);
    }
    if data.id_commitment.len() > 128
        || data.id_commitment != enrollment.id_commitment
        || data.embedding.embedding_type != enrollment.form.face_embedding_type
        || data.embedding.embedding_version != enrollment.form.face_embedding_version
        || data.embedding.embedding_inference_backend
            != enrollment.form.face_embedding_inference_backend
        || data.capture_id != enrollment.form.capture_id
        || data.captured_at.to_string() != enrollment.form.timestamp
        || data.pcp_version != enrollment.form.pcp_version
        || poseidon::associated_data(data)
            .map(|hash| hash.to_string())
            .as_deref()
            != Some(enrollment.form.associated_data_hash.as_str())
    {
        return Err(Error::InconsistentEnrollment);
    }

    let mut entries = vec![
        (
            "manifest.json",
            json(&Manifest {
                format: FORMAT,
                pcp_version: &data.pcp_version,
                associated_data_hash: &enrollment.form.associated_data_hash,
            })?,
        ),
        (
            "associated_data/info.json",
            json(&Info {
                id_commitment: &data.id_commitment,
                capture_id: &data.capture_id,
                captured_at: data.captured_at,
            })?,
        ),
        (
            "associated_data/face_embeddings.json",
            json(&[&data.embedding])?,
        ),
        (
            "associated_data/face_ampc_share_0.json",
            json(&data.shares[0])?,
        ),
        (
            "associated_data/face_ampc_share_1.json",
            json(&data.shares[1])?,
        ),
        (
            "associated_data/face_ampc_share_2.json",
            json(&data.shares[2])?,
        ),
        (
            "enrollment.json",
            json(&Enrollment {
                id_commitment: &enrollment.id_commitment,
                parts: enrollment
                    .form
                    .parts()
                    .into_iter()
                    .map(|(name, value)| Part {
                        name,
                        value_base64: STANDARD.encode(value),
                    })
                    .collect(),
            })?,
        ),
    ];
    let raw_bytes = entries.iter().map(|(_, bytes)| bytes.len()).sum::<usize>()
        + data.image_png.len()
        + enrollment.tee_attestation_document.len();
    // Fixed backing storage prevents a growing Vec from leaving abandoned plaintext copies.
    let capacity = raw_bytes + raw_bytes / 100 + 64 * 1024;
    if capacity > MAX_PACKAGE_BYTES {
        return Err(Error::TooLarge);
    }
    let mut plaintext = Zeroizing::new(vec![0; capacity]);
    let length = {
        let encoder = GzEncoder::new(
            Cursor::new(plaintext.as_mut_slice()),
            Compression::default(),
        );
        let mut archive = Builder::new(encoder);
        for (name, bytes) in &mut entries {
            append(&mut archive, name, bytes)?;
        }
        append(
            &mut archive,
            "associated_data/face_image.png",
            &data.image_png,
        )?;
        append(
            &mut archive,
            "attestation/nitro.cose",
            &enrollment.tee_attestation_document,
        )?;
        archive
            .into_inner()
            .map_err(|_| Error::Serialization)?
            .finish()
            .map_err(|_| Error::Serialization)?
            .position() as usize
    };
    custody_key
        .seal(rng, &plaintext[..length])
        .map_err(|_| Error::Encryption)
}

fn append<W: Write>(archive: &mut Builder<W>, name: &str, bytes: &[u8]) -> Result<(), Error> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    archive
        .append_data(&mut header, name, bytes)
        .map_err(|_| Error::Serialization)
}

fn json(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>, Error> {
    struct Size(usize);
    impl Write for Size {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|&size| size <= MAX_PACKAGE_BYTES)
                .ok_or_else(|| io::Error::other("package limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut size = Size(0);
    serde_json::to_writer(&mut size, value).map_err(|_| Error::Serialization)?;
    let mut bytes = Zeroizing::new(vec![0; size.0]);
    serde_json::to_writer(bytes.as_mut_slice(), value).map_err(|_| Error::Serialization)?;
    Ok(bytes)
}
