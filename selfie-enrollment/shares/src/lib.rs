//! Oxide-compatible face share generation and recipient encryption.
//!
//! Sharing and serialization follow Oxide `32868184652c894d3bd2e7c5580dfff94f2a90a7`,
//! `oxide/src/api/pop_face_backend_api/face_embedding_shares.rs`. Decoding and
//! quantization follow biometric-engines `face-engine-v2.20.0`,
//! `utils/src/encoding.rs` and `face_engine/src/nodes/template_generation/`.

use ampc_secret_sharing::{FACE_VECTOR_SIZE, FaceVector};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bincode::Options;
use crypto_box::PublicKey;
use curve25519_dalek::montgomery::MontgomeryPoint;
use rand::{CryptoRng, Rng};
use selfie_enrollment_sealed_types::FaceEmbedding;
use serde::Serialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// One recipient's plaintext share. Contains sensitive data; do not log it.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
pub struct FaceShare {
    /// PCP/share version supplied by the caller, not the embedding model version.
    pub version: String,
    /// Standard base64 of 512 little-endian `u16` values.
    pub share_data: String,
}

/// Failures contain no embedding or share values.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unsupported face embedding type, version or inference backend")]
    UnsupportedEmbedding,
    #[error("invalid face embedding encoding")]
    InvalidEncoding,
    #[error("face embedding must contain {FACE_VECTOR_SIZE} values, got {actual}")]
    InvalidLength { actual: u64 },
    #[error("face embedding contains a non-finite value")]
    NonFinite,
    #[error("failed to generate face embedding shares")]
    Sharing,
    #[error("invalid or duplicate public key for face-AMPC party {party}")]
    InvalidRecipient { party: usize },
    #[error("failed to serialize face share for party {party}")]
    Serialization { party: usize },
    #[error("failed to encrypt face share for party {party}")]
    Encryption { party: usize },
}

/// Decode, quantize and share a worker embedding in recipient order 0, 1, 2.
///
/// Supply an RNG seeded from fresh entropy in production. Validation completes
/// before randomness is consumed. The returned shares serialize as Oxide's
/// `{version, share_data}` JSON and erase their owned buffers on drop.
///
/// # Errors
/// Rejects unsupported metadata, malformed encodings, non-512 dimensions and
/// non-finite values; propagates a sharing failure without biometric data.
pub fn generate<R: Rng + CryptoRng>(
    embedding: &FaceEmbedding,
    pcp_version: &str,
    rng: &mut R,
) -> Result<[FaceShare; 3], Error> {
    let quantized = quantize(embedding)?;
    let mut vector = FaceVector::new(*quantized);
    let shares = vector.secret_share(rng);
    vector.0.zeroize();
    Ok(shares.map_err(|_| Error::Sharing)?.map(|mut share| {
        let mut bytes = Zeroizing::new(Vec::with_capacity(FACE_VECTOR_SIZE * 2));
        for value in &share.0 {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        share.0.zeroize();
        FaceShare {
            version: pcp_version.to_owned(),
            share_data: STANDARD.encode(&*bytes),
        }
    }))
}

/// Encrypt each share's JSON with the same-index recipient key using Oxide's
/// libsodium-compatible sealed-box format, then standard-base64 encode it.
///
/// The caller must authenticate the three public keys and supply them in AMPC
/// party order 0, 1, 2. Validation here checks key suitability, not provenance.
/// Supply an RNG seeded from fresh entropy in production. All recipient keys are
/// checked before consuming randomness. Shares remain available to the caller
/// for PCP assembly; temporary plaintext JSON is erased on drop.
///
/// # Errors
/// Rejects duplicate or low-order recipient keys. Propagates serialization and
/// encryption failures without exposing share values.
pub fn encrypt<R: Rng + CryptoRng>(
    shares: &[FaceShare; 3],
    recipient_keys: &[PublicKey; 3],
    rng: &mut R,
) -> Result<[String; 3], Error> {
    for (party, key) in recipient_keys.iter().enumerate() {
        // Parsing a PublicKey checks only its length. A fixed clamped scalar
        // detects points that would produce an all-zero X25519 shared secret.
        if recipient_keys[..party].contains(key)
            || MontgomeryPoint(*key.as_bytes()).mul_clamped([0x42; 32]) == MontgomeryPoint([0; 32])
        {
            return Err(Error::InvalidRecipient { party });
        }
    }

    let mut encrypted = std::array::from_fn(|_| String::new());
    for (party, share) in shares.iter().enumerate() {
        // JSON can escape each input byte as six bytes (\u00XX). Allocate before
        // writing secrets; a fixed slice prevents growth from leaving unwiped copies.
        let capacity = share
            .version
            .len()
            .checked_add(share.share_data.len())
            .and_then(|len| len.checked_mul(6))
            .and_then(|len| len.checked_add(br#"{"version":"","share_data":""}"#.len()))
            .ok_or(Error::Serialization { party })?;
        let mut plaintext = Zeroizing::new(vec![0; capacity]);
        let mut writer = plaintext.as_mut_slice();
        serde_json::to_writer(&mut writer, share).map_err(|_| Error::Serialization { party })?;
        let length = capacity - writer.len();
        let ciphertext = recipient_keys[party]
            .seal(rng, &plaintext[..length])
            .map_err(|_| Error::Encryption { party })?;
        encrypted[party] = STANDARD.encode(ciphertext);
    }
    Ok(encrypted)
}

fn quantize(embedding: &FaceEmbedding) -> Result<Zeroizing<[i8; FACE_VECTOR_SIZE]>, Error> {
    if !matches!(
        embedding.embedding_type.as_str(),
        "ghostfacenet" | "ghostfacenet_flipped_mean"
    ) || embedding.embedding_version != "2.0.0"
        || embedding.embedding_inference_backend != "face-engine"
    {
        return Err(Error::UnsupportedEmbedding);
    }
    // Match the sealed result's bound before allocating decoded bytes.
    if embedding.embedding.len() > 4096 {
        return Err(Error::InvalidEncoding);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    STANDARD
        .decode_vec(&embedding.embedding, &mut bytes)
        .map_err(|_| Error::InvalidEncoding)?;
    // Preflight the fixed-size vector so decoding cannot leave a partial float buffer.
    let count = u64::from_le_bytes(*bytes.first_chunk::<8>().ok_or(Error::InvalidEncoding)?);
    if count != FACE_VECTOR_SIZE as u64 {
        return Err(Error::InvalidLength { actual: count });
    }
    if bytes.len() < 8 + FACE_VECTOR_SIZE * 4 {
        return Err(Error::InvalidEncoding);
    }
    let values = Zeroizing::new(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(1_048_576)
            .deserialize::<Vec<f32>>(&bytes)
            .map_err(|_| Error::InvalidEncoding)?,
    );
    if values.iter().any(|value| !value.is_finite()) {
        return Err(Error::NonFinite);
    }
    let mut quantized = Zeroizing::new([0; FACE_VECTOR_SIZE]);
    for (output, value) in quantized.iter_mut().zip(values.iter()) {
        *output = (value / 0.020_803_409_f32)
            .round_ties_even()
            .clamp(-8.0, 7.0) as i8;
    }
    Ok(quantized)
}
