//! Generate DI shares from the biometric worker's quantized embeddings.
//!
//! Each embedding is 512 signed int4 values, one two's-complement value per byte.
//! The caller retains the float embeddings and metadata for PCP assembly and
//! supplies a cryptographic RNG seeded from fresh entropy in production.

use ampc_secret_sharing::iris_vector::{IRIS_VECTOR_SIZE, IrisVector};
use rand::{CryptoRng, Rng};

/// Locked Git revision of the AMPC implementation used to produce these shares.
///
/// This must match the `ampc-secret-sharing` revision pinned in this crate's `Cargo.toml`.
pub const VERSION: &str = "3dfb4aacd8152329d03c4fe71dd81ee05589f360";

/// Sharing failures without embedding values. The caller supplies eye and mirror context.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An embedding must contain exactly 512 bytes.
    #[error("embedding must contain {IRIS_VECTOR_SIZE} bytes, got {actual}")]
    InvalidLength {
        /// Received byte count.
        actual: usize,
    },
    /// A signed byte is outside the int4 range.
    #[error("embedding contains a value outside [-8, 7]")]
    InvalidValue,
    /// The underlying sharing operation failed.
    #[error("failed to generate embedding shares")]
    Sharing {
        /// Underlying algorithm failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Generate three shares of one quantized embedding using `IrisVector::secret_share`.
///
/// The input is validated before consuming randomness. Bytes encode signed int4
/// values in two's complement, as in the worker protocol. Call independently for
/// each original or mirrored embedding, advancing the RNG across calls.
/// Seed the RNG from fresh entropy in production.
///
/// Returns three 512-element vectors in recipient order. Same-index shares
/// belong to the same recipient across embeddings and eyes. The returned values
/// are sensitive; callers must keep them out of logs.
///
/// # Errors
/// Rejects lengths other than 512 and signed values outside `[-8, 7]`.
/// Propagates failures from the underlying sharing operation.
pub fn generate<R: Rng + CryptoRng>(embedding: &[u8], rng: &mut R) -> Result<[Vec<u16>; 3], Error> {
    let bytes: &[u8; IRIS_VECTOR_SIZE] =
        embedding.try_into().map_err(|_| Error::InvalidLength {
            actual: embedding.len(),
        })?;
    let values = bytes.map(u8::cast_signed);
    if values.iter().any(|value| !(-8..=7).contains(value)) {
        return Err(Error::InvalidValue);
    }
    let shares = IrisVector::new(values)
        .secret_share(rng)
        .map_err(|source| Error::Sharing {
            source: source.into(),
        })?;
    Ok(shares.map(|share| share.to_vec()))
}

/// Generate five-party shares of a 512-element quantized embedding.
///
/// Indices 0–4 map to Shamir IDs 1–5; any three recipients can reconstruct the
/// embedding. Supply a cryptographic RNG seeded from fresh entropy and advance it
/// across calls for each eye, mirror and share family. Never log the returned shares.
///
/// # Errors
/// Rejects lengths other than 512 and signed values outside `[-8, 7]` before
/// consuming randomness. Propagates failures from the sharing library.
pub fn generate_5_party<R: Rng + CryptoRng>(
    embedding: &[u8],
    rng: &mut R,
) -> Result<[Vec<u16>; 5], Error> {
    let bytes: &[u8; IRIS_VECTOR_SIZE] =
        embedding.try_into().map_err(|_| Error::InvalidLength {
            actual: embedding.len(),
        })?;
    let values = bytes.map(u8::cast_signed);
    if values.iter().any(|value| !(-8..=7).contains(value)) {
        return Err(Error::InvalidValue);
    }
    let shares = IrisVector::new(values)
        .secret_share_5_parties(rng)
        .map_err(|source| Error::Sharing {
            source: source.into(),
        })?;
    Ok(shares.map(|share| share.to_vec()))
}
