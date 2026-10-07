//! Generate DI shares from the biometric worker's quantized embeddings.
//!
//! Each embedding is 512 signed int4 values, one two's-complement value per byte.
//! The caller retains the float embeddings and metadata for PCP assembly and
//! supplies a cryptographic RNG seeded from fresh entropy in production.

use ampc_secret_sharing::iris_vector::{IRIS_VECTOR_SIZE, IrisVector};
use rand::{CryptoRng, Rng};

/// Three recipient shares for each of one eye's original and mirrored embeddings.
/// Same-index shares belong to the same recipient across embeddings and eyes.
/// Sensitive share contents deliberately do not implement `Debug`.
pub struct EyeShares {
    /// Original embedding shares, each containing 512 values.
    pub embedding_shares: [Vec<u16>; 3],
    /// Mirrored embedding shares in the same recipient order.
    pub mirror_embedding_shares: [Vec<u16>; 3],
}

/// Sharing failures with embedding roles, never embedding values.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An embedding must contain exactly 512 bytes.
    #[error("{embedding} embedding must contain {IRIS_VECTOR_SIZE} bytes, got {actual}")]
    InvalidLength {
        /// Original or mirrored embedding.
        embedding: &'static str,
        /// Received byte count.
        actual: usize,
    },
    /// A signed byte is outside the int4 range.
    #[error("{embedding} embedding contains a value outside [-8, 7]")]
    InvalidValue {
        /// Original or mirrored embedding.
        embedding: &'static str,
    },
    /// The underlying sharing operation failed.
    #[error("failed to generate {embedding} embedding shares")]
    Sharing {
        /// Original or mirrored embedding.
        embedding: &'static str,
        /// Underlying algorithm failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Generate three shares of each quantized embedding using `IrisVector::secret_share`.
///
/// Both inputs are validated before consuming randomness. Bytes encode signed
/// int4 values in two's complement, as in the worker protocol. The RNG advances
/// continuously across both embeddings; use fresh entropy in production.
///
/// # Errors
/// Rejects lengths other than 512 and signed values outside `[-8, 7]`.
/// Propagates sharing failures with the original/mirrored role.
pub fn generate<R: Rng + CryptoRng>(
    embedding: &[u8],
    mirror_embedding: &[u8],
    rng: &mut R,
) -> Result<EyeShares, Error> {
    let original = vector(embedding, "original")?;
    let mirrored = vector(mirror_embedding, "mirrored")?;
    let share = |vector: IrisVector, rng: &mut R, embedding| {
        vector
            .secret_share(rng)
            .map(|shares| shares.map(|share| share.to_vec()))
            .map_err(|source| Error::Sharing {
                embedding,
                source: source.into(),
            })
    };
    Ok(EyeShares {
        embedding_shares: share(original, rng, "original")?,
        mirror_embedding_shares: share(mirrored, rng, "mirrored")?,
    })
}

fn vector(bytes: &[u8], embedding: &'static str) -> Result<IrisVector, Error> {
    let bytes: &[u8; IRIS_VECTOR_SIZE] = bytes.try_into().map_err(|_| Error::InvalidLength {
        embedding,
        actual: bytes.len(),
    })?;
    let values = bytes.map(u8::cast_signed);
    if values.iter().any(|value| !(-8..=7).contains(value)) {
        return Err(Error::InvalidValue { embedding });
    }
    Ok(IrisVector::new(values))
}
