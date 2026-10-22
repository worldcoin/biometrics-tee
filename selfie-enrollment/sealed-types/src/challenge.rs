//! Draft three-pose contract and deterministic generator.
//!
//! These primitives do not authenticate sessions or randomness, enforce expiry,
//! sign commitments, or evaluate images.
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// One fixed draft format; these tags also separate commitment from generation.
const COMMITMENT_DOMAIN: &[u8] = b"selfie-enrollment/challenge/commitment/v1\0";
const GENERATION_DOMAIN: &[u8] = b"selfie-enrollment/challenge/generation/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid challenge context")]
    InvalidContext,
    #[error("challenge derivation failed")]
    Derivation,
}

/// Public inputs fixed before the nonce is committed and randomness is observed.
///
/// Identifiers and digests are opaque bytes, not raw user/session identifiers.
/// A future run controller must validate their provenance and enforce the deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeContext {
    /// Per-attempt ID assigned by the future enclave run controller.
    pub challenge_id: [u8; 16],
    /// Binding to an authenticated requesting session; its derivation is not defined here.
    pub session_binding: [u8; 32],
    pub expires_at_unix_ms: u64,
    pub policy_digest: [u8; 32],
    /// Digest of the pinned source configuration, including its verification policy.
    pub randomness_source: [u8; 32],
    pub randomness_round: u64,
}

impl ChallengeContext {
    pub fn validate(&self) -> Result<(), Error> {
        if self.challenge_id == [0; 16]
            || self.session_binding == [0; 32]
            || self.policy_digest == [0; 32]
            || self.randomness_source == [0; 32]
            || self.expires_at_unix_ms == 0
            || self.randomness_round == 0
        {
            return Err(Error::InvalidContext);
        }
        Ok(())
    }

    /// Fixed-order bytes for commitment and generation; integers are big-endian.
    fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(&self.challenge_id);
        bytes.extend_from_slice(&self.session_binding);
        bytes.extend_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.randomness_source);
        bytes.extend_from_slice(&self.randomness_round.to_be_bytes());
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The person's anatomical left, independent of camera mirroring.
    Left,
    Right,
}
impl Side {
    fn opposite(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnAngle {
    Deg20,
    Deg25,
}

/// The pose the participant is expected to produce for one challenge step.
/// This describes the expected response, not submitted evidence or an evaluation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetResponse {
    Front,
    Turn { side: Side, angle: TurnAngle },
}

/// Expected responses: one frontal reference, then a turn to each side.
/// Fields are private so callers cannot bypass the generator's shape constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetResponses([TargetResponse; 3]);

impl TargetResponses {
    fn new(side: Side, first: TurnAngle, second: TurnAngle) -> Self {
        Self([
            TargetResponse::Front,
            TargetResponse::Turn { side, angle: first },
            TargetResponse::Turn {
                side: side.opposite(),
                angle: second,
            },
        ])
    }

    pub fn poses(&self) -> &[TargetResponse; 3] {
        &self.0
    }
}

/// Unsigned SHA-256 commitment. The nonce must stay private until permanent closure.
/// No evidence of issuance time or ordering is supplied by this digest alone.
pub fn commitment(context: &ChallengeContext, nonce: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut hash = Sha256::new();
    hash.update(COMMITMENT_DOMAIN);
    hash.update(context.canonical_bytes()?);
    hash.update(nonce);
    Ok(hash.finalize().into())
}

fn derive_seed(
    context: &ChallengeContext,
    nonce: &[u8; 32],
    external_randomness: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let context = context.canonical_bytes()?;
    let mut seed = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(external_randomness), nonce)
        .expand_multi_info(&[GENERATION_DOMAIN, &context], seed.as_mut())
        .map_err(|_| Error::Derivation)?;
    Ok(seed)
}

/// Reproducible target responses from the committed nonce and the selected round's value.
///
/// The caller must verify the randomness source/round separately. This generator
/// has only eight possible plans; the 256-bit seed does not imply 256-bit challenge
/// entropy or resistance to an adaptive image generator.
pub fn derive_target_responses(
    context: &ChallengeContext,
    nonce: &[u8; 32],
    external_randomness: &[u8; 32],
) -> Result<TargetResponses, Error> {
    let seed = derive_seed(context, nonce, external_randomness)?;
    let angle = |mask| {
        if seed[0] & mask == 0 {
            TurnAngle::Deg20
        } else {
            TurnAngle::Deg25
        }
    };
    Ok(TargetResponses::new(
        if seed[0] & 1 == 0 {
            Side::Left
        } else {
            Side::Right
        },
        angle(2),
        angle(4),
    ))
}
