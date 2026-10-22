//! Draft three-pose contract and deterministic generator.
//!
//! These primitives do not authenticate sessions or randomness, enforce expiry,
//! sign commitments, or evaluate images.
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const CONTEXT_BYTES: usize = 128;
pub const TARGET_RESPONSES_BYTES: usize = 6;

// One fixed draft format; these tags also separate commitment from generation.
const COMMITMENT_DOMAIN: &[u8] = b"selfie-enrollment/challenge/commitment/v1\0";
const GENERATION_DOMAIN: &[u8] = b"selfie-enrollment/challenge/generation/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid challenge context")]
    InvalidContext,
    #[error("invalid challenge encoding")]
    InvalidEncoding,
    #[error("invalid three-pose target responses")]
    InvalidTargetResponses,
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

    /// Fixed-width fields in declaration order; integers are unsigned big-endian.
    pub fn encode(&self) -> Result<[u8; CONTEXT_BYTES], Error> {
        self.validate()?;
        let mut bytes = [0; CONTEXT_BYTES];
        bytes[0..16].copy_from_slice(&self.challenge_id);
        bytes[16..48].copy_from_slice(&self.session_binding);
        bytes[48..56].copy_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        bytes[56..88].copy_from_slice(&self.policy_digest);
        bytes[88..120].copy_from_slice(&self.randomness_source);
        bytes[120..128].copy_from_slice(&self.randomness_round.to_be_bytes());
        Ok(bytes)
    }

    /// Decodes this fixed format; rejects truncation, trailing bytes and empty fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CONTEXT_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let field = |range: std::ops::Range<usize>| &bytes[range];
        let context = Self {
            challenge_id: field(0..16).try_into().unwrap(),
            session_binding: field(16..48).try_into().unwrap(),
            expires_at_unix_ms: u64::from_be_bytes(field(48..56).try_into().unwrap()),
            policy_digest: field(56..88).try_into().unwrap(),
            randomness_source: field(88..120).try_into().unwrap(),
            randomness_round: u64::from_be_bytes(field(120..128).try_into().unwrap()),
        };
        context.validate()?;
        Ok(context)
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

    /// Three (side, angle) byte pairs: front=(0,0), left=1, right=2, angles=20/25.
    pub fn encode(&self) -> [u8; TARGET_RESPONSES_BYTES] {
        let mut bytes = [0; TARGET_RESPONSES_BYTES];
        for (response, pair) in self.0.iter().zip(bytes.as_chunks_mut::<2>().0) {
            if let TargetResponse::Turn { side, angle } = response {
                pair[0] = match side {
                    Side::Left => 1,
                    Side::Right => 2,
                };
                pair[1] = match angle {
                    TurnAngle::Deg20 => 20,
                    TurnAngle::Deg25 => 25,
                };
            }
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; TARGET_RESPONSES_BYTES] =
            bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        let angle = |value| match value {
            20 => Ok(TurnAngle::Deg20),
            25 => Ok(TurnAngle::Deg25),
            _ => Err(Error::InvalidTargetResponses),
        };
        let side = match (bytes[0], bytes[1], bytes[2], bytes[4]) {
            (0, 0, 1, 2) => Side::Left,
            (0, 0, 2, 1) => Side::Right,
            _ => return Err(Error::InvalidTargetResponses),
        };
        Ok(Self::new(side, angle(bytes[3])?, angle(bytes[5])?))
    }
}

/// Unsigned SHA-256 commitment. The nonce must stay private until permanent closure.
/// No evidence of issuance time or ordering is supplied by this digest alone.
pub fn commitment(context: &ChallengeContext, nonce: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut hash = Sha256::new();
    hash.update(COMMITMENT_DOMAIN);
    hash.update(context.encode()?);
    hash.update(nonce);
    Ok(hash.finalize().into())
}

fn derive_seed(
    context: &ChallengeContext,
    nonce: &[u8; 32],
    external_randomness: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let context = context.encode()?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn bytes<const N: usize>(value: &Value) -> [u8; N] {
        hex::decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn fixture_context(value: &Value) -> ChallengeContext {
        ChallengeContext {
            challenge_id: bytes(&value["challenge_id"]),
            session_binding: bytes(&value["session_binding"]),
            expires_at_unix_ms: value["expires_at_unix_ms"].as_u64().unwrap(),
            policy_digest: bytes(&value["policy_digest"]),
            randomness_source: bytes(&value["randomness_source"]),
            randomness_round: value["randomness_round"].as_u64().unwrap(),
        }
    }

    fn vectors() -> Vec<Value> {
        serde_json::from_str(include_str!("../tests/fixtures/challenge-v1.json")).unwrap()
    }

    fn context() -> ChallengeContext {
        fixture_context(&vectors()[0]["context"])
    }

    #[test]
    fn matches_independent_vectors_including_full_kdf_output() {
        let mut plans = std::collections::BTreeSet::new();
        for vector in vectors() {
            let context = fixture_context(&vector["context"]);
            let nonce = bytes(&vector["nonce"]);
            let randomness = bytes(&vector["external_randomness"]);
            let encoded: [u8; CONTEXT_BYTES] = bytes(&vector["context_hex"]);
            assert_eq!(context.encode().unwrap(), encoded, "{}", vector["name"]);
            assert_eq!(ChallengeContext::decode(&encoded).unwrap(), context);
            assert_eq!(
                commitment(&context, &nonce).unwrap(),
                bytes(&vector["commitment_hex"])
            );
            assert_eq!(
                *derive_seed(&context, &nonce, &randomness).unwrap(),
                bytes(&vector["seed_hex"])
            );
            let responses = derive_target_responses(&context, &nonce, &randomness).unwrap();
            assert_eq!(responses.encode(), bytes(&vector["target_responses_hex"]));
            assert_eq!(
                TargetResponses::decode(&responses.encode()).unwrap(),
                responses
            );
            plans.insert(responses.encode());
        }
        assert_eq!(plans.len(), 8);
    }

    #[test]
    fn rejects_every_truncated_context_and_trailing_data() {
        let encoded = context().encode().unwrap();
        for length in 0..CONTEXT_BYTES {
            assert_eq!(
                ChallengeContext::decode(&encoded[..length]),
                Err(Error::InvalidEncoding)
            );
        }
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert_eq!(
            ChallengeContext::decode(&trailing),
            Err(Error::InvalidEncoding)
        );
    }

    #[test]
    fn empty_identifiers_and_deadlines_are_rejected() {
        for range in [0..16, 16..48, 48..56, 56..88, 88..120, 120..128] {
            let mut encoded = context().encode().unwrap();
            encoded[range].fill(0);
            assert_eq!(
                ChallengeContext::decode(&encoded),
                Err(Error::InvalidContext)
            );
        }
        let mut invalid = context();
        invalid.session_binding = [0; 32];
        assert_eq!(invalid.encode(), Err(Error::InvalidContext));
        assert_eq!(commitment(&invalid, &[0; 32]), Err(Error::InvalidContext));
        assert_eq!(
            derive_target_responses(&invalid, &[0; 32], &[0; 32]),
            Err(Error::InvalidContext)
        );
    }

    #[test]
    fn every_binding_field_and_nonce_affects_commitment_and_seed() {
        let context = context();
        let encoded = context.encode().unwrap();
        let original_commitment = commitment(&context, &[3; 32]).unwrap();
        let original_seed = derive_seed(&context, &[3; 32], &[4; 32]).unwrap();
        // Change every byte in each accepted context field.
        for offset in 0..CONTEXT_BYTES {
            let mut modified = encoded;
            modified[offset] ^= 1;
            let other = ChallengeContext::decode(&modified).unwrap();
            assert_ne!(commitment(&other, &[3; 32]).unwrap(), original_commitment);
            assert_ne!(
                *derive_seed(&other, &[3; 32], &[4; 32]).unwrap(),
                *original_seed
            );
        }
        assert_ne!(commitment(&context, &[5; 32]).unwrap(), original_commitment);
        assert_ne!(
            *derive_seed(&context, &[5; 32], &[4; 32]).unwrap(),
            *original_seed
        );
        assert_ne!(
            *derive_seed(&context, &[3; 32], &[5; 32]).unwrap(),
            *original_seed
        );
        // Target response collisions are expected: only three bits of the seed select a plan.
    }

    #[test]
    fn target_responses_codec_accepts_exactly_the_eight_supported_plans() {
        for first_side in 0..=3 {
            for second_side in 0..=3 {
                for first_angle in [0, 19, 20, 21, 25, 26, 255] {
                    for second_angle in [0, 19, 20, 21, 25, 26, 255] {
                        let encoded = [0, 0, first_side, first_angle, second_side, second_angle];
                        let valid = matches!((first_side, second_side), (1, 2) | (2, 1))
                            && matches!(first_angle, 20 | 25)
                            && matches!(second_angle, 20 | 25);
                        assert_eq!(TargetResponses::decode(&encoded).is_ok(), valid);
                    }
                }
            }
        }
        let encoded = [0, 0, 1, 20, 2, 25];
        for length in 0..TARGET_RESPONSES_BYTES {
            assert_eq!(
                TargetResponses::decode(&encoded[..length]),
                Err(Error::InvalidEncoding)
            );
        }
        assert_eq!(
            TargetResponses::decode(&[0, 0, 1, 20, 2, 25, 0]),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            TargetResponses::decode(&[1, 20, 1, 20, 2, 25]),
            Err(Error::InvalidTargetResponses)
        );
        assert_eq!(
            TargetResponses::decode(&[0, 20, 1, 20, 2, 25]),
            Err(Error::InvalidTargetResponses)
        );
    }
}
