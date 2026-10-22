//! Draft three-pose contract and deterministic generator.
//!
//! These primitives do not authenticate sessions or randomness, enforce expiry,
//! sign commitments, or evaluate images. See `selfie-enrollment/challenge-protocol.md`.
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const CONTRACT_VERSION: u16 = 1;
pub const GENERATOR_VERSION: u16 = 1;
/// Reserved identifier for the proposed three-pose evaluator, not an implementation.
pub const EVALUATOR_VERSION: u16 = 1;
pub const CONTEXT_BYTES: usize = 134;
pub const TARGET_BYTES: usize = 6;

const COMMITMENT_DOMAIN: &[u8] = b"selfie-enrollment/challenge/commitment/v1\0";
const GENERATION_DOMAIN: &[u8] = b"selfie-enrollment/challenge/generation/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unsupported challenge version")]
    UnsupportedVersion,
    #[error("invalid challenge context")]
    InvalidContext,
    #[error("invalid challenge encoding")]
    InvalidEncoding,
    #[error("invalid three-pose targets")]
    InvalidTargets,
    #[error("challenge derivation failed")]
    Derivation,
}

/// Public inputs fixed before the nonce is committed and randomness is observed.
///
/// Identifiers and digests are opaque bytes, not raw user/session identifiers.
/// A future run controller must validate their provenance and enforce the deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeContext {
    pub contract_version: u16,
    pub generator_version: u16,
    pub evaluator_version: u16,
    pub challenge_id: [u8; 16],
    pub session_binding: [u8; 32],
    pub expires_at_unix_ms: u64,
    pub policy_digest: [u8; 32],
    /// Digest of the pinned source configuration, including its verification policy.
    pub randomness_source: [u8; 32],
    pub randomness_round: u64,
}

impl ChallengeContext {
    pub fn validate(&self) -> Result<(), Error> {
        if self.contract_version != CONTRACT_VERSION
            || self.generator_version != GENERATOR_VERSION
            || self.evaluator_version != EVALUATOR_VERSION
        {
            return Err(Error::UnsupportedVersion);
        }
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
        bytes[0..2].copy_from_slice(&self.contract_version.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.generator_version.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.evaluator_version.to_be_bytes());
        bytes[6..22].copy_from_slice(&self.challenge_id);
        bytes[22..54].copy_from_slice(&self.session_binding);
        bytes[54..62].copy_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        bytes[62..94].copy_from_slice(&self.policy_digest);
        bytes[94..126].copy_from_slice(&self.randomness_source);
        bytes[126..134].copy_from_slice(&self.randomness_round.to_be_bytes());
        Ok(bytes)
    }

    /// Rejects truncation, trailing bytes, unknown versions and reserved empty fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CONTEXT_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let field = |range: std::ops::Range<usize>| &bytes[range];
        let context = Self {
            contract_version: u16::from_be_bytes(field(0..2).try_into().unwrap()),
            generator_version: u16::from_be_bytes(field(2..4).try_into().unwrap()),
            evaluator_version: u16::from_be_bytes(field(4..6).try_into().unwrap()),
            challenge_id: field(6..22).try_into().unwrap(),
            session_binding: field(22..54).try_into().unwrap(),
            expires_at_unix_ms: u64::from_be_bytes(field(54..62).try_into().unwrap()),
            policy_digest: field(62..94).try_into().unwrap(),
            randomness_source: field(94..126).try_into().unwrap(),
            randomness_round: u64::from_be_bytes(field(126..134).try_into().unwrap()),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoseTarget {
    Front,
    Turn { side: Side, angle: TurnAngle },
}

/// Exactly one frontal reference, then a turn to each side. Fields are private so
/// callers cannot construct plans that bypass the generator's shape constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Targets([PoseTarget; 3]);

impl Targets {
    fn new(side: Side, first: TurnAngle, second: TurnAngle) -> Self {
        Self([
            PoseTarget::Front,
            PoseTarget::Turn { side, angle: first },
            PoseTarget::Turn {
                side: side.opposite(),
                angle: second,
            },
        ])
    }

    pub fn poses(&self) -> &[PoseTarget; 3] {
        &self.0
    }

    /// Three (side, angle) byte pairs: front=(0,0), left=1, right=2, angles=20/25.
    pub fn encode(&self) -> [u8; TARGET_BYTES] {
        let mut bytes = [0; TARGET_BYTES];
        for (target, pair) in self.0.iter().zip(bytes.as_chunks_mut::<2>().0) {
            if let PoseTarget::Turn { side, angle } = target {
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
        let bytes: [u8; TARGET_BYTES] = bytes.try_into().map_err(|_| Error::InvalidEncoding)?;
        let angle = |value| match value {
            20 => Ok(TurnAngle::Deg20),
            25 => Ok(TurnAngle::Deg25),
            _ => Err(Error::InvalidTargets),
        };
        let side = match (bytes[0], bytes[1], bytes[2], bytes[4]) {
            (0, 0, 1, 2) => Side::Left,
            (0, 0, 2, 1) => Side::Right,
            _ => return Err(Error::InvalidTargets),
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

/// Reproducible targets from the committed nonce and the selected round's value.
///
/// The caller must verify the randomness source/round separately. This generator
/// has only eight possible plans; the 256-bit seed does not imply 256-bit challenge
/// entropy or resistance to an adaptive image generator.
pub fn derive_targets(
    context: &ChallengeContext,
    nonce: &[u8; 32],
    external_randomness: &[u8; 32],
) -> Result<Targets, Error> {
    let seed = derive_seed(context, nonce, external_randomness)?;
    let angle = |mask| {
        if seed[0] & mask == 0 {
            TurnAngle::Deg20
        } else {
            TurnAngle::Deg25
        }
    };
    Ok(Targets::new(
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
            contract_version: value["contract_version"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            generator_version: value["generator_version"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
            evaluator_version: value["evaluator_version"]
                .as_u64()
                .unwrap()
                .try_into()
                .unwrap(),
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
            let targets = derive_targets(&context, &nonce, &randomness).unwrap();
            assert_eq!(targets.encode(), bytes(&vector["targets_hex"]));
            assert_eq!(Targets::decode(&targets.encode()).unwrap(), targets);
            plans.insert(targets.encode());
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
    fn unknown_versions_fail_at_decoding_and_generation_boundaries() {
        for value in [0, 2, u16::MAX] {
            for index in 0..3 {
                let mut context = context();
                let mut encoded = context.encode().unwrap();
                encoded[index * 2..index * 2 + 2].copy_from_slice(&value.to_be_bytes());
                assert_eq!(
                    ChallengeContext::decode(&encoded),
                    Err(Error::UnsupportedVersion)
                );
                match index {
                    0 => context.contract_version = value,
                    1 => context.generator_version = value,
                    _ => context.evaluator_version = value,
                }
                assert_eq!(context.encode(), Err(Error::UnsupportedVersion));
                assert_eq!(
                    commitment(&context, &[0; 32]),
                    Err(Error::UnsupportedVersion)
                );
                assert_eq!(
                    derive_targets(&context, &[0; 32], &[0; 32]),
                    Err(Error::UnsupportedVersion)
                );
            }
        }
    }

    #[test]
    fn empty_identifiers_and_deadlines_are_rejected() {
        for range in [6..22, 22..54, 54..62, 62..94, 94..126, 126..134] {
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
            derive_targets(&invalid, &[0; 32], &[0; 32]),
            Err(Error::InvalidContext)
        );
    }

    #[test]
    fn every_binding_field_and_nonce_affects_commitment_and_seed() {
        let context = context();
        let encoded = context.encode().unwrap();
        let original_commitment = commitment(&context, &[3; 32]).unwrap();
        let original_seed = derive_seed(&context, &[3; 32], &[4; 32]).unwrap();
        // Change every byte in each accepted context field; versions are checked above.
        for offset in 6..CONTEXT_BYTES {
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
        // Target collisions are expected: only three bits of the seed select a plan.
    }

    #[test]
    fn target_codec_accepts_exactly_the_eight_supported_plans() {
        for first_side in 0..=3 {
            for second_side in 0..=3 {
                for first_angle in [0, 19, 20, 21, 25, 26, 255] {
                    for second_angle in [0, 19, 20, 21, 25, 26, 255] {
                        let encoded = [0, 0, first_side, first_angle, second_side, second_angle];
                        let valid = matches!((first_side, second_side), (1, 2) | (2, 1))
                            && matches!(first_angle, 20 | 25)
                            && matches!(second_angle, 20 | 25);
                        assert_eq!(Targets::decode(&encoded).is_ok(), valid);
                    }
                }
            }
        }
        let encoded = [0, 0, 1, 20, 2, 25];
        for length in 0..TARGET_BYTES {
            assert_eq!(
                Targets::decode(&encoded[..length]),
                Err(Error::InvalidEncoding)
            );
        }
        assert_eq!(
            Targets::decode(&[0, 0, 1, 20, 2, 25, 0]),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            Targets::decode(&[1, 20, 1, 20, 2, 25]),
            Err(Error::InvalidTargets)
        );
        assert_eq!(
            Targets::decode(&[0, 20, 1, 20, 2, 25]),
            Err(Error::InvalidTargets)
        );
    }
}
