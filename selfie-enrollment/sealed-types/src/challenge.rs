//! Three-pose challenge transcripts and their compact byte representation.
//! This module does not create runs, authenticate callers or evaluate images.

/// The pose the participant is expected to produce, not submitted evidence.
/// Left and right refer to the person's anatomical sides, regardless of mirroring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChallengeOption {
    Forward = 0x00,
    Left = 0x01,
    Right = 0x02,
}

/// Each pose appears exactly once. Initial camera alignment is a separate UI step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetOptions([ChallengeOption; 3]);

/// The complete requested sequence, not evidence of completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeTranscript {
    pub challenge_id: [u8; 16],
    pub target_options: TargetOptions,
    /// UTC milliseconds; the active run must retain and enforce its own deadline.
    pub expires_at_unix_ms: u64,
}

impl ChallengeTranscript {
    /// Sixteen ID bytes, three option codes, then an unsigned big-endian expiry.
    pub fn encode(&self) -> [u8; 27] {
        let mut bytes = [0; 27];
        bytes[..16].copy_from_slice(&self.challenge_id);
        bytes[16..19].copy_from_slice(&self.target_options.encode());
        bytes[19..].copy_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        bytes
    }

    /// Reject wrong lengths, unknown option codes and repeated poses.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 27] = bytes.try_into().map_err(|_| Error)?;
        Ok(Self {
            challenge_id: bytes[..16].try_into().map_err(|_| Error)?,
            target_options: TargetOptions::decode(&bytes[16..19])?,
            expires_at_unix_ms: u64::from_be_bytes(bytes[19..].try_into().map_err(|_| Error)?),
        })
    }

    /// Equality with the deadline is expired. Receipt time must come from the enclave.
    pub fn is_expired_at(&self, received_at_unix_ms: u64) -> bool {
        received_at_unix_ms >= self.expires_at_unix_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid challenge transcript or target options")]
pub struct Error;

impl TargetOptions {
    /// Build one of the six permutations from an order number in 0..6.
    /// Dividing by two selects the first pose; the remainder orders the other two.
    pub fn from_order(order: u8) -> Option<Self> {
        if order >= 6 {
            return None;
        }
        use ChallengeOption::{Forward, Left, Right};
        let mut poses = [Forward, Left, Right];
        // Select the first pose while preserving the order of those remaining.
        poses[..=usize::from(order / 2)].rotate_right(1);
        if order % 2 == 1 {
            poses.swap(1, 2);
        }
        Some(Self(poses))
    }

    pub fn options(&self) -> &[ChallengeOption; 3] {
        &self.0
    }

    /// One byte per pose, in challenge order; hex is just a display convention.
    pub fn encode(&self) -> [u8; 3] {
        self.0.map(|pose| pose as u8)
    }

    /// Reject wrong lengths, unknown pose codes and repeated poses.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let codes: [u8; 3] = bytes.try_into().map_err(|_| Error)?;
        if codes.iter().any(|&code| code > 2)
            || codes[0] == codes[1]
            || codes[0] == codes[2]
            || codes[1] == codes[2]
        {
            return Err(Error);
        }
        let poses = [
            ChallengeOption::Forward,
            ChallengeOption::Left,
            ChallengeOption::Right,
        ];
        Ok(Self(codes.map(|code| poses[usize::from(code)])))
    }
}

/// Deterministically sample an order number in 0..6 from private random seed bytes.
///
/// 252 = floor(256 / 6) * 6, giving each outcome exactly 42 accepted byte values.
/// Reject 252..255 to avoid bias. If every byte is rejected, return None so the
/// enclave can resample (probability 2^-192 for uniform random bytes).
pub fn order_from_seed(seed: &[u8; 32]) -> Option<u8> {
    let byte = seed.iter().copied().find(|&byte| byte < 252)?;
    Some(byte % 6)
}

/// Sample the order number, then construct its target options.
pub fn derive_target_options(seed: &[u8; 32]) -> Option<TargetOptions> {
    order_from_seed(seed).and_then(TargetOptions::from_order)
}
