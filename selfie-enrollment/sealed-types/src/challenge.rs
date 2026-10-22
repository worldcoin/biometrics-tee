//! Three-pose challenge generation and its compact byte representation.
//! This module does not create runs, authenticate callers or evaluate images.

/// The pose the participant is expected to produce, not submitted evidence.
/// Left and right refer to the person's anatomical sides, regardless of mirroring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TargetResponse {
    Forward = 0x00,
    Left = 0x01,
    Right = 0x02,
}

/// Each pose appears exactly once. Initial camera alignment is a separate UI step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetResponses([TargetResponse; 3]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("expected three distinct pose codes: 0x00, 0x01 and 0x02")]
pub struct Error;

impl TargetResponses {
    /// Build one of the six permutations from an order number in 0..6.
    /// Dividing by two selects the first pose; the remainder orders the other two.
    pub fn from_order(order: u8) -> Option<Self> {
        if order >= 6 {
            return None;
        }
        use TargetResponse::{Forward, Left, Right};
        let mut poses = [Forward, Left, Right];
        // Select the first pose while preserving the order of those remaining.
        poses[..=usize::from(order / 2)].rotate_right(1);
        if order % 2 == 1 {
            poses.swap(1, 2);
        }
        Some(Self(poses))
    }

    pub fn poses(&self) -> &[TargetResponse; 3] {
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
            TargetResponse::Forward,
            TargetResponse::Left,
            TargetResponse::Right,
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

/// Sample the order number, then construct its expected responses.
pub fn derive_target_responses(seed: &[u8; 32]) -> Option<TargetResponses> {
    order_from_seed(seed).and_then(TargetResponses::from_order)
}
