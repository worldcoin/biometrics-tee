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

/// Deterministically select one of the six orders from private random seed bytes.
///
/// Use the first byte below 252, then its remainder modulo six. Rejecting 252..255
/// avoids favoring some orders. If every byte is rejected, return None so the
/// enclave can sample a new seed (probability 2^-192 for uniform random bytes).
/// Keep this table order fixed: it defines how seeds map to expected responses.
pub fn derive_target_responses(seed: &[u8; 32]) -> Option<TargetResponses> {
    use TargetResponse::{Forward, Left, Right};
    const ORDERS: [[TargetResponse; 3]; 6] = [
        [Forward, Left, Right],
        [Forward, Right, Left],
        [Left, Forward, Right],
        [Left, Right, Forward],
        [Right, Forward, Left],
        [Right, Left, Forward],
    ];
    let byte = seed.iter().copied().find(|&byte| byte < 252)?;
    Some(TargetResponses(ORDERS[usize::from(byte % 6)]))
}
