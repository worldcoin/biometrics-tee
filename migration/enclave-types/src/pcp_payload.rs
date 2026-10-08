//! The plaintext inside the sealed channel, in both directions: a version byte, then the PCP.
//!
//! The version lets the app's request grow, e.g. by a self-custody key, without a new route.

use crate::Error;

/// The only payload version so far.
pub const PCP_PAYLOAD_VERSION: u8 = 1;

/// Prefixes `pcp` with [`PCP_PAYLOAD_VERSION`].
#[must_use]
pub fn encode(pcp: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(pcp.len() + 1);
    payload.push(PCP_PAYLOAD_VERSION);
    payload.extend_from_slice(pcp);
    payload
}

/// The PCP inside `payload`.
///
/// # Errors
///
/// [`Error::InvalidInput`] for an unknown version or an empty PCP.
pub const fn decode(payload: &[u8]) -> Result<&[u8], Error> {
    match payload.split_first() {
        Some((&PCP_PAYLOAD_VERSION, pcp)) if !pcp.is_empty() => Ok(pcp),
        _ => Err(Error::InvalidInput),
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use crate::Error;

    #[test]
    fn a_pcp_round_trips() {
        assert_eq!(decode(&encode(b"pcp")), Ok(&b"pcp"[..]));
    }

    #[test]
    fn an_unknown_version_or_empty_pcp_is_invalid() {
        for payload in [&b""[..], &[1][..], &[2, 0xaa][..]] {
            assert_eq!(decode(payload), Err(Error::InvalidInput), "{payload:?}");
        }
    }
}
