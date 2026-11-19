//! Length-hiding framing for plaintexts the enclave seals to the app's response key.
//!
//! The host stores the sealed blobs, so their sizes are host-visible. Worker-controlled
//! content (version strings, diagnostic JSON) must not choose those sizes. A padded plaintext
//! is a big-endian `u32` payload length, the payload, then zero bytes up to the target size.

/// Bytes of the length prefix in front of every padded payload.
pub const PADDING_PREFIX_BYTES: usize = 4;

/// The migrated PCP is padded up to a multiple of this many bytes.
pub const PCP_PADDING_BUCKET_BYTES: usize = 64 * 1024;

/// Frames `payload` and pads it with zeros to exactly `total` bytes.
///
/// Returns `None` when `payload` plus its prefix does not fit in `total`, or its length does
/// not fit the prefix.
#[must_use]
pub fn pad_to(payload: &[u8], total: usize) -> Option<Vec<u8>> {
    let length = u32::try_from(payload.len()).ok()?;
    if payload.len() > total.checked_sub(PADDING_PREFIX_BYTES)? {
        return None;
    }
    let mut padded = Vec::with_capacity(total);
    padded.extend_from_slice(&length.to_be_bytes());
    padded.extend_from_slice(payload);
    padded.resize(total, 0);
    Some(padded)
}

/// Frames `payload` and pads it with zeros to the next multiple of `bucket` bytes.
///
/// Returns `None` for a zero `bucket` or a payload too large to frame.
#[must_use]
pub fn pad_to_bucket(payload: &[u8], bucket: usize) -> Option<Vec<u8>> {
    let framed = payload.len().checked_add(PADDING_PREFIX_BYTES)?;
    let total = framed.checked_next_multiple_of(bucket)?;
    pad_to(payload, total)
}

/// The payload inside a padded plaintext, or `None` when the framing is malformed or the
/// padding is not all zeros.
#[must_use]
pub fn unpad(padded: &[u8]) -> Option<&[u8]> {
    let (prefix, rest) = padded.split_first_chunk::<PADDING_PREFIX_BYTES>()?;
    let length = usize::try_from(u32::from_be_bytes(*prefix)).ok()?;
    if length > rest.len() {
        return None;
    }
    let (payload, padding) = rest.split_at(length);
    padding.iter().all(|&byte| byte == 0).then_some(payload)
}

#[cfg(test)]
mod tests {
    use super::{PADDING_PREFIX_BYTES, pad_to, pad_to_bucket, unpad};

    #[test]
    fn padded_payloads_round_trip() {
        for payload in [&b""[..], b"x", &[7; 1000]] {
            let padded = pad_to(payload, 4096).unwrap();
            assert_eq!(padded.len(), 4096);
            assert_eq!(unpad(&padded), Some(payload));
        }
    }

    #[test]
    fn bucketed_sizes_do_not_depend_on_the_exact_payload_length() {
        let short = pad_to_bucket(&[1; 10], 1024).unwrap();
        let long = pad_to_bucket(&[1; 1024 - PADDING_PREFIX_BYTES], 1024).unwrap();
        assert_eq!(short.len(), 1024);
        assert_eq!(long.len(), 1024);
        assert_eq!(pad_to_bucket(&[1; 1024], 1024).unwrap().len(), 2048);
        assert!(pad_to_bucket(b"x", 0).is_none());
    }

    #[test]
    fn a_payload_that_does_not_fit_is_refused() {
        assert!(pad_to(&[0; 13], 16).is_none());
        assert!(pad_to(&[0; 12], 16).is_some());
        assert!(pad_to(b"", 3).is_none());
    }

    #[test]
    fn malformed_padding_is_refused() {
        let mut padded = pad_to(b"abc", 16).unwrap();
        assert!(unpad(&padded[..3]).is_none());
        padded[15] = 1;
        assert!(unpad(&padded).is_none());
        let mut too_long = pad_to(b"abc", 16).unwrap();
        too_long[..4].copy_from_slice(&13u32.to_be_bytes());
        assert!(unpad(&too_long).is_none());
    }
}
