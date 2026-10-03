//! Who is calling: the app's attested device key.
//!
//! Only a mock exists until the real verifier (integrity token, request signature, single-use
//! nonce) lands; it trusts a header and is refused at startup unless explicitly allowed.

use axum::http::HeaderMap;
use di_migration_primitives::app_api::DEVICE_PUBLIC_KEY_HEADER;

/// Bounds the key we store; a real key is a few hundred bytes of base64.
const MAX_DEVICE_KEY_LEN: usize = 1024;

/// The caller could not be authenticated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("device key missing or invalid")]
pub struct AuthError;

/// Authenticates a request from its headers and raw body, which a request signature covers.
pub trait Authenticator: Send + Sync {
    /// The caller's verified device public key.
    fn authenticate(&self, headers: &HeaderMap, body: &[u8]) -> Result<String, AuthError>;
}

/// Takes the device key from a header without verifying anything. Never for production.
pub struct TrustedHeaderAuthenticator;

impl Authenticator for TrustedHeaderAuthenticator {
    fn authenticate(&self, headers: &HeaderMap, _body: &[u8]) -> Result<String, AuthError> {
        let key = headers
            .get(DEVICE_PUBLIC_KEY_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .ok_or(AuthError)?;
        if key.is_empty() || key.len() > MAX_DEVICE_KEY_LEN {
            return Err(AuthError);
        }
        Ok(key.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use di_migration_primitives::app_api::DEVICE_PUBLIC_KEY_HEADER;

    use super::{AuthError, Authenticator, TrustedHeaderAuthenticator};

    fn with_key(key: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            DEVICE_PUBLIC_KEY_HEADER,
            HeaderValue::from_str(key).unwrap(),
        );
        headers
    }

    #[test]
    fn the_header_is_the_device_key() {
        assert_eq!(
            TrustedHeaderAuthenticator.authenticate(&with_key("device-key"), b""),
            Ok("device-key".to_owned())
        );
    }

    #[test]
    fn a_missing_blank_or_oversized_key_is_rejected() {
        for headers in [
            HeaderMap::new(),
            with_key("  "),
            with_key(&"k".repeat(1025)),
        ] {
            assert_eq!(
                TrustedHeaderAuthenticator.authenticate(&headers, b""),
                Err(AuthError)
            );
        }
    }
}
