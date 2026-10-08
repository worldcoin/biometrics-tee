//! The app's attested device key, which the enclave seals into the new PCP.

use attested_request::device::DeviceKey;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{EncodedPoint, PublicKey, ecdsa::VerifyingKey};
use serde::Deserialize;

const COORDINATE_BYTES: usize = 32;

/// Bounds the key we accept; a P-256 JWK is about 120 bytes.
const MAX_JWK_LEN: usize = 1024;

/// The public members of an EC JWK; any others are ignored.
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

/// A device key in the one form the enclave seals.
pub struct CanonicalKey {
    /// The RFC 7638 canonical JWK: `crv`, `kty`, `x`, `y` in that order, no whitespace, and
    /// coordinates padded to 32 bytes.
    pub jwk: String,
    /// Its RFC 7638 thumbprint, as the auth proxy sets `x-attested-key-thumbprint`.
    pub thumbprint: String,
}

/// The canonical form of the P-256 key in `jwk`, or `None` unless `jwk` is a valid EC P-256 JWK.
pub fn canonicalize(jwk: &str) -> Option<CanonicalKey> {
    if jwk.len() > MAX_JWK_LEN {
        return None;
    }
    let jwk: Jwk = serde_json::from_str(jwk).ok()?;
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return None;
    }
    let point = EncodedPoint::from_affine_coordinates(
        &coordinate(&jwk.x)?.into(),
        &coordinate(&jwk.y)?.into(),
        false,
    );
    let key = VerifyingKey::from(PublicKey::from_sec1_bytes(point.as_bytes()).ok()?);
    let point = key.to_encoded_point(false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        unreachable!("an uncompressed point has both coordinates");
    };
    Some(CanonicalKey {
        jwk: format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(x),
            URL_SAFE_NO_PAD.encode(y),
        ),
        thumbprint: DeviceKey::new(key).thumbprint(),
    })
}

// Encoders may strip leading zero bytes, so shorter coordinates are left-padded.
fn coordinate(encoded: &str) -> Option<[u8; COORDINATE_BYTES]> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let padding = COORDINATE_BYTES.checked_sub(bytes.len())?;
    let mut coordinate = [0u8; COORDINATE_BYTES];
    coordinate[padding..].copy_from_slice(&bytes);
    Some(coordinate)
}

#[cfg(test)]
mod tests {
    use attested_request::{device::DeviceKey, test_util::test_key};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::{Digest, Sha256};

    use super::canonicalize;

    fn jwk() -> serde_json::Value {
        serde_json::from_str(&di_migration_client::device_jwk(
            test_key("device-key").verifying_key(),
        ))
        .unwrap()
    }

    #[test]
    fn any_serialization_canonicalizes_to_the_proxy_s_thumbprint() {
        let expected = DeviceKey::new(*test_key("device-key").verifying_key()).thumbprint();
        let mut extra = jwk();
        extra["kid"] = "extra members are dropped".into();

        for sent in [
            jwk().to_string(),
            serde_json::to_string_pretty(&extra).unwrap(),
        ] {
            let key = canonicalize(&sent).expect("a P-256 key");
            assert_eq!(key.thumbprint, expected);
            assert_eq!(
                key.thumbprint,
                URL_SAFE_NO_PAD.encode(Sha256::digest(key.jwk.as_bytes()))
            );
            assert!(
                key.jwk.starts_with(r#"{"crv":"P-256","kty":"EC","x":""#),
                "{}",
                key.jwk
            );
        }
    }

    #[test]
    fn keys_that_are_not_p256_points_are_rejected() {
        let mut other_curve = jwk();
        other_curve["crv"] = "P-384".into();
        let mut off_curve = jwk();
        off_curve["y"] = off_curve["x"].clone();
        let mut not_base64 = jwk();
        not_base64["x"] = "not base64!".into();

        for jwk in [other_curve, off_curve, not_base64] {
            assert!(canonicalize(&jwk.to_string()).is_none(), "{jwk}");
        }
        assert!(canonicalize("not json").is_none());
    }
}
