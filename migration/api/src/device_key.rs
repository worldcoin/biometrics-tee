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

/// The RFC 7638 thumbprint of the P-256 key in `jwk`, computed as the auth proxy does for
/// `x-attested-key-thumbprint`, or `None` unless `jwk` is a valid EC P-256 JWK.
pub fn thumbprint(jwk: &str) -> Option<String> {
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
    let key = PublicKey::from_sec1_bytes(point.as_bytes()).ok()?;
    Some(DeviceKey::new(VerifyingKey::from(key)).thumbprint())
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

    use super::thumbprint;

    fn jwk() -> serde_json::Value {
        serde_json::from_str(&di_migration_client::device_jwk(
            test_key("device-key").verifying_key(),
        ))
        .unwrap()
    }

    #[test]
    fn the_thumbprint_is_the_one_the_proxy_sets() {
        let expected = DeviceKey::new(*test_key("device-key").verifying_key()).thumbprint();
        let mut reordered = jwk();
        reordered["kid"] = "extra members are ignored".into();

        assert_eq!(thumbprint(&jwk().to_string()), Some(expected.clone()));
        assert_eq!(
            thumbprint(&serde_json::to_string_pretty(&reordered).unwrap()),
            Some(expected)
        );
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
            assert_eq!(thumbprint(&jwk.to_string()), None, "{jwk}");
        }
        assert_eq!(thumbprint("not json"), None);
    }
}
