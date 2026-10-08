//! The app's attested device key, which the enclave seals into the new PCP.

use attested_request::device::DeviceKey;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use di_migration_primitives::app_api::DeviceJwk;
use p256::{EncodedPoint, PublicKey, ecdsa::VerifyingKey};

const COORDINATE_BYTES: usize = 32;

/// A device key the app sent, checked to be a P-256 point.
pub struct SentDeviceKey(VerifyingKey);

impl SentDeviceKey {
    /// The key in `jwk`, or `None` unless it is a valid EC P-256 key.
    pub fn parse(jwk: &DeviceJwk) -> Option<Self> {
        if jwk.kty != "EC" || jwk.crv != "P-256" {
            return None;
        }
        let point = EncodedPoint::from_affine_coordinates(
            &coordinate(&jwk.x)?.into(),
            &coordinate(&jwk.y)?.into(),
            false,
        );
        let key = PublicKey::from_sec1_bytes(point.as_bytes()).ok()?;
        Some(Self(VerifyingKey::from(key)))
    }

    /// The RFC 7638 thumbprint, computed as the auth proxy does for `x-attested-key-thumbprint`.
    pub fn thumbprint(&self) -> String {
        DeviceKey::new(self.0).thumbprint()
    }

    /// The RFC 7638 canonical JWK, the one form the enclave seals.
    pub fn canonical_jwk(&self) -> String {
        let point = self.0.to_encoded_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
            unreachable!("an uncompressed point has both coordinates");
        };
        format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(x),
            URL_SAFE_NO_PAD.encode(y),
        )
    }
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
    use di_migration_primitives::app_api::DeviceJwk;
    use sha2::{Digest, Sha256};

    use super::SentDeviceKey;

    fn jwk() -> DeviceJwk {
        let point = test_key("device-key")
            .verifying_key()
            .to_encoded_point(false);
        DeviceJwk {
            kty: "EC".to_owned(),
            crv: "P-256".to_owned(),
            x: URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            y: URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        }
    }

    #[test]
    fn the_thumbprint_is_the_one_the_proxy_sets() {
        let key = SentDeviceKey::parse(&jwk()).expect("a P-256 key");

        assert_eq!(
            key.thumbprint(),
            DeviceKey::new(*test_key("device-key").verifying_key()).thumbprint()
        );
        assert_eq!(
            key.thumbprint(),
            URL_SAFE_NO_PAD.encode(Sha256::digest(key.canonical_jwk().as_bytes()))
        );
    }

    #[test]
    fn keys_that_are_not_p256_points_are_rejected() {
        let mut other_curve = jwk();
        other_curve.crv = "P-384".to_owned();
        let mut off_curve = jwk();
        off_curve.y = off_curve.x.clone();
        let mut not_base64 = jwk();
        not_base64.x = "not base64!".to_owned();

        for jwk in [other_curve, off_curve, not_base64] {
            assert!(SentDeviceKey::parse(&jwk).is_none(), "{jwk:?}");
        }
    }
}
