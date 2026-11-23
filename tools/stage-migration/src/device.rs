//! A forged staging device, as stage's auth proxy and signup backend accept it.
//!
//! Like an app, it keeps one device key and renews its integrity token before it expires; the
//! token claims match orb-tools' `integrity-forge`, whose tokens cannot be renewed for a key.

use std::{
    convert::Infallible,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use attested_request::{Platform, sign::Signer};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use integrity_forge::{DEFAULT_AG_KID, DEFAULT_AUDIENCE, DEFAULT_ISSUER, DEFAULT_PLATFORM};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use serde_json::{Value, json};

/// How long a token is valid; the same as `integrity-forge` and the staging test gateway.
const TOKEN_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// A token is renewed once it is this old, so no request carries one about to expire.
const RENEW_AFTER: Duration = Duration::from_secs(3 * 60);

pub struct StageDevice {
    device_key: SigningKey,
    device_jwk: Value,
    ag_key: EncodingKey,
    token: Mutex<(String, Instant)>,
}

impl StageDevice {
    pub fn new(ag_private_key_pem: &str) -> Result<Self> {
        let ag_key = EncodingKey::from_ec_pem(ag_private_key_pem.as_bytes())
            .context("the AG key is not a P-256 PKCS#8 PEM")?;
        let device_key = SigningKey::random(&mut rand::rngs::OsRng);
        let point = device_key.verifying_key().to_encoded_point(false);
        let device_jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().context("uncompressed point has x")?),
            "y": URL_SAFE_NO_PAD.encode(point.y().context("uncompressed point has y")?),
        });
        let token = mint(&ag_key, &device_jwk)?;
        Ok(Self {
            device_key,
            device_jwk,
            ag_key,
            token: Mutex::new((token, Instant::now())),
        })
    }

    /// A token for this device's key, renewed when the current one is older than `RENEW_AFTER`.
    pub fn integrity_token(&self) -> String {
        let mut token = self.token.lock().expect("token lock");
        if token.1.elapsed() >= RENEW_AFTER {
            // Minting already succeeded with these keys in `new`.
            let renewed = mint(&self.ag_key, &self.device_jwk).expect("renew the integrity token");
            *token = (renewed, Instant::now());
        }
        token.0.clone()
    }
}

/// An integrity token from the staging test AG key whose `cnf.jwk` is the device key.
fn mint(ag_key: &EncodingKey, device_jwk: &Value) -> Result<String> {
    let exp = (SystemTime::now() + TOKEN_LIFETIME)
        .duration_since(UNIX_EPOCH)
        .context("system clock before the Unix epoch")?
        .as_secs();
    let claims = json!({
        "iss": DEFAULT_ISSUER,
        "aud": DEFAULT_AUDIENCE,
        "exp": exp,
        "pass": true,
        "platform": DEFAULT_PLATFORM,
        "cnf": { "jwk": device_jwk },
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(DEFAULT_AG_KID.to_owned());
    jsonwebtoken::encode(&header, &claims, ag_key).context("sign the integrity token")
}

impl Signer for StageDevice {
    type Error = Infallible;

    fn platform(&self) -> Platform {
        Platform::Android
    }

    fn sign(&self, client_data_hash: &[u8; 32]) -> Result<Vec<u8>, Infallible> {
        let signature: Signature = self
            .device_key
            .sign_prehash(client_data_hash)
            .expect("a 32-byte digest is a valid P-256 prehash");
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::{RENEW_AFTER, StageDevice};

    /// Any P-256 key works as the AG key here.
    fn ag_key_pem() -> String {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        p256::SecretKey::random(&mut rand::rngs::OsRng)
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode PKCS#8")
            .to_string()
    }

    #[test]
    fn a_fresh_token_is_reused_and_an_old_one_renewed() {
        let device = StageDevice::new(&ag_key_pem()).expect("device");
        let first = device.integrity_token();
        assert_eq!(device.integrity_token(), first);

        device.token.lock().expect("lock").1 -= RENEW_AFTER;
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_ne!(device.integrity_token(), first);
    }
}
