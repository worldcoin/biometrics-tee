//! The parent relays TLS bytes and supplies its temporary workload credentials.
//!
//! Credential frames are length-prefixed JSON, capped before allocation. Both
//! endpoints ship together; frames carry a version and reject unknown fields.

use aws_credential_types::Credentials;
use serde::{Deserialize, Serialize};
use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

/// Parent CID assigned by Nitro.
pub const PARENT_CID: u32 = 3;
/// Parent port forwarding opaque TLS to the configured regional KMS endpoint.
pub const TLS_PORT: u32 = 7000;
/// Parent port serving temporary credentials only to its configured enclave CID.
pub const CREDENTIALS_PORT: u32 = 7001;
/// Entire credential exchange, including provider refresh, must fit this deadline.
pub const CREDENTIALS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_FRAME: usize = 16 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    version: u8,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expires_at: u64,
}

impl Drop for Frame {
    fn drop(&mut self) {
        self.access_key_id.zeroize();
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid temporary credential frame",
    )
}

impl Frame {
    fn expiry(&self) -> io::Result<SystemTime> {
        let expiry = UNIX_EPOCH
            .checked_add(Duration::from_secs(self.expires_at))
            .ok_or_else(invalid)?;
        if self.version != 1
            || self.access_key_id.is_empty()
            || self.access_key_id.len() > 128
            || self.secret_access_key.is_empty()
            || self.secret_access_key.len() > 128
            || self.session_token.is_empty()
            || self.session_token.len() > 8192
            || expiry.duration_since(SystemTime::now()).unwrap_or_default()
                < Duration::from_secs(60)
        {
            return Err(invalid());
        }
        Ok(expiry)
    }
}

/// Sends one validated temporary-credential frame. The caller bounds the exchange time.
///
/// # Errors
/// Rejects static, expired or incomplete credentials and propagates I/O failures.
pub async fn write_credentials(
    stream: &mut (impl AsyncWrite + Unpin),
    credentials: &Credentials,
) -> io::Result<()> {
    let frame = Frame {
        version: 1,
        access_key_id: credentials.access_key_id().to_owned(),
        secret_access_key: credentials.secret_access_key().to_owned(),
        session_token: credentials.session_token().ok_or_else(invalid)?.to_owned(),
        expires_at: credentials
            .expiry()
            .ok_or_else(invalid)?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_secs(),
    };
    frame.expiry()?;
    let bytes = Zeroizing::new(serde_json::to_vec(&frame).map_err(|_| invalid())?);
    if bytes.len() > MAX_FRAME {
        return Err(invalid());
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| invalid())?)
        .await?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await
}

/// Reads bounded temporary credentials.
///
/// SDK identity caching uses their expiration
/// to request a fresh frame. The caller bounds the exchange time.
///
/// # Errors
/// Rejects malformed, oversized, expired or unsupported frames and I/O failures.
pub async fn read_credentials(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<Credentials> {
    let len = stream.read_u32().await? as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    stream.read_exact(&mut bytes).await?;
    let frame: Frame = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let expiry = frame.expiry()?;
    Ok(Credentials::new(
        &frame.access_key_id,
        &frame.secret_access_key,
        Some(frame.session_token.clone()),
        Some(expiry),
        "enclave-parent",
    ))
}

/// Regional AWS KMS hostname; region input cannot supply a URL or port.
#[must_use]
pub fn hostname(region: &str) -> Option<String> {
    if region.len() > 32
        || region.is_empty()
        || !region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return None;
    }
    let suffix = if region.starts_with("cn-") {
        "amazonaws.com.cn"
    } else {
        "amazonaws.com"
    };
    Some(format!("kms.{region}.{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary() -> Credentials {
        Credentials::new(
            "synthetic-id",
            "synthetic-secret",
            Some("synthetic-token".into()),
            Some(SystemTime::now() + Duration::from_secs(3600)),
            "test",
        )
    }

    #[tokio::test]
    async fn temporary_credentials_round_trip_with_expiry() {
        let (mut writer, mut reader) = tokio::io::duplex(MAX_FRAME);
        let expected = temporary();
        write_credentials(&mut writer, &expected).await.unwrap();
        let actual = read_credentials(&mut reader).await.unwrap();
        assert_eq!(actual.access_key_id(), expected.access_key_id());
        assert_eq!(actual.secret_access_key(), expected.secret_access_key());
        assert_eq!(actual.session_token(), expected.session_token());
        assert_eq!(
            actual
                .expiry()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expected
                .expiry()
                .unwrap()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
    }

    #[tokio::test]
    async fn static_and_near_expiry_credentials_are_not_sent() {
        for expiry in [
            None,
            Some(SystemTime::now()),
            Some(SystemTime::now() + Duration::from_secs(30)),
        ] {
            let credentials =
                Credentials::new("id", "secret", Some("token".into()), expiry, "test");
            assert!(
                write_credentials(&mut tokio::io::sink(), &credentials)
                    .await
                    .is_err()
            );
        }
        let credentials = Credentials::new(
            "id",
            "secret",
            None,
            Some(SystemTime::now() + Duration::from_secs(3600)),
            "test",
        );
        assert!(
            write_credentials(&mut tokio::io::sink(), &credentials)
                .await
                .is_err()
        );
    }

    async fn read_frame(bytes: &[u8]) -> io::Result<Credentials> {
        let mut frame = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(bytes);
        read_credentials(&mut frame.as_slice()).await
    }

    #[tokio::test]
    async fn malformed_and_unbounded_frames_fail_without_echoing_secrets() {
        for bytes in [
            b"sensitive-invalid-json".as_slice(),
            b"{}",
            b"{\"version\":2}",
        ] {
            let error = read_frame(bytes).await.unwrap_err();
            assert!(!format!("{error:?}").contains("sensitive"));
        }
        for len in [0u32, 16385, u32::MAX] {
            assert!(
                read_credentials(&mut len.to_be_bytes().as_slice())
                    .await
                    .is_err()
            );
        }
        let mut value = serde_json::json!({"version":1,"access_key_id":"id","secret_access_key":"secret","session_token":"token","expires_at":u64::MAX});
        assert!(
            read_frame(&serde_json::to_vec(&value).unwrap())
                .await
                .is_err()
        );
        value["expires_at"] = serde_json::json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600
        );
        value["extra"] = serde_json::json!("unsupported");
        assert!(
            read_frame(&serde_json::to_vec(&value).unwrap())
                .await
                .is_err()
        );
        value.as_object_mut().unwrap().remove("extra");
        value["version"] = serde_json::json!(2);
        assert!(
            read_frame(&serde_json::to_vec(&value).unwrap())
                .await
                .is_err()
        );
    }

    #[test]
    fn endpoints_are_fixed_aws_hostnames() {
        assert_eq!(
            hostname("us-east-1").unwrap(),
            "kms.us-east-1.amazonaws.com"
        );
        assert_eq!(
            hostname("cn-north-1").unwrap(),
            "kms.cn-north-1.amazonaws.com.cn"
        );
        for region in ["", "evil.example", "us-east-1:443", "../", "us-east-1\n"] {
            assert!(hostname(region).is_none());
        }
    }
}
