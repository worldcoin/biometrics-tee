//! The plaintext inside the sealed channel, in both directions: a version byte, then the body.
//!
//! The version lets the app's request grow, e.g. by a self-custody key, without a new route.

use serde::{Deserialize, Serialize};

use crate::Error;

/// Payload version: CBOR `{ pcp, credential }` after the version byte.
pub const PCP_WITH_CREDENTIAL_VERSION: u8 = 1;

/// PCP and self-custody credential the app seals to the enclave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcpWithCredential {
    /// The PCP to migrate.
    #[serde(with = "serde_bytes")]
    pub pcp: Vec<u8>,
    /// Self-custody credential sealed into the migrated PCP.
    pub credential: String,
}

/// Prefixes a CBOR `{ pcp, credential }` with [`PCP_WITH_CREDENTIAL_VERSION`].
///
/// # Errors
///
/// [`Error::InvalidInput`] when CBOR encoding fails (should not happen for these fields).
pub fn encode(pcp: &[u8], credential: &str) -> Result<Vec<u8>, Error> {
    let body = PcpWithCredential {
        pcp: pcp.to_vec(),
        credential: credential.to_owned(),
    };
    let mut payload = vec![PCP_WITH_CREDENTIAL_VERSION];
    ciborium::into_writer(&body, &mut payload).map_err(|_| Error::InvalidInput)?;
    Ok(payload)
}

/// The PCP and credential inside a [`PCP_WITH_CREDENTIAL_VERSION`] `payload`.
///
/// # Errors
///
/// [`Error::InvalidInput`] for an unknown version, bad CBOR, or an empty PCP/credential.
pub fn decode(payload: &[u8]) -> Result<PcpWithCredential, Error> {
    let Some((&PCP_WITH_CREDENTIAL_VERSION, body)) = payload.split_first() else {
        return Err(Error::InvalidInput);
    };
    let decoded: PcpWithCredential =
        ciborium::from_reader(body).map_err(|_| Error::InvalidInput)?;
    if decoded.pcp.is_empty() || decoded.credential.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{PCP_WITH_CREDENTIAL_VERSION, PcpWithCredential, decode, encode};
    use crate::Error;

    #[test]
    fn a_pcp_round_trips() {
        assert_eq!(
            decode(&encode(b"pcp", "cred").expect("encode")),
            Ok(PcpWithCredential {
                pcp: b"pcp".to_vec(),
                credential: "cred".to_owned(),
            })
        );
    }

    #[test]
    fn an_unknown_version_or_empty_pcp_is_invalid() {
        for payload in [&b""[..], &[1][..], &[2, 0xaa][..]] {
            assert_eq!(decode(payload), Err(Error::InvalidInput), "{payload:?}");
        }
    }

    #[test]
    fn a_pcp_with_credential_round_trips() {
        let payload = encode(b"pcp", "cred").expect("encode");
        assert_eq!(payload[0], PCP_WITH_CREDENTIAL_VERSION);
        assert_eq!(
            decode(&payload),
            Ok(PcpWithCredential {
                pcp: b"pcp".to_vec(),
                credential: "cred".to_owned(),
            })
        );
    }
}
