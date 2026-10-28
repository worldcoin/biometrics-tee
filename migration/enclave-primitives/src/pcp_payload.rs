//! The request plaintext inside the sealed channel: a version byte, then the body.
//!
//! The version lets the app's request grow, e.g. by a self-custody key, without a new route.

use serde::{Deserialize, Serialize};

use crate::Error;

/// Payload version: CBOR `{ pcp, credential, device_public_key }` after the version byte.
pub const MIGRATION_PAYLOAD_VERSION: u8 = 2;

/// PCP, self-custody credential, and recipient key the app seals to the enclave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPayload {
    /// The PCP to migrate.
    #[serde(with = "serde_bytes")]
    pub pcp: Vec<u8>,
    /// Self-custody credential sealed into the migrated PCP.
    pub credential: String,
    /// Recipient key bound to the PCP by the client's sealed request.
    #[serde(with = "serde_bytes")]
    pub device_public_key: [u8; 32],
}

/// Prefixes the PCP, credential and recipient key with [`MIGRATION_PAYLOAD_VERSION`].
///
/// # Errors
///
/// [`Error::InvalidInput`] when CBOR encoding fails (should not happen for these fields).
pub fn encode(
    pcp: &[u8],
    credential: &str,
    device_public_key: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let body = MigrationPayload {
        pcp: pcp.to_vec(),
        credential: credential.to_owned(),
        device_public_key: *device_public_key,
    };
    let mut payload = vec![MIGRATION_PAYLOAD_VERSION];
    ciborium::into_writer(&body, &mut payload).map_err(|_| Error::InvalidInput)?;
    Ok(payload)
}

/// The migration inputs inside a [`MIGRATION_PAYLOAD_VERSION`] `payload`.
///
/// # Errors
///
/// [`Error::InvalidInput`] for an unknown version, bad CBOR, an empty PCP/credential,
/// or a missing or incorrectly sized recipient key.
pub fn decode(payload: &[u8]) -> Result<MigrationPayload, Error> {
    let Some((&MIGRATION_PAYLOAD_VERSION, body)) = payload.split_first() else {
        return Err(Error::InvalidInput);
    };
    let decoded: MigrationPayload = ciborium::from_reader(body).map_err(|_| Error::InvalidInput)?;
    if decoded.pcp.is_empty() || decoded.credential.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{MIGRATION_PAYLOAD_VERSION, MigrationPayload, decode, encode};
    use crate::Error;

    #[test]
    fn a_pcp_round_trips() {
        assert_eq!(
            decode(&encode(b"pcp", "cred", &[7; 32]).expect("encode")),
            Ok(MigrationPayload {
                pcp: b"pcp".to_vec(),
                credential: "cred".to_owned(),
                device_public_key: [7; 32],
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
    fn legacy_payloads_and_missing_or_wrong_length_recipient_keys_are_rejected() {
        #[derive(serde::Serialize)]
        struct UncheckedPayload<'a> {
            #[serde(with = "serde_bytes")]
            pcp: &'a [u8],
            credential: &'a str,
            #[serde(with = "serde_bytes", skip_serializing_if = "Option::is_none")]
            device_public_key: Option<Vec<u8>>,
        }
        let mut legacy = encode(b"pcp", "cred", &[7; 32]).unwrap();
        legacy[0] = 1;
        assert_eq!(decode(&legacy), Err(Error::InvalidInput));

        for device_public_key in [None, Some(vec![]), Some(vec![7; 31]), Some(vec![7; 33])] {
            let mut payload = vec![MIGRATION_PAYLOAD_VERSION];
            ciborium::into_writer(
                &UncheckedPayload {
                    pcp: b"pcp",
                    credential: "cred",
                    device_public_key,
                },
                &mut payload,
            )
            .unwrap();
            assert_eq!(decode(&payload), Err(Error::InvalidInput));
        }
    }

    #[test]
    fn a_migration_payload_round_trips() {
        let payload = encode(b"pcp", "cred", &[7; 32]).expect("encode");
        assert_eq!(payload[0], MIGRATION_PAYLOAD_VERSION);
        assert_eq!(
            decode(&payload),
            Ok(MigrationPayload {
                pcp: b"pcp".to_vec(),
                credential: "cred".to_owned(),
                device_public_key: [7; 32],
            })
        );
    }
}
