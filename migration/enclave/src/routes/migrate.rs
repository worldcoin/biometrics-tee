use std::{
    io::Read,
    path::Path,
    sync::Arc,
};

use di_migration_enclave_primitives::{
    self as enclave_primitives, MigrateRequest, MigrateResponse, pcp_payload,
};
use flate2::read::GzDecoder;
use tar::Archive;
use world_id_primitives::{
    Credential, EdDSAPublicKey, poseidon::ds, sponge::hash_bytes_to_field_element,
};

use crate::state::EnclaveState;

/// Ceiling for `hashes.json` inside a PCP; the file is a small JSON manifest.
const MAX_HASHES_JSON_BYTES: usize = 1024 * 1024;

/// Opens the app's PCP with this boot's key and seals it back to the app's one-time response
/// key, so the host only ever handles ciphertext. Echoes the PCP until the migration lands;
/// `sub` and the device key are unused until then.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MigrateRequest,
) -> Result<MigrateResponse, enclave_primitives::Error> {
    if request.blob.is_empty() {
        tracing::warn!("migrate request carried no blob");
        return Err(enclave_primitives::Error::InvalidInput);
    }

    // Opening and sealing are CPU-bound; keep them off the async workers.
    tokio::task::spawn_blocking(move || {
        let (plaintext, sealer) = state.channel().open(&request.blob).map_err(|error| {
            tracing::warn!(?error, "migrate request was not sealed to this boot");
            enclave_primitives::Error::RequestNotOpened
        })?;
        let pcp_with_credential = pcp_payload::decode(&plaintext).inspect_err(|_| {
            tracing::warn!("migrate request carried an unknown payload");
        })?;
        verify_credential(
            state.issuer_pubkey(),
            &request.sub,
            &pcp_with_credential.credential,
            &pcp_with_credential.pcp,
        )?;

        let blob = sealer
            .seal(
                &pcp_payload::encode(&pcp_with_credential.pcp, &pcp_with_credential.credential)
                    .map_err(|_| enclave_primitives::Error::Internal)?,
            )
            .map_err(|error| {
                tracing::error!(?error, "failed to seal the migrated PCP");
                enclave_primitives::Error::Internal
            })?;
        Ok(MigrateResponse { blob })
    })
    .await
    .map_err(|error| {
        // The unwind has already zeroized the closure's secrets; restart so the panic is seen.
        if error.is_panic() {
            tracing::error!("migration panicked");
            std::process::exit(1);
        }
        tracing::error!(%error, "migration task was cancelled");
        enclave_primitives::Error::Internal
    })?
}

/// Checks the credential's subject, issuer signature, and PCP `hashes.json` claim.
fn verify_credential(
    issuer_pubkey: &EdDSAPublicKey,
    expected_sub: &str,
    credential_json: &str,
    pcp: &[u8],
) -> Result<(), enclave_primitives::Error> {
    let credential: Credential =
        serde_json::from_slice(credential_json.as_bytes()).map_err(|_| {
            tracing::warn!("failed to deserialize credential");
            enclave_primitives::Error::CredentialDeserializationFailed
        })?;
    if credential.sub.to_string() != expected_sub {
        tracing::warn!("credential sub mismatch");
        return Err(enclave_primitives::Error::CredentialSubMismatch);
    }

    let valid = credential.verify_signature(issuer_pubkey).map_err(|_| {
        tracing::warn!("credential signature verification failed");
        enclave_primitives::Error::CredentialSignatureVerificationFailed
    })?;
    if !valid {
        tracing::warn!("credential signature verification failed");
        return Err(enclave_primitives::Error::CredentialSignatureVerificationFailed);
    }

    // claims[0] is Poseidon2(CLAIMS_HASH_V1, raw hashes.json) for a PCP-backed credential.
    let hashes_json = hashes_json_from_pcp(pcp)?;
    let expected_claim =
        hash_bytes_to_field_element(ds::CLAIMS_HASH_V1, &hashes_json).map_err(|_| {
            tracing::warn!("failed to hash hashes.json into a claim");
            enclave_primitives::Error::CredentialClaimsMismatch
        })?;
    let Some(actual_claim) = credential.claims.first() else {
        tracing::warn!("credential carried no claims");
        return Err(enclave_primitives::Error::CredentialClaimsMismatch);
    };
    if expected_claim != *actual_claim {
        tracing::warn!("credential claims mismatch");
        return Err(enclave_primitives::Error::CredentialClaimsMismatch);
    }
    Ok(())
}

/// Reads `hashes.json` from a gzip-compressed tar PCP without writing to disk.
fn hashes_json_from_pcp(pcp: &[u8]) -> Result<Vec<u8>, enclave_primitives::Error> {
    let mut archive = Archive::new(GzDecoder::new(pcp));
    let entries = archive.entries().map_err(|error| {
        tracing::warn!(%error, "PCP is not a gzip tar archive");
        enclave_primitives::Error::InvalidInput
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            tracing::warn!(%error, "failed to read a PCP tar entry");
            enclave_primitives::Error::InvalidInput
        })?;
        let is_hashes = entry
            .path()
            .map(|path| path.as_ref() == Path::new("hashes.json"))
            .map_err(|error| {
                tracing::warn!(%error, "PCP tar entry path is invalid");
                enclave_primitives::Error::InvalidInput
            })?;
        if !is_hashes {
            continue;
        }

        let mut hashes_json = Vec::new();
        entry
            .take(MAX_HASHES_JSON_BYTES as u64 + 1)
            .read_to_end(&mut hashes_json)
            .map_err(|error| {
                tracing::warn!(%error, "failed to read hashes.json from PCP");
                enclave_primitives::Error::InvalidInput
            })?;
        if hashes_json.is_empty() || hashes_json.len() > MAX_HASHES_JSON_BYTES {
            tracing::warn!("hashes.json missing or too large");
            return Err(enclave_primitives::Error::InvalidInput);
        }
        return Ok(hashes_json);
    }

    tracing::warn!("PCP did not contain hashes.json");
    Err(enclave_primitives::Error::InvalidInput)
}


#[cfg(test)]
mod tests {
    use std::{io::Write, sync::Arc};

    use di_migration_enclave_primitives::{
        self as enclave_primitives, MIGRATION_CHANNEL_DOMAIN, MigrateRequest,
        pcp_payload::{self, PcpWithCredential},
    };
    use flate2::write::GzEncoder;
    use pontifex::channel::{ChannelConsumer, ChannelDomain, ResponseOpener};
    use world_id_primitives::{Credential, EdDSAPrivateKey, FieldElement};

    use super::handler;
    use crate::{state::EnclaveState, test_support};

    /// Seals `plaintext` to `state`'s key as the app does.
    fn sealed(
        state: &EnclaveState,
        plaintext: &[u8],
        sub: impl Into<String>,
    ) -> (MigrateRequest, ResponseOpener) {
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MIGRATION_CHANNEL_DOMAIN),
            &state.channel().public_key(),
        )
        .expect("valid key");
        let (blob, opener) = consumer.seal_to_enclave(plaintext).expect("should seal");
        (
            MigrateRequest {
                blob: blob.into(),
                sub: sub.into(),
                device_public_key: "device-key".to_owned(),
            },
            opener,
        )
    }

    /// Builds a gzip-compressed tar PCP whose only file is `hashes.json`, matching orb PCP layout.
    fn pcp_with_hashes_json(hashes_json: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut tar_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_path("hashes.json").expect("path");
            header.set_size(hashes_json.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive
                .append(&header, hashes_json)
                .expect("append hashes.json");
            archive.finish().expect("finish tar");
        }
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).expect("gzip");
        encoder.finish().expect("finish gzip")
    }

    /// Mirrors iris signup: claim raw bytes are `hashes.json`, then Poseidon-hashed into claims[0]
    /// and signed by the issuer (`createClaimFromPcp` → credential signer).
    fn signed_credential_for_pcp(
        issuer: &EdDSAPrivateKey,
        hashes_json: &[u8],
        sub: FieldElement,
    ) -> String {
        let credential = Credential::new()
            .subject(sub)
            .genesis_issued_at(1_700_000_000)
            .expires_at(2_000_000_000)
            .claim(0, hashes_json)
            .expect("claim from hashes.json")
            .sign(issuer)
            .expect("sign");
        serde_json::to_string(&credential).expect("serialize credential")
    }

    #[tokio::test]
    async fn a_sealed_pcp_round_trips_to_the_app() {
        let issuer = EdDSAPrivateKey::from_bytes([7u8; 32]);
        let state = Arc::new(test_support::state_with_issuer_pubkey(issuer.public()));

        // Compact hashes.json as orbs emit; iris base64-encodes these bytes as the claim input.
        let hashes_json = br#"{"thumbnail.png":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let pcp = pcp_with_hashes_json(hashes_json);
        let sub = FieldElement::from(42u64);
        let credential = signed_credential_for_pcp(&issuer, hashes_json, sub);
        let payload = pcp_payload::encode(&pcp, &credential).expect("encode");

        let (request, opener) = sealed(&state, &payload, sub.to_string());
        let response = handler(state, request).await.expect("should migrate");

        let plaintext = opener
            .open_from_enclave(&response.blob)
            .expect("the app should open it");
        assert_eq!(
            pcp_payload::decode(&plaintext).expect("decode"),
            PcpWithCredential { pcp, credential }
        );
    }

    #[tokio::test]
    async fn a_blob_sealed_to_another_boot_is_not_opened() {
        let earlier = test_support::state();
        let (request, _) = sealed(
            &earlier,
            &pcp_payload::encode(b"old pcp", "self-custody").expect("encode"),
            "sub",
        );

        let error = handler(Arc::new(test_support::state()), request)
            .await
            .expect_err("a new boot cannot open it");

        assert_eq!(error, enclave_primitives::Error::RequestNotOpened);
    }

    #[tokio::test]
    async fn an_unknown_payload_or_empty_blob_is_invalid() {
        let state = Arc::new(test_support::state());
        let (unknown, _) = sealed(&state, &[9, 1, 2], "sub");
        let mut empty = unknown.clone();
        empty.blob = Vec::new().into();

        for request in [unknown, empty] {
            assert_eq!(
                handler(Arc::clone(&state), request).await,
                Err(enclave_primitives::Error::InvalidInput)
            );
        }
    }
}
