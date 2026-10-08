use std::sync::Arc;

use di_migration_enclave_types::{
    self as enclave_types, MigrateRequest, MigrateResponse, pcp_payload,
};

use crate::state::EnclaveState;

/// Opens the app's PCP with this boot's key and seals it back to the app's one-time response
/// key, so the host only ever handles ciphertext. Echoes the PCP until the migration lands;
/// `sub` and the device key are unused until then.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MigrateRequest,
) -> Result<MigrateResponse, enclave_types::Error> {
    if request.blob.is_empty() {
        tracing::warn!("migrate request carried no blob");
        return Err(enclave_types::Error::InvalidInput);
    }

    // Opening and sealing are CPU-bound; keep them off the async workers.
    tokio::task::spawn_blocking(move || {
        let (plaintext, sealer) = state.channel().open(&request.blob).map_err(|error| {
            tracing::warn!(?error, "migrate request was not sealed to this boot");
            enclave_types::Error::RequestNotOpened
        })?;
        let pcp = pcp_payload::decode(&plaintext).inspect_err(|_| {
            tracing::warn!("migrate request carried an unknown payload");
        })?;
        let blob = sealer.seal(&pcp_payload::encode(pcp)).map_err(|error| {
            tracing::error!(?error, "failed to seal the migrated PCP");
            enclave_types::Error::Internal
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
        enclave_types::Error::Internal
    })?
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use di_migration_enclave_types::{
        self as enclave_types, MIGRATION_CHANNEL_DOMAIN, MigrateRequest, pcp_payload,
    };
    use pontifex::channel::{ChannelConsumer, ChannelDomain, ResponseOpener};

    use super::handler;
    use crate::{state::EnclaveState, test_support};

    /// Seals `plaintext` to `state`'s key as the app does.
    fn sealed(state: &EnclaveState, plaintext: &[u8]) -> (MigrateRequest, ResponseOpener) {
        let consumer = ChannelConsumer::from_unverified_public_key(
            ChannelDomain::new(MIGRATION_CHANNEL_DOMAIN),
            &state.channel().public_key(),
        )
        .expect("valid key");
        let (blob, opener) = consumer.seal_to_enclave(plaintext).expect("should seal");
        (
            MigrateRequest {
                blob: blob.into(),
                sub: "sub".to_owned(),
                device_public_key: "device-key".to_owned(),
            },
            opener,
        )
    }

    #[tokio::test]
    async fn a_sealed_pcp_round_trips_to_the_app() {
        let state = Arc::new(test_support::state());
        let (request, opener) = sealed(&state, &pcp_payload::encode(b"old pcp"));

        let response = handler(state, request).await.expect("should migrate");

        let plaintext = opener
            .open_from_enclave(&response.blob)
            .expect("the app should open it");
        assert_eq!(pcp_payload::decode(&plaintext), Ok(&b"old pcp"[..]));
    }

    #[tokio::test]
    async fn a_blob_sealed_to_another_boot_is_not_opened() {
        let earlier = test_support::state();
        let (request, _) = sealed(&earlier, &pcp_payload::encode(b"old pcp"));

        let error = handler(Arc::new(test_support::state()), request)
            .await
            .expect_err("a new boot cannot open it");

        assert_eq!(error, enclave_types::Error::RequestNotOpened);
    }

    #[tokio::test]
    async fn an_unknown_payload_or_empty_blob_is_invalid() {
        let state = Arc::new(test_support::state());
        let (unknown, _) = sealed(&state, &[9, 1, 2]);
        let mut empty = unknown.clone();
        empty.blob = Vec::new().into();

        for request in [unknown, empty] {
            assert_eq!(
                handler(Arc::clone(&state), request).await,
                Err(enclave_types::Error::InvalidInput)
            );
        }
    }
}
