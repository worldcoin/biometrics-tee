use std::sync::Arc;

use di_migration_enclave_types::{
    self as enclave_types, MigrateRequest, MigrateResponse, pcp_payload,
};

use crate::{blocking, pipeline::Job, state::EnclaveState};

/// Opens the app's PCP with this boot's key, migrates it, and seals the result to the app's
/// one-time response key, so the host only ever handles ciphertext.
pub async fn handler(
    state: Arc<EnclaveState>,
    request: MigrateRequest,
) -> Result<MigrateResponse, enclave_types::Error> {
    if request.blob.is_empty() {
        tracing::warn!("migrate request carried no blob");
        return Err(enclave_types::Error::InvalidInput);
    }

    blocking(move || {
        let (plaintext, sealer) = state.channel().open(&request.blob).map_err(|error| {
            tracing::warn!(?error, "migrate request was not sealed to this boot");
            enclave_types::Error::RequestNotOpened
        })?;
        let pcp = pcp_payload::decode(&plaintext).inspect_err(|_| {
            tracing::warn!("migrate request carried an unknown payload");
        })?;
        let job = Job {
            sub: request.sub,
            device_public_key: request.device_public_key,
        };
        let migrated = state.pipeline().migrate(pcp, &job)?;

        let blob = sealer
            .seal(&pcp_payload::encode(&migrated))
            .map_err(|error| {
                tracing::error!(?error, "failed to seal the migrated PCP");
                enclave_types::Error::Internal
            })?;
        Ok(MigrateResponse { blob })
    })
    .await?
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
    async fn only_the_app_can_open_the_migrated_pcp() {
        let state = Arc::new(test_support::state());
        let (request, opener) = sealed(&state, &pcp_payload::encode(b"old pcp"));

        let response = handler(state, request).await.expect("should migrate");

        assert!(!response.blob.windows(7).any(|window| window == b"old pcp"));
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
