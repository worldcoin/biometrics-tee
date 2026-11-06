//! Enrollment recipients come from the measured image, never the parent or a request.
use std::sync::Arc;

use anyhow::Context;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crypto_box::PublicKey;
use selfie_enrollment_identity::CaptureAttestor;

use crate::{
    State,
    enrollment::{Producer, TrustedContext},
};

const KEY_ENV: [&str; 3] = [
    "FACE_AMPC_PUBLIC_KEY_0",
    "FACE_AMPC_PUBLIC_KEY_1",
    "FACE_AMPC_PUBLIC_KEY_2",
];

#[cfg(target_os = "linux")]
pub(crate) fn from_env() -> anyhow::Result<[Option<String>; 3]> {
    let mut values = [None, None, None];
    for (name, value) in KEY_ENV.into_iter().zip(&mut values) {
        *value = match std::env::var(name) {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be UTF-8"),
        };
    }
    Ok(values)
}

/// Preserve extraction-only releases when no keys are configured. A supplied keyset
/// must be complete and valid; configuration failures must stop startup.
pub(crate) fn configure(
    state: State,
    values: [Option<String>; 3],
    worker_sha384: &str,
    attestor: Arc<dyn CaptureAttestor + Send + Sync>,
) -> anyhow::Result<State> {
    if values.iter().all(Option::is_none) {
        tracing::info!(
            enrollment_enabled = false,
            "enrollment configuration loaded"
        );
        return Ok(state);
    }

    let mut keys = [[0; 32]; 3];
    for (index, (value, key)) in values.into_iter().zip(&mut keys).enumerate() {
        let name = KEY_ENV[index];
        let value =
            value.with_context(|| format!("{name} is required when enrollment is configured"))?;
        let decoded = STANDARD
            .decode(&value)
            .with_context(|| format!("{name} must be standard base64"))?;
        *key = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("{name} must decode to 32 bytes"))?;
    }

    let mut measurement = [0; 48];
    hex::decode_to_slice(worker_sha384, &mut measurement)
        .context("verified worker SHA-384 must be 48 hex-encoded bytes")?;
    let context = TrustedContext::new(keys.map(PublicKey::from), measurement)
        .context("invalid measured enrollment recipients or worker measurement")?;
    let state = state.with_enrollment(Producer::new(context, attestor));
    tracing::info!(enrollment_enabled = true, "enrollment configuration loaded");
    Ok(state)
}
