use pontifex::PcrConfig;
use serde::Deserialize;
use sigstore_verify::{
    PublicKeyVerificationPolicy, Verifier,
    trust_root::{SIGSTORE_PRODUCTION_TRUSTED_ROOT, TrustedRoot},
    types::{Bundle, DerPublicKey},
};

/// An approved PCR registry or the evidence authenticating it is invalid.
#[derive(Debug, thiserror::Error)]
pub enum RegistryVerificationError {
    #[error("invalid base64 for PCR registry {field}: {source}")]
    InvalidBase64 {
        field: &'static str,
        source: base64::DecodeError,
    },
    #[error("invalid Sigstore bundle: {0}")]
    Bundle(#[source] serde_json::Error),
    #[error("invalid PCR approval public key: {0}")]
    ApprovalKey(#[source] sigstore_verify::types::Error),
    #[error("invalid Sigstore trusted root: {0}")]
    TrustedRoot(#[source] sigstore_verify::trust_root::Error),
    #[error("PCR registry verification failed: {0}")]
    Verification(#[source] sigstore_verify::Error),
    #[error("the Sigstore bundle does not prove Rekor log inclusion")]
    MissingInclusionProof,
    #[error("invalid PCR registry JSON: {0}")]
    Registry(#[source] serde_json::Error),
    #[error("{0} must be a nonzero 48-byte hexadecimal measurement")]
    InvalidMeasurement(&'static str),
}

#[derive(Deserialize)]
struct Registry {
    approved_builds: Vec<ApprovedBuild>,
}

#[derive(Deserialize)]
struct ApprovedBuild {
    measurements: Measurements,
}

#[derive(Deserialize)]
#[serde(rename_all = "UPPERCASE", deny_unknown_fields)]
struct Measurements {
    pcr0: String,
    pcr1: String,
    pcr2: String,
}

pub(crate) fn verified_pcr_configs(
    registry: &[u8],
    bundle: &[u8],
    approval_key_pem: &str,
) -> Result<Vec<PcrConfig>, RegistryVerificationError> {
    let bundle: Bundle =
        serde_json::from_slice(bundle).map_err(RegistryVerificationError::Bundle)?;
    // Older bundle versions may contain only a signed promise to include the entry.
    if !bundle.has_inclusion_proof() {
        return Err(RegistryVerificationError::MissingInclusionProof);
    }
    let approval_key =
        DerPublicKey::from_pem(approval_key_pem).map_err(RegistryVerificationError::ApprovalKey)?;
    let trusted_root = TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT)
        .map_err(RegistryVerificationError::TrustedRoot)?;
    let verifier = Verifier::new(&trusted_root).map_err(RegistryVerificationError::Verification)?;
    let policy = PublicKeyVerificationPolicy::new(approval_key);
    let result = verifier
        .verify(registry, &bundle, &policy)
        .map_err(RegistryVerificationError::Verification)?;
    if !result.tlog_verified() {
        return Err(RegistryVerificationError::MissingInclusionProof);
    }

    let registry: Registry =
        serde_json::from_slice(registry).map_err(RegistryVerificationError::Registry)?;
    registry
        .approved_builds
        .into_iter()
        .map(|build| {
            let Measurements { pcr0, pcr1, pcr2 } = build.measurements;
            Ok(PcrConfig::new(pcr_bytes("PCR0", &pcr0)?)
                .with_pcr(1, pcr_bytes("PCR1", &pcr1)?)
                .with_pcr(2, pcr_bytes("PCR2", &pcr2)?))
        })
        .collect()
}

fn pcr_bytes(name: &'static str, hex: &str) -> Result<[u8; 48], RegistryVerificationError> {
    let mut bytes = [0; 48];
    hex::decode_to_slice(hex, &mut bytes)
        .map_err(|_| RegistryVerificationError::InvalidMeasurement(name))?;
    if bytes == [0; 48] {
        return Err(RegistryVerificationError::InvalidMeasurement(name));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTRY: &[u8] =
        include_bytes!("../tests/fixtures/registry-approval/approved-pcrs.json");
    const BUNDLE: &[u8] =
        include_bytes!("../tests/fixtures/registry-approval/approved-pcrs.sigstore.json");
    const KEY: &str = include_str!("../tests/fixtures/registry-approval/approval.pub");

    #[test]
    fn verifies_signed_and_logged_registry() {
        let configs = verified_pcr_configs(REGISTRY, BUNDLE, KEY).unwrap();
        assert_eq!(configs.len(), 1);
    }

    #[test]
    fn rejects_changed_registry_bytes() {
        let mut changed = REGISTRY.to_vec();
        changed.push(b'\n');
        assert!(matches!(
            verified_pcr_configs(&changed, BUNDLE, KEY),
            Err(RegistryVerificationError::Verification(
                sigstore_verify::Error::ArtifactMismatch(_)
            ))
        ));
    }

    #[test]
    fn rejects_signed_inclusion_promise_without_proof() {
        let mut bundle: serde_json::Value = serde_json::from_slice(BUNDLE).unwrap();
        bundle["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1".into();
        bundle["verificationMaterial"]["tlogEntries"][0]
            .as_object_mut()
            .unwrap()
            .remove("inclusionProof");
        assert!(matches!(
            verified_pcr_configs(REGISTRY, &serde_json::to_vec(&bundle).unwrap(), KEY),
            Err(RegistryVerificationError::MissingInclusionProof)
        ));
    }
}
