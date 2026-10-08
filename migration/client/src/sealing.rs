//! The app's end of the sealed channel: verify the enclave boot, seal the PCP to it, and open
//! the migrated PCP it seals back.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use di_migration_enclave_primitives::{MIGRATION_CHANNEL_DOMAIN, pcp_payload};
use di_migration_primitives::{EnclaveId, app_api::InitMigrationResponse};
use pontifex::{
    PcrConfig, Verifier,
    channel::{ChannelConsumer, ChannelDomain, ChannelError, ResponseOpener},
};
use zeroize::Zeroizing;

/// The oldest attestation document the enclave still serves while its refresh keeps failing.
const MAX_ATTESTATION_AGE: Duration = Duration::from_hours(1);

#[derive(Debug, thiserror::Error)]
pub enum SealingError {
    #[error("the init response's {field} is not valid base64")]
    InvalidBase64 { field: &'static str },
    #[error("the enclave's attestation was not verified: {0}")]
    Attestation(#[source] ChannelError),
    #[error("enclave_id {claimed} does not match the attested key {attested}")]
    EnclaveIdMismatch { claimed: String, attested: String },
    #[error("failed to encode the sealed payload")]
    Encode,
    #[error("failed to seal the PCP: {0}")]
    Seal(#[source] ChannelError),
    #[error("failed to open the migrated PCP: {0}")]
    Open(#[source] ChannelError),
    #[error("the migrated PCP carried an unknown payload")]
    UnknownPayload,
}

/// Checks enclave attestations against the PCRs of the enclave builds the app trusts.
pub struct EnclaveVerifier(Verifier);

impl EnclaveVerifier {
    /// Trusts an enclave whose PCRs match one of `trusted`.
    #[must_use]
    pub fn new(trusted: Vec<PcrConfig>) -> Self {
        Self(Verifier::new(trusted, MAX_ATTESTATION_AGE))
    }

    /// Trusts any genuine Nitro enclave, whatever it runs; for debug-mode enclaves, whose PCRs
    /// are zero.
    #[must_use]
    pub fn dangerously_skip_measurements() -> Self {
        Self(Verifier::new(Vec::new(), MAX_ATTESTATION_AGE).dangerously_skip_measurements())
    }

    /// The channel to the enclave boot `init` names, once its attestation verifies and commits
    /// to the key and `enclave_id` the API returned.
    ///
    /// # Errors
    ///
    /// [`SealingError`] when the response is malformed or the enclave is not trusted.
    pub fn attested_channel(
        &self,
        init: &InitMigrationResponse,
    ) -> Result<EnclaveChannel, SealingError> {
        let document = decode(&init.attestation, "attestation")?;
        let public_key = decode(&init.enclave_public_key, "enclave_public_key")?;
        let (consumer, _) = ChannelConsumer::from_attestation(
            ChannelDomain::new(MIGRATION_CHANNEL_DOMAIN),
            &self.0,
            &document,
            &public_key,
        )
        .map_err(SealingError::Attestation)?;

        check_enclave_id(&init.enclave_id, &public_key)?;

        Ok(EnclaveChannel(consumer))
    }
}

/// The API routes the job by `enclave_id`; a wrong one sends the PCP to a boot that can't open it.
fn check_enclave_id(claimed: &EnclaveId, attested_key: &[u8]) -> Result<(), SealingError> {
    let attested =
        EnclaveId::from_commitment(pontifex::channel::public_key_commitment(attested_key));
    if &attested != claimed {
        return Err(SealingError::EnclaveIdMismatch {
            claimed: claimed.as_str().to_owned(),
            attested: attested.as_str().to_owned(),
        });
    }
    Ok(())
}

/// A channel to one verified enclave boot.
pub struct EnclaveChannel(ChannelConsumer);

impl EnclaveChannel {
    /// Seals `pcp` and `credential` as CBOR for upload. Only the returned opener can read the
    /// enclave's reply, and it cannot be persisted: keep it until the migrated PCP is downloaded.
    ///
    /// # Errors
    ///
    /// [`SealingError::Encode`] when the payload cannot be built, [`SealingError::Seal`] when
    /// sealing fails.
    pub fn seal(&self, pcp: &[u8], credential: &str) -> Result<(Vec<u8>, PcpOpener), SealingError> {
        let plaintext = pcp_payload::encode(pcp, credential).map_err(|_| SealingError::Encode)?;
        let (blob, opener) = self
            .0
            .seal_to_enclave(&plaintext)
            .map_err(SealingError::Seal)?;
        Ok((blob, PcpOpener(opener)))
    }
}

/// Opens the one reply to a sealed PCP.
pub struct PcpOpener(ResponseOpener);

impl PcpOpener {
    /// The migrated PCP inside the downloaded `blob`.
    ///
    /// # Errors
    ///
    /// [`SealingError`] when `blob` was not sealed to this request or carries an unknown payload.
    pub fn open(self, blob: &[u8]) -> Result<(Zeroizing<Vec<u8>>, String), SealingError> {
        let payload = self.0.open_from_enclave(blob).map_err(SealingError::Open)?;
        let pcp = pcp_payload::decode(&payload).map_err(|_| SealingError::UnknownPayload)?;
        Ok((Zeroizing::new(pcp.pcp), pcp.credential))
    }
}

fn decode(value: &str, field: &'static str) -> Result<Vec<u8>, SealingError> {
    STANDARD
        .decode(value)
        .map_err(|_| SealingError::InvalidBase64 { field })
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use di_migration_enclave_primitives::{MIGRATION_CHANNEL_DOMAIN, pcp_payload};
    use di_migration_primitives::{EnclaveId, app_api::InitMigrationResponse};
    use pontifex::channel::{ChannelConsumer, ChannelDomain, ChannelEnclave};

    use super::{EnclaveChannel, EnclaveVerifier, SealingError, check_enclave_id};

    fn domain() -> ChannelDomain {
        ChannelDomain::new(MIGRATION_CHANNEL_DOMAIN)
    }

    fn init(enclave: &ChannelEnclave, attestation: &[u8]) -> InitMigrationResponse {
        InitMigrationResponse {
            enclave_id: EnclaveId::from_commitment(enclave.public_key_commitment()),
            attestation: STANDARD.encode(attestation),
            enclave_public_key: STANDARD.encode(enclave.public_key()),
            upload_url: "http://s3.test/pcp/1".to_owned(),
            migrate_by: 1,
        }
    }

    /// The enclave's side of `/v1/migrate`, as in the enclave crate.
    fn migrate(enclave: &ChannelEnclave, blob: &[u8]) -> Vec<u8> {
        let (plaintext, sealer) = enclave.open(blob).expect("sealed to this enclave");
        let pcp = pcp_payload::decode(&plaintext).expect("a PCP payload");
        sealer
            .seal(&pcp_payload::encode(&pcp.pcp, &pcp.credential).expect("encode"))
            .expect("should seal")
    }

    #[test]
    fn a_sealed_pcp_round_trips_through_the_enclave() {
        let enclave = ChannelEnclave::generate(domain()).expect("should generate");
        let channel = EnclaveChannel(
            ChannelConsumer::from_unverified_public_key(domain(), &enclave.public_key())
                .expect("valid key"),
        );

        let (blob, opener) = channel
            .seal(b"old pcp", "self-custody")
            .expect("should seal");
        let pcp = opener.open(&migrate(&enclave, &blob)).expect("should open");

        assert_eq!(pcp.0.as_slice(), b"old pcp");
        assert_eq!(pcp.1, "self-custody");
    }

    #[test]
    fn seal_with_credential_puts_cbor_on_the_wire() {
        let enclave = ChannelEnclave::generate(domain()).expect("should generate");
        let channel = EnclaveChannel(
            ChannelConsumer::from_unverified_public_key(domain(), &enclave.public_key())
                .expect("valid key"),
        );

        let (blob, _) = channel
            .seal(b"old pcp", "self-custody")
            .expect("should seal");
        let (plaintext, _) = enclave.open(&blob).expect("sealed to this enclave");
        let decoded = pcp_payload::decode(&plaintext).expect("credential payload");

        assert_eq!(decoded.pcp, b"old pcp");
        assert_eq!(decoded.credential, "self-custody");
    }

    #[test]
    fn a_reply_to_another_request_is_not_opened() {
        let enclave = ChannelEnclave::generate(domain()).expect("should generate");
        let channel = EnclaveChannel(
            ChannelConsumer::from_unverified_public_key(domain(), &enclave.public_key())
                .expect("valid key"),
        );
        let (first, _) = channel.seal(b"first", "self-custody").expect("should seal");
        let (_, second_opener) = channel
            .seal(b"second", "self-custody")
            .expect("should seal");

        let error = second_opener
            .open(&migrate(&enclave, &first))
            .expect_err("another request's reply");

        assert!(matches!(error, SealingError::Open(_)), "{error}");
    }

    #[test]
    fn an_unverifiable_attestation_is_rejected() {
        let enclave = ChannelEnclave::generate(domain()).expect("should generate");

        let error = EnclaveVerifier::dangerously_skip_measurements()
            .attested_channel(&init(&enclave, b"not a COSE document"))
            .err()
            .expect("a forged attestation");

        assert!(matches!(error, SealingError::Attestation(_)), "{error}");
    }

    #[test]
    fn malformed_base64_is_rejected_before_verification() {
        let enclave = ChannelEnclave::generate(domain()).expect("should generate");
        let mut response = init(&enclave, b"doc");
        response.enclave_public_key = "not base64!".to_owned();

        let error = EnclaveVerifier::dangerously_skip_measurements()
            .attested_channel(&response)
            .err()
            .expect("malformed key");

        assert!(
            matches!(
                error,
                SealingError::InvalidBase64 {
                    field: "enclave_public_key"
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn an_enclave_id_of_another_boot_is_rejected() {
        let attested = ChannelEnclave::generate(domain()).expect("should generate");
        let other = ChannelEnclave::generate(domain()).expect("should generate");
        let claimed = EnclaveId::from_commitment(other.public_key_commitment());

        assert!(
            check_enclave_id(&init(&attested, b"doc").enclave_id, &attested.public_key()).is_ok()
        );
        let error = check_enclave_id(&claimed, &attested.public_key())
            .expect_err("another boot's enclave_id");

        assert!(
            matches!(error, SealingError::EnclaveIdMismatch { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_reply_with_an_unknown_payload_version_is_rejected() {
        let enclave = ChannelEnclave::generate(domain()).expect("should generate");
        let channel = EnclaveChannel(
            ChannelConsumer::from_unverified_public_key(domain(), &enclave.public_key())
                .expect("valid key"),
        );
        let (blob, opener) = channel
            .seal(b"old pcp", "self-custody")
            .expect("should seal");

        // An enclave build that replies with a payload version this client does not know.
        let (_, sealer) = enclave.open(&blob).expect("sealed to this enclave");
        let reply = sealer
            .seal(&[pcp_payload::PCP_PAYLOAD_VERSION + 1, 0x42])
            .expect("should seal");
        let error = opener.open(&reply).expect_err("an unknown payload");

        assert!(matches!(error, SealingError::UnknownPayload), "{error}");
    }
}
