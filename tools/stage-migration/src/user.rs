//! A real stage user, enrolled with the reference PCP and holding a staging credential for it.

use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oxide::{EnrollmentStatus, IdentityDeletionStatus};
use signup_flow::{
    file_system::TestInMemoryDeviceFileSystem,
    make_bundle_with_pcp_package,
    orb_enrollment_harness::OrbEnrollmentHarness,
    walletkit_utils::{self, OnChainUser, TEE_MIGRATION_CHALLENGE_TYPE},
};
use uuid::Uuid;

use crate::{
    device::StageDevice,
    reference::{extract_iris_share_files, repack_reference_pcp},
};

/// The files of a decrypted (tier 0) PCP, the template every user's PCP is repacked from.
pub struct ReferencePcp(BTreeMap<String, Vec<u8>>);

impl ReferencePcp {
    /// Reads every file directly in `dir`; the PCP has no subdirectories.
    pub fn read(dir: &Path) -> Result<Self> {
        let mut files = BTreeMap::new();
        for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("PCP file names must be UTF-8"))?;
            if name.starts_with('.') {
                continue;
            }
            ensure!(
                entry.file_type()?.is_file(),
                "{name} in the PCP is not a file"
            );
            files.insert(name, std::fs::read(entry.path())?);
        }
        ensure!(
            files.contains_key("hashes.json"),
            "{} is not a decrypted PCP",
            dir.display()
        );
        Ok(Self(files))
    }
}

pub struct StageUser {
    pub sub: String,
    pub credential: String,
    /// The PCP the credential was issued for, as the gzip tar the enclave reads.
    pub pcp: Vec<u8>,
    pub device: Arc<StageDevice>,
    wallet: OnChainUser,
    harness: OrbEnrollmentHarness,
}

/// A World ID ownership proof, as the migration API takes it.
pub struct OwnershipProof {
    pub proof: String,
    pub challenge_id: String,
}

impl StageUser {
    /// Registers a World ID on stage, enrolls it with a generated PCP, swaps in the reference
    /// PCP and refreshes the enrollment for a credential that covers it.
    pub async fn provision(ag_private_key_pem: &str, reference: &ReferencePcp) -> Result<Self> {
        let wallet = register_world_id().await?;
        let harness = OrbEnrollmentHarness::new_with_file_system(
            wallet.sub.clone(),
            Arc::new(TestInMemoryDeviceFileSystem::new()),
        )
        .with_integrity_meta_request(integrity_forge::forged_integrity_request(
            ag_private_key_pem.to_owned(),
        ));

        let signup_id = Uuid::new_v4().as_simple().to_string();
        let signup_pcp = make_bundle_with_pcp_package(
            &signup_id,
            "DE",
            &harness.identity_commitment(),
            &mut rand::rngs::OsRng,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .context("generate the enrollment PCP")?;
        let iris_shares = extract_iris_share_files(&signup_pcp)?;
        harness.install_pcp(&signup_id, &signup_pcp)?;
        let enrollment = harness
            .send_enrollment_request(None)
            .await
            .context("enroll on stage")?;
        ensure!(
            enrollment.status == EnrollmentStatus::SIGNUP_UNIQUE_SUCCESSFUL,
            "stage enrollment ended as {:?}",
            enrollment.status
        );

        let pcp = repack_reference_pcp(
            reference.0.clone(),
            &enrollment.capture_id,
            &harness.identity_commitment(),
            &iris_shares,
        )
        .context("repack the reference PCP")?;
        harness.install_pcp(&enrollment.capture_id, &pcp)?;
        let credential = harness
            .refresh_enrollment(Some(wallet.sub.clone()))
            .await
            .context("refresh the enrollment for a credential")?;
        let credential = String::from_utf8(STANDARD.decode(credential)?)
            .context("the staging credential is not UTF-8 JSON")?;

        Ok(Self {
            sub: wallet.sub.clone(),
            credential,
            pcp,
            device: Arc::new(StageDevice::new(ag_private_key_pem)?),
            wallet,
            harness,
        })
    }

    /// A fresh proof over a new `teedi_migration` challenge.
    pub async fn ownership_proof(&self) -> Result<OwnershipProof> {
        let proof = self
            .wallet
            .generate_v4_proof(TEE_MIGRATION_CHALLENGE_TYPE)
            .await?;
        Ok(OwnershipProof {
            proof: STANDARD.encode(&proof.proof_cbor),
            challenge_id: proof.challenge_id,
        })
    }

    /// Deletes the stage identity, so load tests do not leave enrolled users behind.
    pub async fn delete(&self) -> Result<()> {
        let response = self.harness.delete_identity().await?;
        ensure!(
            response.status == IdentityDeletionStatus::IrisDeletionRequestIssued,
            "identity deletion ended as {:?}",
            response.status
        );
        Ok(())
    }
}

/// Registration attempts per World ID.
const REGISTRATION_ATTEMPTS: u32 = 4;

/// Registers a World ID, retrying with backoff: concurrent registrations on stage can race for
/// the next registry leaf and fail with a leaf index mismatch.
async fn register_world_id() -> Result<OnChainUser> {
    let mut attempt = 1;
    loop {
        let store = walletkit_utils::create_credential_store()?;
        match walletkit_utils::init_user_on_chain_with_credentials(store).await {
            Ok(wallet) => return Ok(wallet),
            Err(error) if attempt < REGISTRATION_ATTEMPTS => {
                let backoff = Duration::from_secs(2u64.pow(attempt))
                    + Duration::from_millis(fastrand::u64(..1000));
                eprintln!(
                    "warning: World ID registration attempt {attempt} of {REGISTRATION_ATTEMPTS} failed, retrying in {:.1}s: {error:#}",
                    backoff.as_secs_f64()
                );
                tokio::time::sleep(backoff).await;
                attempt += 1;
            }
            Err(error) => return Err(error.context("register the stage World ID")),
        }
    }
}
