//! In-memory synthetic fixtures. Images and biometric values are invented
//! placeholders for mapping checks; builder keys are generated during tests.
// Each test crate uses a different subset of these helpers.
#![allow(dead_code)]

use std::io::Read;

use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;
use di_migration_pcp::*;
use orb_pcp_defs::v1;
use serde_json::json;

/// Synthetic multiframe image IDs in their canonical form.
pub const FRAME_A: &str = "0012a0b1c2d3e4f5a6b7c8d901000000";
pub const FRAME_B: &str = "0012a0b1c2d3e4f5a6b7c8d902000000";
/// The signup ID `context()` assigns to the new package.
pub const NEW_SIGNUP_ID: &str = "0012a0b1c2d3e4f5a6b7c8d900000000";

/// Source iris code files, in the compact sorted encoding real sources use.
pub const IRIS_CODES: &[u8] = br#"{"IRIS_version":"old","left_iris_code":"old-left-code"}"#;

pub fn iris_code_share(index: usize, with_shares_version: bool) -> Vec<u8> {
    let version = if with_shares_version {
        r#""IRIS_shares_version":"old-shares","#
    } else {
        ""
    };
    format!(r#"{{{version}"IRIS_version":"old","left_iris_code_shares":"old-share-{index}"}}"#)
        .into_bytes()
}

pub fn source_files(version: &str) -> Files {
    let timestamp = if version.starts_with("0.") {
        json!(1700000000)
    } else {
        json!("1700000000")
    };
    let info = json!({
        "signup_id": "synthetic-orb-signup", "signup_id_salt": "old-salt",
        "signup_reason": "synthetic-reason",
        "timestamp": timestamp, "timestamp_salt": "capture-salt",
        "orb_id": "original-orb", "operator_id": "original-operator",
        "left_ir_image_id": "left-id", "right_ir_image_id": "right-id",
        "thumbnail_image_id": "face-id", "id_commitment": "original-commitment",
        "left_iris_code_aggregate_image_ids": ["old-aggregate"]
    });
    let mut files: Files = [
        (
            "hashes.json",
            serde_json::to_vec(&json!({"version": version})).unwrap(),
        ),
        ("hashes.sign", b"synthetic-signature".to_vec()),
        ("info.json", serde_json::to_vec(&info).unwrap()),
        ("iris/left_ir.png", b"synthetic-left-png".to_vec()),
        ("iris/right_ir.png", b"synthetic-right-png".to_vec()),
        ("face/thumbnail.png", b"synthetic-face-png".to_vec()),
        ("iris_codes.json", IRIS_CODES.to_vec()),
        (
            "face_embeddings.json",
            b"[{\"head_pose\":{\"yaw\":1}}]".to_vec(),
        ),
    ]
    .into_iter()
    .map(|(p, b)| (p.to_owned(), b))
    .collect();
    for index in 0..3 {
        files.insert(
            format!("iris_code_shares_{index}.json"),
            iris_code_share(index, true),
        );
    }
    files
}

pub fn context() -> MigrationContext {
    MigrationContext {
        tee_software_version: "0.1.0-test".into(),
        migrated_ts: 1800000000,
        signup_id: NEW_SIGNUP_ID.parse().unwrap(),
    }
}

// Fixed, invented values for mapping and encoding checks; no inference runs.
pub fn pipeline() -> PreparedBiometrics<'static> {
    let normalized = || orb_pcp::NormalizedIrisFrame {
        image: &[1; 16],
        mask: &[2; 16],
        image_resized: &[3; 8],
        mask_resized: &[4; 8],
    };
    let model = || "1.2.3".to_owned();
    let encoding = || "test-di-encoding".to_owned();
    PreparedBiometrics {
        biometric_pipeline_version: "pipeline-1".into(),
        face_embeddings: vec![v1::FaceEmbedding {
            embedding: Some("new-face".into()),
            embedding_type: Some("test-face".into()),
            embedding_version: Some("face-2".into()),
            embedding_inference_backend: Some("test-runtime".into()),
        }],
        di_embeddings: v1::DiIrisEmbeddings {
            embedding_v1: Some(v1::DiIrisEmbeddingV1 {
                model_version: model(),
                embedding_inference_backend: "test-runtime".into(),
                embedding_version: encoding(),
                left_embedding: vec![1, 2],
                left_mirror_embedding: vec![3, 4],
                right_embedding: vec![1, 2],
                right_mirror_embedding: vec![3, 4],
                left_embedding_f32: vec![0.1, 0.2],
                left_mirror_embedding_f32: vec![0.3, 0.4],
                right_embedding_f32: vec![0.1, 0.2],
                right_mirror_embedding_f32: vec![0.3, 0.4],
            }),
        },
        di_embedding_shares: [1u32, 2, 3].map(|recipient| {
            let base = 10 * recipient;
            v1::DiIrisEmbeddingShares {
                share_v1: Some(v1::DiIrisEmbeddingShareV1 {
                    model_version: model(),
                    shares_version: "test-di-shares".into(),
                    embedding_version: encoding(),
                    left_share: vec![base + 1, base + 2],
                    left_mirror_share: vec![base + 3, base + 4],
                    right_share: vec![base + 1, base + 2],
                    right_mirror_share: vec![base + 3, base + 4],
                }),
            }
        }),
        left_normalized: normalized(),
        right_normalized: normalized(),
        extra_normalized: Default::default(),
    }
}

/// Ephemeral recipient key pairs; a distinct pair per role checks key routing.
pub struct OutputKeys {
    user: sealedbox::Keypair,
    iris: sealedbox::Keypair,
    normalized_iris: sealedbox::Keypair,
    face: sealedbox::Keypair,
    tier2: sealedbox::Keypair,
}

impl OutputKeys {
    pub fn generate() -> Self {
        let pair = || sealedbox::Keypair::generate().unwrap();
        Self {
            user: pair(),
            iris: pair(),
            normalized_iris: pair(),
            face: pair(),
            tier2: pair(),
        }
    }

    pub fn recipients(&self) -> OutputRecipients<'_> {
        fn key(pair: &sealedbox::Keypair) -> orb_pcp::BackendKey<'_> {
            orb_pcp::BackendKey {
                public_key: &pair.public_key,
                encrypted_private_key: "synthetic-envelope",
            }
        }
        OutputRecipients {
            user_public_key: &self.user.public_key,
            backend_keys: orb_pcp::BackendKeys {
                iris: key(&self.iris),
                normalized_iris: key(&self.normalized_iris),
                face: key(&self.face),
                tier2: key(&self.tier2),
            },
        }
    }
}

/// Opened package members. Inner-archive members use the logical
/// `<archive stem>/<member>` paths of `SourcePcp`.
pub struct OpenedPcp {
    pub files: Files,
    pub signed_digest: [u8; 32],
}

pub const SIGNATURE: &[u8] = b"synthetic-tee-signature";

/// Build the migration with the shared builder, then decrypt and open the result.
pub fn build_and_open(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
) -> OpenedPcp {
    let keys = OutputKeys::generate();
    let mut signed_digest = None;
    let package = with_build_request(source, biometrics, context, keys.recipients(), |request| {
        orb_pcp::build(request, &mut rand::rngs::OsRng, |digest| {
            signed_digest = Some(*digest);
            Ok::<_, std::convert::Infallible>(SIGNATURE.to_vec())
        })
    })
    .unwrap()
    .unwrap();
    OpenedPcp {
        files: open(&package, &keys),
        signed_digest: signed_digest.unwrap(),
    }
}

/// The checks `with_build_request` runs before building, without building.
pub fn check_request(
    source: &SourcePcp,
    biometrics: &PreparedBiometrics<'_>,
    context: &MigrationContext,
) -> Result<(), Error> {
    with_build_request(
        source,
        biometrics,
        context,
        OutputKeys::generate().recipients(),
        |_| (),
    )
}

/// Decrypt a package: everything is in tier 0, tiers 1 and 2 are empty archives.
pub fn open(package: &orb_pcp::Package, keys: &OutputKeys) -> Files {
    let tier = |bytes: &[u8]| {
        let gzip = unseal(bytes, &keys.user);
        let mut tar = Vec::new();
        flate2::read::GzDecoder::new(gzip.as_slice())
            .read_to_end(&mut tar)
            .unwrap();
        untar(&tar)
    };
    assert!(tier(&package.tier1).is_empty() && tier(&package.tier2).is_empty());
    let mut files = Files::new();
    for (name, bytes) in tier(&package.tier0) {
        let Some(stem) = name.strip_suffix(".tar") else {
            assert!(files.insert(name, bytes).is_none());
            continue;
        };
        let pair = match stem {
            "iris" => &keys.iris,
            "normalized_iris" => &keys.normalized_iris,
            "face" | "fraud" => &keys.face,
            "face_ir_and_thermal" => &keys.tier2,
            _ => panic!("unexpected inner archive {name}"),
        };
        for (member, bytes) in untar(&unseal(&bytes, pair)) {
            assert!(files.insert(format!("{stem}/{member}"), bytes).is_none());
        }
    }
    files
}

fn unseal(ciphertext: &[u8], pair: &sealedbox::Keypair) -> Vec<u8> {
    let mut plaintext = vec![0; ciphertext.len() - sealedbox::OVERHEAD_LENGTH];
    sealedbox::decrypt(ciphertext, pair, &mut plaintext).unwrap();
    plaintext
}

fn untar(bytes: &[u8]) -> Files {
    let mut files = Files::new();
    for entry in tar::Archive::new(bytes).entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_str().unwrap().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        assert!(files.insert(name, bytes).is_none(), "duplicate member");
    }
    files
}
