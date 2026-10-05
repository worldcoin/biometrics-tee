//! In-memory synthetic fixtures. Images and biometric values are invented
//! placeholders for mapping checks; builder keys are generated during tests.
// Each test crate uses a different subset of these helpers.
#![allow(dead_code)]

use std::io::Read;

use alkali::asymmetric::seal::curve25519xsalsa20poly1305 as sealedbox;
use di_migration_pcp::*;
use serde_json::json;

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
    [
        (
            "hashes.json",
            serde_json::to_vec(&json!({"version": version})).unwrap(),
        ),
        ("hashes.sign", b"synthetic-signature".to_vec()),
        ("info.json", serde_json::to_vec(&info).unwrap()),
        ("iris/left_ir.png", b"synthetic-left-png".to_vec()),
        ("iris/right_ir.png", b"synthetic-right-png".to_vec()),
        ("face/thumbnail.png", b"synthetic-face-png".to_vec()),
        (
            "iris_codes.json",
            b"{ \"IRIS_version\": \"old\", \"left_iris_code\": null }\n".to_vec(),
        ),
        (
            "face_embeddings.json",
            b"[{\"head_pose\":{\"yaw\":1}}]".to_vec(),
        ),
    ]
    .into_iter()
    .map(|(p, b)| (p.to_owned(), b))
    .collect()
}

pub fn context() -> MigrationContext {
    MigrationContext {
        tee_version: "0.1.0-test".into(),
        migrated_ts: 1800000000,
    }
}

// Fixed, invented values for mapping and encoding checks; no inference runs.
pub fn pipeline() -> PreparedBiometrics<'static> {
    let iris_eye = || orb_pcp::DaugmanEyeData {
        iris_code: Some("new-code"),
        mask_code: Some("new-mask"),
        iris_code_shares: ["code-0", "code-1", "code-2"],
        mask_code_shares: ["mask-0", "mask-1", "mask-2"],
    };
    let di_eye = || orb_pcp::DiEyeData {
        embedding: &[1, 2],
        mirror_embedding: &[3, 4],
        embedding_f32: &[0.1, 0.2],
        mirror_embedding_f32: &[0.3, 0.4],
        embedding_shares: [&[11, 12], &[21, 22], &[31, 32]],
        mirror_embedding_shares: [&[13, 14], &[23, 24], &[33, 34]],
    };
    let normalized = || orb_pcp::NormalizedIrisFrame {
        image: &[1; 16],
        mask: &[2; 16],
        image_resized: &[3; 8],
        mask_resized: &[4; 8],
    };
    PreparedBiometrics {
        biometric_pipeline_version: "pipeline-1".into(),
        face_embeddings: vec![orb_pcp::FaceEmbedding {
            embedding: "new-face",
            embedding_type: "test-face",
            embedding_version: "face-2",
            embedding_inference_backend: "test-runtime",
        }],
        daugman: orb_pcp::DaugmanData {
            iris_version: Some("iris-1"),
            shares_version: "test-iris-shares",
            left: iris_eye(),
            right: iris_eye(),
        },
        di: orb_pcp::DiData {
            model_version: "1.2.3",
            inference_backend: "test-runtime",
            embedding_version: "test-di-encoding",
            shares_version: "test-di-shares",
            left: Some(di_eye()),
            right: Some(di_eye()),
        },
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
/// `<archive stem>/<member>` paths of `SourcePcp`; `legacy/` members are keyed
/// by basename in `legacy`.
pub struct OpenedPcp {
    pub files: Files,
    pub legacy: Files,
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
    let (files, legacy) = open(&package, &keys);
    OpenedPcp {
        files,
        legacy,
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

/// Decrypt a v2-envelope package: everything is in tier 0, tiers 1 and 2 are
/// empty archives. Returns opened members and `legacy/` members.
pub fn open(package: &orb_pcp::Package, keys: &OutputKeys) -> (Files, Files) {
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
    let mut legacy = Files::new();
    for (name, bytes) in tier(&package.tier0) {
        if let Some(name) = name.strip_prefix("legacy/") {
            assert!(legacy.insert(name.to_owned(), bytes).is_none());
            continue;
        }
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
    (files, legacy)
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
