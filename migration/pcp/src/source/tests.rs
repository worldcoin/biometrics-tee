use base64::engine::general_purpose::STANDARD;
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::*;

struct TestDecryptor;

#[async_trait::async_trait]
impl BackendKeyDecryptor for TestDecryptor {
    async fn decrypt_backend_key(
        &self,
        encrypted_private_key: &[u8],
        _archive_role: &'static str,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        Ok(Zeroizing::new(encrypted_private_key.to_vec()))
    }
}

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut archive = tar::Builder::new(Vec::new());
    for (path, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive.append(&header, *bytes).unwrap();
    }
    archive.into_inner().unwrap()
}

fn encrypt_archive(entries: &[(&str, &[u8])], pair: &sealedbox::Keypair) -> Vec<u8> {
    let plaintext = tar(entries);
    let mut ciphertext = vec![0; plaintext.len() + sealedbox::OVERHEAD_LENGTH];
    sealedbox::encrypt(&plaintext, &pair.public_key, &mut ciphertext).unwrap();
    ciphertext
}

fn encrypted_source() -> (Files, sealedbox::Keypair) {
    let iris = sealedbox::Keypair::generate().unwrap();
    let face = sealedbox::Keypair::generate().unwrap();
    let backend_keys = v1::BackendKeys {
        iris: Some(v1::BackendKey {
            public_key: Some(STANDARD.encode(iris.public_key.as_ref())),
            encrypted_private_key: Some(STANDARD.encode(iris.private_key.as_ref())),
        }),
        face: Some(v1::BackendKey {
            public_key: Some(STANDARD.encode(face.public_key.as_ref())),
            encrypted_private_key: Some(STANDARD.encode(face.private_key.as_ref())),
        }),
        ..Default::default()
    };
    let mut files = Files::new();
    files.insert(
        "info.json".into(),
        serde_json::to_vec(&json!({
            "signup_id": "signup",
            "signup_id_salt": "signup-salt",
            "orb_id": "orb",
            "orb_id_salt": "orb-salt"
        }))
        .unwrap(),
    );
    files.insert(
        "backend_keys.json".into(),
        serde_json::to_vec(&backend_keys).unwrap(),
    );
    files.insert(
        "iris.tar".into(),
        encrypt_archive(
            &[("left_ir.png", b"left"), ("right_ir.png", b"right")],
            &iris,
        ),
    );
    files.insert(
        "face.tar".into(),
        encrypt_archive(&[("thumbnail.png", b"face")], &face),
    );
    files.insert("hashes.sign".into(), b"signature".to_vec());

    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    let manifest = json!({
        "version": "2.8",
        "signup_id": digest(b"signupsignup-salt"),
        "orb_id": digest(b"orborb-salt"),
        "backend_keys.json": digest(&files["backend_keys.json"]),
        "left_ir.png": digest(b"left"),
        "right_ir.png": digest(b"right"),
        "thumbnail.png": digest(b"face"),
    });
    files.insert("hashes.json".into(), serde_json::to_vec(&manifest).unwrap());
    (files, iris)
}

#[tokio::test]
async fn decrypts_archives_and_verifies_their_plaintext_member_hashes() {
    let (files, _) = encrypted_source();
    let source = SourcePcp::parse(files, &TestDecryptor).await.unwrap();
    let inputs = source.pipeline_inputs();
    assert_eq!(inputs.left_ir_png, b"left");
    assert_eq!(inputs.right_ir_png, b"right");
    assert_eq!(inputs.thumbnail_png, b"face");
}

#[tokio::test]
async fn decrypted_members_must_match_the_original_manifest() {
    let (mut files, iris) = encrypted_source();
    files.insert(
        "iris.tar".into(),
        encrypt_archive(
            &[("left_ir.png", b"changed"), ("right_ir.png", b"right")],
            &iris,
        ),
    );

    assert_eq!(
        SourcePcp::parse(files, &TestDecryptor).await.err(),
        Some(Error::SourceIntegrity("manifest_hash_mismatch")),
    );
}

struct UnexpectedDecryptor;

#[async_trait::async_trait]
impl BackendKeyDecryptor for UnexpectedDecryptor {
    async fn decrypt_backend_key(
        &self,
        _encrypted_private_key: &[u8],
        _archive_role: &'static str,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        panic!("backend key integrity must be checked before calling KMS");
    }
}

#[tokio::test]
async fn backend_key_envelope_is_verified_before_decryption() {
    let (mut files, _) = encrypted_source();
    files.get_mut("backend_keys.json").unwrap().push(b' ');

    assert_eq!(
        SourcePcp::parse(files, &UnexpectedDecryptor).await.err(),
        Some(Error::SourceIntegrity("manifest_hash_mismatch")),
    );
}
