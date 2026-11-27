//! Repacks the reference PCP for a freshly enrolled stage user.
//!
//! Copied from orb-tools' `crates/e2e/tests/integration/tee_migration_test_utils.rs`
//! (b415d7e), where it is test-only. Keep the two in sync when the PCP layout changes.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use anyhow::{Context, Result};
use flate2::Compression;
use flate2::write::GzEncoder;
use k256::SecretKey;
use k256::ecdsa::SigningKey;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use signup_flow::selfcustody::pcp::ORB_PRIVATE_KEY_PEM;
use tar::{Archive, Builder};

const IRIS_FILES: [&str; 4] = [
    "iris_codes.json",
    "iris_code_shares_0.json",
    "iris_code_shares_1.json",
    "iris_code_shares_2.json",
];

pub fn extract_iris_share_files(pcp: &[u8]) -> Result<[Vec<u8>; 3]> {
    let mut archive = Archive::new(flate2::read::GzDecoder::new(pcp));
    let mut files = BTreeMap::new();
    for entry in archive.entries().context("read generated PCP archive")? {
        let mut entry = entry.context("read generated PCP archive entry")?;
        let name = entry
            .path()
            .context("read generated PCP archive entry path")?
            .to_string_lossy()
            .into_owned();
        if IRIS_FILES[1..].contains(&name.as_str()) {
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents)?;
            files.insert(name, contents);
        }
    }

    Ok([
        files
            .remove("iris_code_shares_0.json")
            .context("generated PCP is missing iris_code_shares_0.json")?,
        files
            .remove("iris_code_shares_1.json")
            .context("generated PCP is missing iris_code_shares_1.json")?,
        files
            .remove("iris_code_shares_2.json")
            .context("generated PCP is missing iris_code_shares_2.json")?,
    ])
}

pub fn repack_reference_pcp(
    mut files: BTreeMap<String, Vec<u8>>,
    signup_id: &str,
    id_commitment: &str,
    iris_share_files: &[Vec<u8>; 3],
) -> Result<Vec<u8>> {
    let mut hashes: Map<String, Value> = serde_json::from_slice(
        files
            .get("hashes.json")
            .context("reference PCP is missing hashes.json")?,
    )
    .context("parse reference hashes.json")?;
    let mut info: Map<String, Value> = serde_json::from_slice(
        files
            .get("info.json")
            .context("reference PCP is missing info.json")?,
    )
    .context("parse reference info.json")?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs()
        .to_string();

    if info.contains_key("id_commitment") {
        let salt = info
            .get("id_commitment_salt")
            .and_then(Value::as_str)
            .filter(|salt| !salt.is_empty());
        hashes.insert(
            "id_commitment".into(),
            Value::String(hash_value(id_commitment, salt)),
        );
        info.insert("id_commitment".into(), Value::String(id_commitment.into()));
    }

    for (name, value) in [
        ("orb_id", "simulatedorb"),
        ("signup_id", signup_id),
        ("timestamp", timestamp.as_str()),
    ] {
        let salt_name = format!("{name}_salt");
        let salt = info
            .get(&salt_name)
            .and_then(Value::as_str)
            .filter(|salt| !salt.is_empty());
        hashes.insert(name.into(), Value::String(hash_value(value, salt)));
        *info
            .get_mut(name)
            .with_context(|| format!("reference info.json is missing {name}"))? =
            Value::String(value.into());
    }
    files.insert("info.json".into(), serde_json::to_vec(&info)?);

    for (name, enrolled_bytes) in IRIS_FILES[1..].iter().zip(iris_share_files) {
        let reference_bytes = files
            .get_mut(*name)
            .with_context(|| format!("reference PCP is missing {name}"))?;
        let mut reference: Map<String, Value> = serde_json::from_slice(reference_bytes)
            .with_context(|| format!("parse reference {name}"))?;
        let enrolled: Map<String, Value> = serde_json::from_slice(enrolled_bytes)
            .with_context(|| format!("parse enrolled {name}"))?;
        for field in [
            "left_iris_code_shares",
            "left_mask_code_shares",
            "right_iris_code_shares",
            "right_mask_code_shares",
        ] {
            let payload = enrolled
                .get(field)
                .and_then(Value::as_str)
                .filter(|payload| !payload.is_empty())
                .with_context(|| format!("enrolled {name} is missing {field}"))?;
            reference.insert(field.into(), Value::String(payload.into()));
        }
        *reference_bytes = serde_json::to_vec(&reference)?;
        *hashes
            .get_mut(*name)
            .with_context(|| format!("reference manifest is missing {name}"))? =
            Value::String(hex::encode(Sha256::digest(reference_bytes)));
    }

    let hashes_json = serde_json::to_vec(&hashes)?;
    let key = SigningKey::from(
        SecretKey::from_sec1_pem(ORB_PRIVATE_KEY_PEM).context("parse Orb signing key")?,
    );
    let signature: k256::ecdsa::Signature = key
        .sign_prehash(&Sha256::digest(&hashes_json))
        .context("sign updated hashes.json")?;
    *files
        .get_mut("hashes.sign")
        .context("reference PCP is missing hashes.sign")? = signature.to_der().as_bytes().to_vec();
    files.insert("hashes.json".into(), hashes_json);

    let mut archive = Builder::new(Vec::new());
    for (name, bytes) in &files {
        add_tar_file(&mut archive, name, bytes)?;
    }
    let raw_tar = archive
        .into_inner()
        .context("finish repacked reference PCP archive")?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&raw_tar)?;
    encoder.finish().context("gzip updated reference PCP")
}

fn hash_value(value: &str, salt: Option<&str>) -> String {
    let mut input = value.to_owned();
    if let Some(salt) = salt {
        input.push_str(salt);
    }
    hex::encode(Sha256::digest(input.as_bytes()))
}

fn add_tar_file(archive: &mut Builder<Vec<u8>>, name: &str, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_path(name)?;
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    archive.append(&header, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repack_replaces_share_payloads_but_preserves_reference_versions() -> Result<()> {
        let mut files = BTreeMap::new();
        let mut hashes = Map::new();
        let reference_iris: [Vec<u8>; 4] = std::array::from_fn(|index| {
            format!(r#"{{"IRIS_version":"3.4.0","IRIS_shares_version":"3.0","record":{index}}}"#)
                .into_bytes()
        });
        for (name, bytes) in IRIS_FILES.iter().zip(&reference_iris) {
            files.insert((*name).to_owned(), bytes.clone());
            hashes.insert(
                (*name).to_owned(),
                Value::String(hex::encode(Sha256::digest(bytes))),
            );
        }
        files.insert("hashes.json".into(), serde_json::to_vec(&hashes)?);
        files.insert("hashes.sign".into(), Vec::new());
        files.insert(
            "info.json".into(),
            br#"{"orb_id":"old-orb","signup_id":"old-signup","timestamp":"0"}"#.to_vec(),
        );
        let enrolled_shares = std::array::from_fn(|index| {
            serde_json::to_vec(&serde_json::json!({
                "IRIS_version": "2.0",
                "IRIS_shares_version": "new-version",
                "left_iris_code_shares": format!("left-code-{index}"),
                "left_mask_code_shares": format!("left-mask-{index}"),
                "right_iris_code_shares": format!("right-code-{index}"),
                "right_mask_code_shares": format!("right-mask-{index}"),
            }))
            .unwrap()
        });
        let package = repack_reference_pcp(files, "signup", "commitment", &enrolled_shares)?;
        let replaced_shares = extract_iris_share_files(&package)?;
        for (index, bytes) in replaced_shares.iter().enumerate() {
            let replaced: Map<String, Value> = serde_json::from_slice(bytes)?;
            let enrolled: Map<String, Value> = serde_json::from_slice(&enrolled_shares[index])?;
            assert_eq!(replaced["IRIS_version"], "3.4.0");
            assert_eq!(replaced["IRIS_shares_version"], "3.0");
            for field in [
                "left_iris_code_shares",
                "left_mask_code_shares",
                "right_iris_code_shares",
                "right_mask_code_shares",
            ] {
                assert_eq!(replaced[field], enrolled[field]);
            }
        }

        let mut archive = Archive::new(flate2::read::GzDecoder::new(package.as_slice()));
        let mut saw_codes = false;
        let mut saw_manifest = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let name = entry.path()?.to_string_lossy().into_owned();
            if name == "iris_codes.json" {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                assert_eq!(bytes, reference_iris[0]);
                saw_codes = true;
            } else if name == "hashes.json" {
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                let manifest: Map<String, Value> = serde_json::from_slice(&bytes)?;
                assert_eq!(manifest["iris_codes.json"], hashes["iris_codes.json"]);
                for (name, bytes) in IRIS_FILES[1..].iter().zip(&replaced_shares) {
                    assert_eq!(manifest[*name], hex::encode(Sha256::digest(bytes)));
                }
                saw_manifest = true;
            }
        }
        assert!(saw_codes, "repacked PCP is missing iris_codes.json");
        assert!(saw_manifest, "repacked PCP is missing hashes.json");
        Ok(())
    }
}
