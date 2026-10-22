//! Synthetic source corruption tests. Manifests are finalized before tampering.
#[path = "support/profiles.rs"]
mod profiles;
mod support;

use di_migration_pcp::{Error, Files};
use serde_json::{Value, json};

use profiles::version_profile as opened_version_profile;
use support::{refresh_source_manifest, source_files as opened_source_files};

struct SourcePcp;

impl SourcePcp {
    fn parse(files: Files) -> Result<di_migration_pcp::SourcePcp, Error> {
        support::parse_encrypted_source(files)
    }
}

fn source_files(version: &str) -> Files {
    support::encrypt_source(opened_source_files(version))
}

fn version_profile(version: &str, optional: bool) -> Files {
    support::encrypt_source(opened_version_profile(version, optional))
}

fn edit_json(files: &mut Files, name: &str, edit: impl FnOnce(&mut Value)) {
    let mut value = serde_json::from_slice(&files[name]).unwrap();
    edit(&mut value);
    files.insert(name.into(), serde_json::to_vec(&value).unwrap());
}

fn parse_fails(files: Files, reason: &'static str) {
    assert_eq!(
        SourcePcp::parse(files).err(),
        Some(Error::SourceIntegrity(reason))
    );
}

#[test]
fn fixed_hash_vectors_cover_bytes_salted_text_and_integer_precision() {
    // SHA-256("abc"), independent of the fixture manifest generator.
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    for (timestamp, hash) in [
        (
            9007199254740993u64,
            "355f0dd233ece1a52d0889a41530c4b9c4354642b2e227a4ba6942d847309786",
        ),
        (
            u64::MAX,
            "1c491553a2e2f2db4c30b975df85636ab9e048e3543cba0de47016a95b5b985c",
        ),
    ] {
        for timestamp_value in [json!(timestamp), json!(timestamp.to_string())] {
            let info = json!({
                "signup_id": "a", "signup_id_salt": "bc",
                "orb_id": "ab", "orb_id_salt": "c",
                "timestamp": timestamp_value, "timestamp_salt": "salt"
            });
            let manifest = json!({
                "version": 0.3, "signup_id": ABC, "orb_id": ABC, "timestamp": hash,
                "left_ir.png": ABC, "right_ir.png": ABC, "thumbnail.png": ABC
            });
            let files = [
                ("info.json", serde_json::to_vec(&info).unwrap()),
                ("hashes.json", serde_json::to_vec(&manifest).unwrap()),
                ("hashes.sign", b"synthetic-signature".to_vec()),
                ("iris/left_ir.png", b"abc".to_vec()),
                ("iris/right_ir.png", b"abc".to_vec()),
                ("face/thumbnail.png", b"abc".to_vec()),
            ]
            .into_iter()
            .map(|(name, bytes)| (name.into(), bytes))
            .collect();
            let source = SourcePcp::parse(support::encrypt_source(files)).unwrap();
            assert_eq!(
                source.info().timestamp.as_deref(),
                Some(timestamp.to_string().as_str())
            );
        }
    }
}

#[test]
fn every_source_artifact_is_checked_including_replaced_outputs_and_keys() {
    let original = opened_version_profile("2.8", true);
    for name in original
        .keys()
        .filter(|name| !matches!(name.as_str(), "info.json" | "hashes.json" | "hashes.sign"))
    {
        let mut files = original.clone();
        files.get_mut(name).unwrap().push(b' ');
        if name == "backend_keys.json" {
            // The encryption helper replaces the synthetic backend key envelope.
            files = support::encrypt_source(original.clone());
            files.get_mut(name).unwrap().push(b' ');
        } else {
            files = support::encrypt_source(files);
        }
        parse_fails(files, "manifest_hash_mismatch");
    }
}

#[test]
fn every_present_digest_is_required() {
    let original = version_profile("2.8", true);
    let manifest: Value = serde_json::from_slice(&original["hashes.json"]).unwrap();
    for name in manifest
        .as_object()
        .unwrap()
        .keys()
        .filter(|name| *name != "version")
    {
        let mut files = original.clone();
        edit_json(&mut files, "hashes.json", |manifest| {
            manifest.as_object_mut().unwrap().remove(name);
        });
        parse_fails(files, "manifest_entry_missing");
    }
}

#[test]
fn optional_files_can_only_be_absent_when_unlisted() {
    for name in [
        "iris_codes.json",
        "iris_code_shares_0.json",
        "di_iris_embeddings.pb",
    ] {
        let mut files = version_profile("2.8", true);
        files.remove(name);
        parse_fails(files.clone(), "manifest_entry_unexpected");
        edit_json(&mut files, "hashes.json", |manifest| {
            manifest.as_object_mut().unwrap().remove(name);
        });
        SourcePcp::parse(files).unwrap();
    }
}

#[test]
fn unlisted_files_unknown_entries_and_unresolved_metadata_fail() {
    let mut files = source_files("2.8");
    files.insert("normalized_iris/left_normalized_image.bin".into(), vec![1]);
    parse_fails(files, "manifest_entry_missing");
    for name in ["unknown.png", "info.json", "hashes.sign", "latitude"] {
        let mut files = source_files("2.8");
        edit_json(&mut files, "info.json", |info| {
            info["latitude"] = json!(1.5);
            info["latitude_salt"] = json!("synthetic-salt");
        });
        edit_json(&mut files, "hashes.json", |manifest| {
            manifest[name] = json!("00".repeat(32))
        });
        parse_fails(files, "manifest_entry_unexpected");
    }
}

#[test]
fn all_protected_metadata_and_salts_are_checked() {
    let original = version_profile("2.8", true);
    let info: Value = serde_json::from_slice(&original["info.json"]).unwrap();
    for salt_name in info
        .as_object()
        .unwrap()
        .keys()
        .filter(|name| name.ends_with("_salt"))
    {
        for name in [salt_name.as_str(), salt_name.strip_suffix("_salt").unwrap()] {
            let mut files = original.clone();
            edit_json(&mut files, "info.json", |info| {
                info[name] = json!("changed")
            });
            parse_fails(files, "manifest_hash_mismatch");
        }
    }
}

#[test]
fn metadata_requires_valid_value_and_salt_pairs() {
    for salt in [
        Value::Null,
        json!(""),
        json!(1),
        json!([]),
        json!({}),
        json!(true),
    ] {
        let mut files = source_files("2.8");
        edit_json(&mut files, "info.json", |info| info["orb_id_salt"] = salt);
        parse_fails(files, "metadata_salt_invalid");
    }
    let mut files = source_files("2.8");
    edit_json(&mut files, "info.json", |info| {
        info.as_object_mut().unwrap().remove("orb_id_salt");
    });
    parse_fails(files, "metadata_salt_invalid");
    for value in [json!(1), json!([]), json!({}), json!(true)] {
        let mut files = source_files("2.8");
        edit_json(&mut files, "info.json", |info| info["orb_id"] = value);
        parse_fails(files, "metadata_value_invalid");
    }
    for missing in [false, true] {
        let mut files = source_files("2.8");
        edit_json(&mut files, "info.json", |info| {
            if missing {
                info.as_object_mut().unwrap().remove("operator_id");
            } else {
                info["operator_id"] = Value::Null;
            }
        });
        parse_fails(files, "metadata_salt_without_value");
    }
}

#[test]
fn null_and_missing_optional_metadata_have_no_digest() {
    let mut files = source_files("2.8");
    edit_json(&mut files, "info.json", |info| {
        info["operator_id"] = Value::Null;
        info["operator_id_salt"] = Value::Null;
        info.as_object_mut().unwrap().remove("timestamp");
        info.as_object_mut().unwrap().remove("timestamp_salt");
    });
    parse_fails(files.clone(), "manifest_entry_unexpected");
    edit_json(&mut files, "hashes.json", |manifest| {
        manifest.as_object_mut().unwrap().remove("operator_id");
        manifest.as_object_mut().unwrap().remove("timestamp");
    });
    SourcePcp::parse(files).unwrap();
}

#[test]
fn duplicate_member_basenames_fail_even_with_identical_bytes() {
    let mut files = source_files("2.8");
    files.insert("iris/duplicate.png".into(), b"same".to_vec());
    refresh_source_manifest(&mut files);
    files.insert("face/duplicate.png".into(), b"same".to_vec());
    parse_fails(files, "manifest_name_duplicate");
}

#[test]
fn duplicate_json_keys_fail_including_escaped_and_ignored_names() {
    for (artifact, duplicate) in [
        ("hashes.json", r#""version":"2.8","version":"2.8""#),
        ("hashes.json", r#""left_ir.png":"a","left_ir.png":"b""#),
        ("info.json", r#""orb_id":"first","orb_\u0069d":"second""#),
        ("info.json", r#""ignored":null,"ignored":null"#),
    ] {
        let mut files = source_files("2.8");
        files.insert(artifact.into(), format!("{{{duplicate}}}").into_bytes());
        assert!(
            matches!(SourcePcp::parse(files).err(), Some(Error::InvalidJson { artifact: actual, .. }) if actual == artifact)
        );
    }
}

#[test]
fn invalid_digests_and_manifest_shapes_fail_without_payloads() {
    for digest in [
        json!("sensitive-digest"),
        json!("g".repeat(64)),
        json!("0".repeat(63)),
        json!("0".repeat(65)),
        Value::Null,
        json!(123),
        json!([]),
        json!({}),
    ] {
        let mut files = source_files("2.8");
        edit_json(&mut files, "hashes.json", |manifest| {
            manifest["left_ir.png"] = digest
        });
        parse_fails(files, "manifest_digest_invalid");
    }
    for bytes in [
        b"[]".as_slice(),
        b"null",
        b"{} trailing",
        br#"{"version":"2.8""#,
    ] {
        let mut files = source_files("2.8");
        files.insert("hashes.json".into(), bytes.to_vec());
        assert!(matches!(
            SourcePcp::parse(files).err(),
            Some(Error::InvalidJson {
                artifact: "hashes.json",
                ..
            })
        ));
    }
    for version in [Value::Null, json!(true), json!([]), json!({})] {
        let mut files = source_files("2.8");
        edit_json(&mut files, "hashes.json", |manifest| {
            manifest["version"] = version
        });
        parse_fails(files, "manifest_version_invalid");
    }
    let mut files = source_files("2.8");
    files.insert("hashes.json".into(), b"{}".to_vec());
    parse_fails(files, "manifest_version_invalid");
}

#[test]
fn historical_json_formatting_and_hex_case_are_accepted() {
    let mut files = source_files("0.3");
    edit_json(&mut files, "hashes.json", |manifest| {
        for (name, value) in manifest.as_object_mut().unwrap() {
            if name != "version" {
                *value = json!(value.as_str().unwrap().to_uppercase());
            }
        }
    });
    for artifact in ["info.json", "hashes.json"] {
        let object: Value = serde_json::from_slice(&files[artifact]).unwrap();
        let entries = object
            .as_object()
            .unwrap()
            .iter()
            .rev()
            .map(|(name, value)| format!("{}: {}", serde_json::to_string(name).unwrap(), value))
            .collect::<Vec<_>>()
            .join(",\n");
        files.insert(artifact.into(), format!("{{\n{entries}\n}}\n").into_bytes());
    }
    SourcePcp::parse(files).unwrap();
}

#[test]
fn oversized_manifest_and_metadata_are_rejected() {
    for artifact in ["hashes.json", "info.json"] {
        let mut files = source_files("2.8");
        files.insert(artifact.into(), vec![b' '; 1024 * 1024 + 1]);
        assert_eq!(SourcePcp::parse(files).err(), Some(Error::SizeLimit));
    }
}
