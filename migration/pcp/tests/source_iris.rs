//! Source Iris eligibility is independent of file presence and fresh DI validation.
mod support;

use di_migration_pcp::{BuildError, Error, build, validate_build_inputs, verify_completed_pcp};
use serde_json::Value;
use support::{
    OutputKeys, build_and_open, context, parse_source, pipeline, refresh_source_manifest,
    source_files,
};

fn edit_record(files: &mut di_migration_pcp::Files, name: &str, edit: impl FnOnce(&mut Value)) {
    let mut value: Value = serde_json::from_slice(&files[name]).unwrap();
    edit(&mut value);
    files.insert(name.to_owned(), serde_json::to_vec(&value).unwrap());
    refresh_source_manifest(files);
}

fn assert_rejected(files: di_migration_pcp::Files) {
    let source = parse_source(files).unwrap();
    assert_eq!(source.validate_iris(), Err(Error::InvalidSourceIrisData));
    let keys = OutputKeys::generate();
    let (bio, ctx) = (pipeline(), context());
    assert_eq!(
        validate_build_inputs(&source, &bio, &ctx, &keys.user.public_key),
        Err(Error::InvalidSourceIrisData),
    );
    let mut signed = false;
    let result = build(&source, &bio, &ctx, keys.recipients(), |_| {
        signed = true;
        Ok::<_, std::convert::Infallible>(vec![])
    });
    assert!(matches!(
        result,
        Err(BuildError::Mapping(Error::InvalidSourceIrisData))
    ));
    assert!(!signed);
}

#[test]
fn missing_payload_fields_have_a_dedicated_error() {
    for field in [
        "left_iris_code",
        "right_iris_code",
        "left_mask_code",
        "right_mask_code",
    ] {
        let mut files = source_files("2.1");
        edit_record(&mut files, "iris_codes.json", |value| {
            value.as_object_mut().unwrap().remove(field);
        });
        assert_rejected(files);
    }
    for index in 0..3 {
        for field in [
            "left_iris_code_shares",
            "right_iris_code_shares",
            "left_mask_code_shares",
            "right_mask_code_shares",
        ] {
            let mut files = source_files("2.1");
            edit_record(
                &mut files,
                &format!("iris_code_shares_{index}.json"),
                |value| {
                    value.as_object_mut().unwrap().remove(field);
                },
            );
            assert_rejected(files);
        }
        let mut files = source_files("2.1");
        edit_record(
            &mut files,
            &format!("iris_code_shares_{index}.json"),
            |value| {
                value["IRIS_version"] = "different".into();
            },
        );
        assert_rejected(files);
    }
}

#[test]
fn empty_present_records_are_rejected() {
    for name in ["iris_codes.json", "iris_code_shares_0.json"] {
        let mut files = source_files("2.1");
        edit_record(&mut files, name, |value| *value = serde_json::json!({}));
        assert_rejected(files);
    }
}

#[test]
fn optional_files_and_versions_are_preserved_for_every_presence_combination() {
    let names = [
        "iris_codes.json",
        "iris_code_shares_0.json",
        "iris_code_shares_1.json",
        "iris_code_shares_2.json",
    ];
    for present in 0u8..16 {
        let mut files = source_files("2.1");
        for (index, name) in names.iter().enumerate() {
            if present & (1 << index) == 0 {
                files.remove(*name);
            } else {
                edit_record(&mut files, name, |value| {
                    value.as_object_mut().unwrap().remove("IRIS_version");
                    value.as_object_mut().unwrap().remove("IRIS_shares_version");
                });
            }
        }
        refresh_source_manifest(&mut files);
        let source = parse_source(files.clone()).unwrap();
        source.validate_iris().unwrap();
        let (bio, ctx) = (pipeline(), context());
        let result = build_and_open(&source, &bio, &ctx);
        verify_completed_pcp(&source, &bio, &ctx, &result.files).unwrap();
        for name in names {
            assert_eq!(
                files.get(name),
                result.files.get(name),
                "presence mask {present}"
            );
        }
    }
}
