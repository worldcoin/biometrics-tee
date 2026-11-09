//! Opt-in migration of local sample packages, which are never part of this
//! repository: opened PCPs at `$PCP_SAMPLES_DIR/<version>/<signup>/pcp_pkg/`.
//!
//! Set `PCP_SAMPLES_DIR` and `PCP_SAMPLES_EXPECTATIONS` before running
//! `cargo test -p di-migration-pcp --test samples -- --ignored`.
//! Expectations are a private JSON object mapping each relative `pcp_pkg` path
//! to `migrated`, `unsupported_version`, `missing_thumbnail` or `invalid_source_iris_data`.
//! Every discovered package must have exactly one expectation.
//!
//! Failures name the version directory only, never a signup or a payload.
mod support;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::Deserialize;

use di_migration_pcp::*;
use support::{build_and_open, context, pipeline};

struct SourcePcp;

impl SourcePcp {
    fn parse(files: Files) -> Result<di_migration_pcp::SourcePcp, Error> {
        support::parse_source(files)
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Migrated,
    UnsupportedVersion,
    MissingThumbnail,
    InvalidSourceIrisData,
}

#[test]
#[ignore = "needs private samples and explicit expected outcomes"]
fn local_samples_migrate_and_pass_the_final_check() {
    let root = PathBuf::from(std::env::var_os("PCP_SAMPLES_DIR").expect("PCP_SAMPLES_DIR"));
    let expectations =
        std::env::var_os("PCP_SAMPLES_EXPECTATIONS").expect("PCP_SAMPLES_EXPECTATIONS");
    let mut expected: BTreeMap<String, Outcome> =
        serde_json::from_slice(&std::fs::read(expectations).expect("read sample expectations"))
            .expect("valid sample expectations");
    assert!(!expected.is_empty(), "empty sample inventory");
    let inventory = packages(&root);
    assert_eq!(
        inventory.len(),
        expected.len(),
        "sample inventory count differs"
    );
    for (version, package) in inventory {
        let key = package.strip_prefix(&root).unwrap().to_str().unwrap();
        let expected = expected
            .remove(key)
            .expect("sample missing from expectations");
        let outcome = match SourcePcp::parse(read_tree(&package)) {
            Ok(source) => match source.validate_iris() {
                Ok(()) => {
                    let (bio, ctx) = (pipeline(), context());
                    let new = build_and_open(&source, &bio, &ctx);
                    if let Err(error) = verify_completed_pcp(&source, &bio, &ctx, &new.files) {
                        panic!("{version}: {error}");
                    }
                    Outcome::Migrated
                }
                Err(Error::InvalidSourceIrisData) => Outcome::InvalidSourceIrisData,
                Err(error) => panic!("{version}: unexpected Iris error: {error}"),
            },
            Err(Error::UnsupportedVersion) => Outcome::UnsupportedVersion,
            Err(Error::MissingArtifact("face/thumbnail.png")) => Outcome::MissingThumbnail,
            Err(error) => panic!("{version}: {error}"),
        };
        assert_eq!(outcome, expected, "{version}: unexpected outcome");
        eprintln!("{version}: {outcome:?}");
    }
    assert!(expected.is_empty(), "expected samples were not exercised");
}

/// `(version directory, pcp_pkg directory)` for every sample package.
fn packages(root: &Path) -> Vec<(String, PathBuf)> {
    let mut packages = Vec::new();
    for version in visible_entries(root)
        .into_iter()
        .filter(|path| path.is_dir())
    {
        let name = version.file_name().unwrap().to_string_lossy().into_owned();
        for signup in visible_entries(&version) {
            let package = signup.join("pcp_pkg");
            if package.is_dir() {
                packages.push((name.clone(), package));
            }
        }
    }
    packages
}

/// Every file under `dir`, keyed by its `/`-separated path relative to `dir`.
/// A sealed `<name>.tar` next to its opened `<name>/` directory is left out:
/// the mapper takes opened members in place of their archive.
fn read_tree(dir: &Path) -> Files {
    let mut files = Files::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in visible_entries(&next) {
            if entry.is_dir() {
                pending.push(entry);
                continue;
            }
            if entry.extension().is_some_and(|ext| ext == "tar")
                && entry.with_extension("").is_dir()
            {
                continue;
            }
            let relative = entry.strip_prefix(dir).unwrap();
            let path = relative
                .components()
                .map(|part| part.as_os_str().to_str().unwrap())
                .collect::<Vec<_>>()
                .join("/");
            files.insert(path, std::fs::read(&entry).unwrap());
        }
    }
    files
}

fn visible_entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| !path.file_name().unwrap().to_string_lossy().starts_with('.'))
        .collect();
    entries.sort();
    entries
}
