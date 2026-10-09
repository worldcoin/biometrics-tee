//! Opt-in migration of local sample packages, which are never part of this
//! repository: opened PCPs at `$PCP_SAMPLES_DIR/<version>/<signup>/pcp_pkg/`.
//!
//! `PCP_SAMPLES_DIR=<dir> cargo test -p di-migration-pcp --test samples -- --ignored`
//!
//! Failures name the version directory only, never a signup or a payload.
mod support;

use std::path::{Path, PathBuf};

use di_migration_pcp::*;
use support::{build_and_open, context, pipeline};

#[test]
#[ignore = "needs local sample packages in PCP_SAMPLES_DIR"]
fn local_samples_migrate_and_pass_the_final_check() {
    let root = PathBuf::from(std::env::var_os("PCP_SAMPLES_DIR").expect("PCP_SAMPLES_DIR"));
    let mut migrated = 0;
    for (version, package) in packages(&root) {
        match SourcePcp::parse(read_tree(&package)) {
            Ok(source) => {
                let (bio, ctx) = (pipeline(), context());
                let new = build_and_open(&source, &bio, &ctx);
                if let Err(error) = verify_completed_pcp(&source, &bio, &ctx, &new.files) {
                    panic!("{version}: {error}");
                }
                migrated += 1;
                eprintln!("{version}: migrated");
            }
            // Outside the supported versions, or without the face thumbnail
            // the pipeline reads.
            Err(
                error @ (Error::UnsupportedVersion | Error::MissingArtifact("face/thumbnail.png")),
            ) => {
                eprintln!("{version}: not migratable: {error}");
            }
            Err(error) => panic!("{version}: {error}"),
        }
    }
    assert!(migrated > 0, "no sample packages migrated");
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
