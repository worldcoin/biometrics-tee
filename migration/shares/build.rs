use std::{env, fs, path::PathBuf};

fn main() {
    let lock_path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("../../Cargo.lock");
    let lock = fs::read_to_string(&lock_path).expect("workspace Cargo.lock should be readable");
    let package = lock
        .split("[[package]]")
        .find(|package| {
            package
                .lines()
                .any(|line| line.trim() == r#"name = "ampc-secret-sharing""#)
        })
        .expect("ampc-secret-sharing should be present in Cargo.lock");
    let source = package
        .lines()
        .find_map(|line| line.trim().strip_prefix(r#"source = ""#))
        .and_then(|line| line.strip_suffix('"'))
        .expect("ampc-secret-sharing should have a locked source");
    let revision = source
        .rsplit_once('#')
        .map(|(_, revision)| revision)
        .filter(|revision| {
            revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .expect("ampc-secret-sharing source should contain a full Git revision");

    println!("cargo:rustc-env=AMPC_SECRET_SHARING_VERSION={revision}");
    println!("cargo:rerun-if-changed={}", lock_path.display());
}
