fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=proto/biometric_engines.proto");
    println!("cargo:rerun-if-changed=proto/migration.proto");
    prost_build::Config::new()
        .skip_debug([
            "MigrationRequest",
            "FaceEmbedding",
            "EyeResult",
            ".biometric_engines.migration.v1.Failure",
        ])
        .boxed(".biometric_engines.v1.Response.outcome.migration")
        .compile_protos(
            &["proto/biometric_engines.proto", "proto/migration.proto"],
            &["proto"],
        )
}
