fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=proto/biometric_engines.proto");
    println!("cargo:rerun-if-changed=proto/face.proto");
    prost_build::Config::new()
        .skip_debug([
            "EmbeddingResult",
            "FaceImage",
            "LightGuard",
            ".biometric_engines.face.v1.Failure",
        ])
        .enum_attribute(
            ".biometric_engines.face.v1.ImageRole",
            "#[derive(serde::Serialize)]",
        )
        .enum_attribute(
            ".biometric_engines.face.v1.LightGuardMatchingFrame",
            "#[derive(serde::Serialize)]",
        )
        .compile_protos(
            &["proto/biometric_engines.proto", "proto/face.proto"],
            &["proto"],
        )
}
