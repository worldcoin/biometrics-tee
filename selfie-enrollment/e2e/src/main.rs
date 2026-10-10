//! Native end-to-end diagnostics and a loopback browser harness.
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use clap::{Parser, Subcommand};
use selfie_enrollment_client::{Config, EnrollmentClient};
use selfie_enrollment_sealed_types::EmbeddingResult;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Strict-attestation enrollment diagnostics")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Extract through a real measured enclave; does not print biometric data.
    Extract {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        image: PathBuf,
        /// Optional sensitive JSON output; created mode 0600 and never overwritten.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Serve the browser harness on 127.0.0.1:8765 only.
    Serve {
        #[arg(long)]
        config: PathBuf,
        /// wasm-bindgen --target web output directory.
        #[arg(long, default_value = "target/enrollment-web")]
        bindings: PathBuf,
    },
}
fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn read_config(path: &Path) -> Result<Config> {
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    config.validate()?;
    Ok(config)
}
#[derive(Clone)]
struct Harness {
    config: Config,
    bindings: PathBuf,
}
fn local_request(headers: &HeaderMap) -> bool {
    matches!(
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
        Some("127.0.0.1:8765")
    )
}
async fn artifact(
    state: Harness,
    headers: HeaderMap,
    filename: &str,
    content_type: &'static str,
) -> Response {
    if !local_request(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match tokio::fs::read(state.bindings.join(filename)).await {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, content_type),
                (header::CACHE_CONTROL, "no-store"),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Extract {
            config,
            image,
            output,
        } => {
            let config = read_config(&config)?;
            let size = std::fs::metadata(&image)?.len();
            if size == 0 || size > selfie_enrollment_api_types::MAX_IMAGE_BYTES as u64 {
                bail!("image size must be 1 byte through 8 MiB");
            }
            let client = EnrollmentClient::new(config)?;
            let session = client.connect().await?;
            let result = session.extract(std::fs::read(image)?).await?;
            if let Some(output) = output {
                let bytes = Zeroizing::new(serde_json::to_vec(&result)?);
                create_private(&output)?.write_all(&bytes)?;
            }
            match &result {
                EmbeddingResult::Success { embedding } => println!(
                    "{}",
                    serde_json::json!({"status":"success", "embedding_type":embedding.embedding_type,
                    "version":embedding.version,"inference_backend":embedding.inference_backend,"worker":embedding.worker})
                ),
                EmbeddingResult::Failed { reason } => bail!("enclave rejected image: {reason:?}"),
            }
        }
        Command::Serve { config, bindings } => {
            let config = read_config(&config)?;
            for filename in [
                "selfie_enrollment_client.js",
                "selfie_enrollment_client_bg.wasm",
            ] {
                if !bindings.join(filename).is_file() {
                    bail!("build browser bindings first: missing {filename}");
                }
            }
            let state = Harness { config, bindings };
            let app = Router::new()
                .route(
                    "/",
                    get(|headers: HeaderMap| async move {
                        if !local_request(&headers) {
                            return StatusCode::FORBIDDEN.into_response();
                        }
                        (
                            [
                                (header::CACHE_CONTROL, "no-store"),
                                (header::REFERRER_POLICY, "no-referrer"),
                                (header::X_FRAME_OPTIONS, "DENY"),
                            ],
                            Html(include_str!("../web/index.html")),
                        )
                            .into_response()
                    }),
                )
                .route(
                    "/config",
                    get(
                        |State(state): State<Harness>, headers: HeaderMap| async move {
                            if !local_request(&headers) {
                                return StatusCode::FORBIDDEN.into_response();
                            }
                            ([(header::CACHE_CONTROL, "no-store")], Json(state.config))
                                .into_response()
                        },
                    ),
                )
                .route(
                    "/pkg/selfie_enrollment_client.js",
                    get(|State(state), headers| {
                        artifact(
                            state,
                            headers,
                            "selfie_enrollment_client.js",
                            "text/javascript",
                        )
                    }),
                )
                .route(
                    "/pkg/selfie_enrollment_client_bg.wasm",
                    get(|State(state), headers| {
                        artifact(
                            state,
                            headers,
                            "selfie_enrollment_client_bg.wasm",
                            "application/wasm",
                        )
                    }),
                )
                .with_state(state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8765").await?;
            println!("Browser harness: http://127.0.0.1:8765 (Ctrl-C stops the harness)");
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_sensitive_output_is_private_and_never_overwritten() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("result.json");
        create_private(&file).unwrap();
        assert!(create_private(&file).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
