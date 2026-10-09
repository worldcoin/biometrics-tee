//! Operator-only test issuer and end-to-end client. Never deploy this issuer publicly.
use anyhow::{Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use selfie_enrollment_api_types::{AdmissionChallenge, AdmissionTicket, ticket_message};
use selfie_enrollment_client::Config;
use selfie_enrollment_sealed_types::EmbeddingResult;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Strict-attestation enrollment diagnostics and loopback-only test issuer")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Generate a staging test issuer key pair; fails if either output exists.
    Keygen {
        #[arg(long)]
        directory: PathBuf,
    },
    /// Extract through a real measured enclave; does not print biometric data.
    Extract {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        image: PathBuf,
        #[arg(long)]
        admission_key: PathBuf,
        /// Optional sensitive JSON output; created mode 0600 and never overwritten.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Serve the browser harness and sign tickets on 127.0.0.1:8765 only.
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        admission_key: PathBuf,
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
fn read_key(path: &Path) -> Result<SigningKey> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.metadata()?.permissions().mode() & 0o077 != 0 {
            bail!("admission key must have mode 0600");
        }
    }
    let value = Zeroizing::new(std::fs::read_to_string(path)?);
    let bytes = Zeroizing::new(
        hex::decode(value.trim()).map_err(|_| anyhow!("invalid private key encoding"))?,
    );
    SigningKey::from_slice(&bytes).map_err(|_| anyhow!("invalid admission key"))
}
fn generate_keypair(directory: &Path) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    let staging = tempfile::tempdir_in(directory)?;
    let key = SigningKey::random(&mut rand::rngs::OsRng);
    let private_name = "admission-private.hex";
    let public_name = "admission-public.hex";
    let mut private = create_private(&staging.path().join(private_name))?;
    let mut public = create_private(&staging.path().join(public_name))?;
    let secret = Zeroizing::new(hex::encode(key.to_bytes()));
    writeln!(private, "{}", secret.as_str())?;
    writeln!(
        public,
        "{}",
        hex::encode(key.verifying_key().to_encoded_point(false).as_bytes())
    )?;
    private.sync_all()?;
    public.sync_all()?;
    // Hard links publish complete files without replacing an existing key.
    let private_path = directory.join(private_name);
    std::fs::hard_link(staging.path().join(private_name), &private_path)?;
    if let Err(error) = std::fs::hard_link(
        staging.path().join(public_name),
        directory.join(public_name),
    ) {
        std::fs::remove_file(private_path)?;
        return Err(error.into());
    }
    Ok(())
}
fn read_config(path: &Path) -> Result<Config> {
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    config.validate()?;
    Ok(config)
}
fn ticket(key: &SigningKey, challenge: &AdmissionChallenge) -> Result<AdmissionTicket> {
    let expires_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30;
    let signature: Signature = key.sign(&ticket_message(challenge, expires_at));
    Ok(AdmissionTicket {
        expires_at,
        signature: hex::encode(signature.to_bytes()),
    })
}
#[derive(Clone)]
struct Issuer {
    config: Config,
    key: Arc<SigningKey>,
    bindings: PathBuf,
}
fn local_request(headers: &HeaderMap) -> bool {
    matches!(
        headers.get(header::HOST).and_then(|v| v.to_str().ok()),
        Some("127.0.0.1:8765")
    )
}
async fn issue(
    State(state): State<Issuer>,
    headers: HeaderMap,
    Json(challenge): Json<AdmissionChallenge>,
) -> Result<Json<AdmissionTicket>, StatusCode> {
    if !local_request(&headers)
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
            != Some("http://127.0.0.1:8765")
        || challenge.audience != state.config.audience
    {
        return Err(StatusCode::FORBIDDEN);
    }
    ticket(&state.key, &challenge)
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
async fn artifact(
    state: Issuer,
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
        Command::Keygen { directory } => {
            generate_keypair(&directory)?;
            println!("Created issuer key pair; configure only admission-public.hex on the host.");
        }
        Command::Extract {
            config,
            image,
            admission_key,
            output,
        } => {
            let config = read_config(&config)?;
            let key = read_key(&admission_key)?;
            let size = std::fs::metadata(&image)?.len();
            if size == 0 || size > selfie_enrollment_api_types::MAX_IMAGE_BYTES as u64 {
                bail!("image size must be 1 byte through 8 MiB");
            }
            let result = selfie_enrollment_client::native::extract(
                &config,
                std::fs::read(image)?,
                move |challenge| async move {
                    ticket(&key, &challenge).map_err(|_| selfie_enrollment_client::Error::Admission)
                },
            )
            .await?;
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
        Command::Serve {
            config,
            admission_key,
            bindings,
        } => {
            let config = read_config(&config)?;
            let key = Arc::new(read_key(&admission_key)?);
            for filename in [
                "selfie_enrollment_client.js",
                "selfie_enrollment_client_bg.wasm",
            ] {
                if !bindings.join(filename).is_file() {
                    bail!("build browser bindings first: missing {filename}");
                }
            }
            let state = Issuer {
                config,
                key,
                bindings,
            };
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
                        |State(state): State<Issuer>, headers: HeaderMap| async move {
                            if !local_request(&headers) {
                                return StatusCode::FORBIDDEN.into_response();
                            }
                            ([(header::CACHE_CONTROL, "no-store")], Json(state.config))
                                .into_response()
                        },
                    ),
                )
                .route("/issue-ticket", post(issue))
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
                .layer(DefaultBodyLimit::max(2048))
                .with_state(state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:8765").await?;
            println!("Browser harness: http://127.0.0.1:8765 (Ctrl-C stops the issuer)");
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
    fn keygen_preserves_existing_files_and_can_retry_after_a_failed_pair() {
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().join("admission-private.hex");
        let public = temp.path().join("admission-public.hex");
        std::fs::write(&public, "existing").unwrap();
        assert!(generate_keypair(temp.path()).is_err());
        assert!(!private.exists());
        assert_eq!(std::fs::read_to_string(&public).unwrap(), "existing");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        std::fs::remove_file(&public).unwrap();
        generate_keypair(temp.path()).unwrap();
        let key = read_key(&private).unwrap();
        let expected = hex::encode(key.verifying_key().to_encoded_point(false).as_bytes());
        assert_eq!(std::fs::read_to_string(&public).unwrap().trim(), expected);
        assert!(generate_keypair(temp.path()).is_err());
        assert_eq!(read_key(&private).unwrap().to_bytes(), key.to_bytes());
        assert_eq!(std::fs::read_to_string(&public).unwrap().trim(), expected);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for file in [private, public] {
                assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            }
        }
    }
    #[test]
    fn issuer_is_bound_to_loopback_origin_and_never_overwrites_a_key() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("key");
        create_private(&file).unwrap();
        assert!(create_private(&file).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "attacker.example:8765".parse().unwrap());
        assert!(!local_request(&headers));
        headers.insert(header::HOST, "127.0.0.1:8765".parse().unwrap());
        assert!(local_request(&headers));
    }
    #[tokio::test]
    async fn browser_ticket_issuer_rejects_cross_origin_and_wrong_audience() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let state = Issuer {
            config: Config {
                endpoint: "".into(),
                audience: "stage".into(),
                releases: vec![],
            },
            key: Arc::new(key),
            bindings: PathBuf::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "127.0.0.1:8765".parse().unwrap());
        let challenge = AdmissionChallenge {
            audience: "stage".into(),
            nonce: [1; 32],
        };
        assert!(
            issue(
                State(state.clone()),
                headers.clone(),
                Json(challenge.clone())
            )
            .await
            .is_err()
        );
        headers.insert(header::ORIGIN, "https://attacker.example".parse().unwrap());
        assert!(
            issue(
                State(state.clone()),
                headers.clone(),
                Json(challenge.clone())
            )
            .await
            .is_err()
        );
        headers.insert(header::ORIGIN, "http://127.0.0.1:8765".parse().unwrap());
        let Json(signed) = issue(
            State(state.clone()),
            headers.clone(),
            Json(challenge.clone()),
        )
        .await
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            selfie_enrollment_api_types::verify_ticket(
                state.key.verifying_key(),
                &challenge,
                &signed,
                now
            )
            .is_ok()
        );
        let mut wrong = challenge;
        wrong.audience = "prod".into();
        assert!(issue(State(state), headers, Json(wrong)).await.is_err());
    }
}
