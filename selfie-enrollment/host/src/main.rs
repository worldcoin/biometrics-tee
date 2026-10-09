#[cfg(target_os = "linux")]
#[derive(clap::Parser)]
struct Config {
    #[arg(long, env = "HTTP_ADDR", default_value = "0.0.0.0:8000")]
    address: String,
    #[arg(long, env = "ENCLAVE_CID", default_value_t = 16)]
    cid: u32,
    #[arg(long, env = "ENCLAVE_PORT", default_value_t = 1000)]
    port: u32,
    #[arg(long, env = "ADMISSION_PUBLIC_KEY")]
    admission_public_key: String,
    #[arg(long, env = "ADMISSION_AUDIENCE")]
    admission_audience: String,
    #[arg(long, env = "ALLOWED_ORIGINS", value_delimiter = ',')]
    allowed_origins: Vec<String>,
    #[arg(long, env = "WS_MAX_CONNECTIONS", default_value_t = 8)]
    max_connections: usize,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("the enrollment host requires Linux/vsock")
    }
    #[cfg(target_os = "linux")]
    {
        use clap::Parser;
        use selfie_enrollment_host::{AppState, NitroEnclave};
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
        let config = Config::parse();
        let state = AppState::new(
            std::sync::Arc::new(NitroEnclave {
                cid: config.cid,
                port: config.port,
            }),
            &config.admission_public_key,
            config.admission_audience,
            config.allowed_origins,
            config.max_connections,
        )?;
        let listener = tokio::net::TcpListener::bind(&config.address).await?;
        let permits = state.connections.clone();
        axum::serve(listener, selfie_enrollment_host::router(state.clone()))
            .with_graceful_shutdown(async move {
                let mut terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("install SIGTERM handler");
                tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
                permits.close();
            })
            .await?;
        state.drain().await?;
        Ok(())
    }
}
