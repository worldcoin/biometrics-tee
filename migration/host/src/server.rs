//! Axum server setup and lifecycle.

use std::{net::SocketAddr, num::NonZeroU16};

use anyhow::Context;
use telemetry_batteries::tracing::middleware::TraceLayer;
use tokio::net::TcpListener;

use crate::{AppState, routes, worker::Worker};

/// Starts the API server and the worker. If the worker ever stops, the process exits, so a
/// host never keeps accepting jobs nothing runs.
///
/// # Errors
///
/// Returns an error when the listener cannot bind, the server exits, or the worker stops.
pub async fn start(port: NonZeroU16, state: AppState, worker: Worker) -> anyhow::Result<()> {
    let address = SocketAddr::from(([0, 0, 0, 0], port.get()));
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind API to {address}"))?;

    let server = axum::serve(
        listener,
        routes::handler()
            .with_state(state)
            .layer(TraceLayer::new_for_axum())
            .into_make_service(),
    )
    .with_graceful_shutdown(shutdown_signal());

    tokio::select! {
        result = server => result.context("API server failed"),
        joined = tokio::spawn(worker.run()) => {
            tracing::error!(?joined, "job worker stopped");
            anyhow::bail!("job worker stopped")
        }
    }
}

/// Resolves on the first shutdown signal; SIGTERM too, since that is what drains a pod.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl-C handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = interrupt => tracing::warn!("received Ctrl-C, shutting down"),
        () = terminate => tracing::warn!("received SIGTERM, shutting down"),
    }
}
