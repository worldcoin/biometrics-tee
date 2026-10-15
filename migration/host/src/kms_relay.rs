//! Fixed-destination KMS TLS relay and temporary credentials for one enclave CID.
//! TLS bytes are opaque to the host. The AWS SDK provider owns credential refresh.

use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use di_migration_enclave_primitives::kms::{
    self as wire, CREDENTIALS_PORT, CREDENTIALS_TIMEOUT, TLS_PORT,
};
use std::{future::Future, io, time::Duration};
use telemetry_batteries::reexports::metrics;
use tokio::{net::TcpStream, task::JoinSet};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

const MAX_CONNECTIONS: usize = 32;
const RELAY_TIMEOUT: Duration = Duration::from_secs(15);

/// Serves both parent ports.
///
/// Only the configured enclave CID can connect. At most 32 workers are tracked,
/// including completed workers awaiting collection. Each connection has a deadline.
/// Supervising callers must stop the host if this listener exits unexpectedly.
///
/// # Errors
/// Returns invalid region/CID configuration, listener failures or worker panics.
pub async fn serve(
    region: &str,
    enclave_cid: u32,
    credentials: SharedCredentialsProvider,
) -> io::Result<()> {
    let hostname =
        wire::hostname(region).ok_or_else(|| io::Error::other("invalid KMS relay region"))?;
    if enclave_cid <= wire::PARENT_CID || enclave_cid == u32::MAX {
        return Err(io::Error::other("invalid enclave CID for KMS relay"));
    }
    let tls_listener = VsockListener::bind(VsockAddr::new(wire::PARENT_CID, TLS_PORT))?;
    let credentials_listener =
        VsockListener::bind(VsockAddr::new(wire::PARENT_CID, CREDENTIALS_PORT))?;
    let mut tasks = JoinSet::new();
    tracing::info!("enclave KMS relay enabled");
    loop {
        let (accepted, kind) = tokio::select! {
            result = tls_listener.accept() => (result, "tls"),
            result = credentials_listener.accept() => (result, "credentials"),
            result = tasks.join_next(), if !tasks.is_empty() => {
                if result.is_some_and(|result| result.is_err()) {
                    return Err(io::Error::other("KMS relay worker panicked"));
                }
                continue;
            }
        };
        let (stream, peer) = accepted?;
        if !allowed_peer(peer.cid(), enclave_cid) {
            metrics::counter!("migration.kms_relay.rejected", "reason" => "peer").increment(1);
            continue;
        }
        let hostname = hostname.clone();
        let credentials = credentials.clone();
        spawn_worker(&mut tasks, async move {
            let started = std::time::Instant::now();
            let result = if kind == "tls" {
                tokio::time::timeout(RELAY_TIMEOUT, relay(stream, &hostname)).await
            } else {
                tokio::time::timeout(CREDENTIALS_TIMEOUT, send_credentials(stream, credentials))
                    .await
            };
            let outcome = match result {
                Ok(Ok(())) => "success",
                Ok(Err(_)) => "io",
                Err(_) => "timeout",
            };
            metrics::counter!("migration.kms_relay.requests", "kind" => kind, "outcome" => outcome)
                .increment(1);
            metrics::histogram!("migration.kms_relay.duration_seconds", "kind" => kind)
                .record(started.elapsed().as_secs_f64());
            if outcome != "success" {
                tracing::warn!(kind, outcome, "enclave KMS relay exchange failed");
            }
        });
    }
}

fn spawn_worker(tasks: &mut JoinSet<()>, worker: impl Future<Output = ()> + Send + 'static) {
    if tasks.len() >= MAX_CONNECTIONS {
        metrics::counter!("migration.kms_relay.rejected", "reason" => "capacity").increment(1);
        return;
    }
    tasks.spawn(worker);
}

const fn allowed_peer(actual: u32, expected: u32) -> bool {
    actual == expected
}

async fn relay(mut stream: VsockStream, hostname: &str) -> io::Result<()> {
    let mut upstream = TcpStream::connect((hostname, 443)).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
    Ok(())
}

async fn send_credentials(
    mut stream: VsockStream,
    provider: SharedCredentialsProvider,
) -> io::Result<()> {
    let credentials = provider
        .provide_credentials()
        .await
        .map_err(|_| io::Error::other("workload credential provider failed"))?;
    wire::write_credentials(&mut stream, &credentials).await
}

#[cfg(test)]
mod tests {
    use super::{MAX_CONNECTIONS, spawn_worker};
    use tokio::{sync::mpsc, task::JoinSet};

    #[tokio::test]
    async fn capacity_is_released_only_when_workers_are_collected() {
        let mut tasks = JoinSet::new();
        let (completed, mut completions) = mpsc::unbounded_channel();
        for _ in 0..MAX_CONNECTIONS {
            let completed = completed.clone();
            spawn_worker(&mut tasks, async move {
                completed.send(()).unwrap();
            });
        }
        spawn_worker(&mut tasks, async {});
        assert_eq!(tasks.len(), MAX_CONNECTIONS);

        for _ in 0..MAX_CONNECTIONS {
            completions.recv().await.unwrap();
        }
        spawn_worker(&mut tasks, async {});
        assert_eq!(tasks.len(), MAX_CONNECTIONS);

        tasks.join_next().await.unwrap().unwrap();
        spawn_worker(&mut tasks, async {});
        assert_eq!(tasks.len(), MAX_CONNECTIONS);
        tasks.join_all().await;
    }

    #[test]
    fn only_the_configured_enclave_receives_credentials() {
        assert!(super::allowed_peer(16, 16));
        for peer in [0, 1, 2, 3, 15, 17, u32::MAX] {
            assert!(!super::allowed_peer(peer, 16));
        }
    }
}
