//! The API's view of the host fleet: who is ready and how full each host is.
//!
//! A background loop resolves the hosts' headless Service and polls each host's `/capacity`;
//! init reads the cached result, so admission and placement never wait on the hosts.

use std::{
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use di_migration_primitives::host_api::Capacity;
use tokio::{task::JoinSet, time::Instant};

use crate::host_client::HostClient;

/// Finds the ready hosts.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Every ready host's address.
    async fn resolve(&self) -> Result<Vec<SocketAddr>, String>;
}

/// Resolves a headless Service, which lists only ready pods, so draining hosts drop out.
pub struct DnsResolver {
    name: String,
    port: u16,
}

impl DnsResolver {
    /// Resolves `name` and dials each address on `port`.
    #[must_use]
    pub const fn new(name: String, port: u16) -> Self {
        Self { name, port }
    }
}

#[async_trait]
impl Resolver for DnsResolver {
    async fn resolve(&self) -> Result<Vec<SocketAddr>, String> {
        let mut hosts: Vec<SocketAddr> = tokio::net::lookup_host((self.name.as_str(), self.port))
            .await
            .map_err(|error| error.to_string())?
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        Ok(hosts)
    }
}

/// One host's load as of the last poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostLoad {
    addr: SocketAddr,
    queued: usize,
    capacity: usize,
}

#[derive(Default)]
struct Snapshot {
    hosts: Vec<HostLoad>,
    refreshed_at: Option<Instant>,
}

/// Where init may place a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "init places jobs in a follow-up")
)]
pub enum Placement {
    /// This host has room.
    Host(SocketAddr),
    /// No host is below the admission threshold; the app should back off.
    AtCapacity,
    /// The fleet's load is unknown, e.g. polling failed; admitting blind could overload it.
    Unknown,
}

/// The cached fleet load, refreshed in the background.
pub struct Fleet {
    resolver: Arc<dyn Resolver>,
    client: HostClient,
    snapshot: RwLock<Snapshot>,
    /// Older snapshots count as unknown; a few missed polls in a row.
    max_age: Duration,
    /// A host is open while `queued` is below this percentage of its `capacity`.
    threshold_percent: usize,
}

impl Fleet {
    /// A fleet with no data yet; it is unknown until the first refresh.
    #[must_use]
    pub fn new(
        resolver: Arc<dyn Resolver>,
        client: HostClient,
        max_age: Duration,
        threshold_percent: usize,
    ) -> Self {
        Self {
            resolver,
            client,
            snapshot: RwLock::new(Snapshot::default()),
            max_age,
            threshold_percent,
        }
    }

    /// Polls every ready host once. A host that does not answer is left out, so it gets no jobs.
    pub async fn refresh(&self) {
        let hosts = match self.resolver.resolve().await {
            Ok(hosts) => hosts,
            Err(error) => {
                tracing::warn!(%error, dependency = "host-dns", "failed to resolve the hosts");
                return;
            }
        };

        let mut polls = JoinSet::new();
        for addr in hosts {
            let client = self.client.clone();
            polls.spawn(async move { (addr, client.capacity(addr).await) });
        }
        let mut loads = Vec::new();
        while let Some(joined) = polls.join_next().await {
            match joined {
                Ok((addr, Ok(Capacity { queued, capacity }))) => loads.push(HostLoad {
                    addr,
                    queued,
                    capacity,
                }),
                Ok((addr, Err(error))) => {
                    tracing::warn!(%addr, %error, dependency = "host", "capacity poll failed");
                }
                Err(error) => tracing::error!(%error, "capacity poll task failed"),
            }
        }

        *self.write() = Snapshot {
            hosts: loads,
            refreshed_at: Some(Instant::now()),
        };
    }

    /// Refreshes every `interval` until the process stops.
    pub async fn run(self: Arc<Self>, interval: Duration) {
        loop {
            self.refresh().await;
            tokio::time::sleep(interval).await;
        }
    }

    /// The fleet's summed load, or `None` while it is unknown.
    pub fn totals(&self) -> Option<Capacity> {
        let snapshot = self.read();
        self.is_fresh(&snapshot).then(|| Capacity {
            queued: snapshot.hosts.iter().map(|host| host.queued).sum(),
            capacity: snapshot.hosts.iter().map(|host| host.capacity).sum(),
        })
    }

    /// Picks a random host below the admission threshold. Nothing is counted between polls:
    /// the share above the threshold is headroom for jobs the hosts do not report yet.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "init places jobs in a follow-up")
    )]
    pub fn place(&self) -> Placement {
        let snapshot = self.read();
        if !self.is_fresh(&snapshot) {
            return Placement::Unknown;
        }
        let open: Vec<SocketAddr> = snapshot
            .hosts
            .iter()
            .filter(|host| host.queued * 100 < host.capacity * self.threshold_percent)
            .map(|host| host.addr)
            .collect();
        fastrand::choice(open).map_or(Placement::AtCapacity, Placement::Host)
    }

    fn is_fresh(&self, snapshot: &Snapshot) -> bool {
        snapshot
            .refreshed_at
            .is_some_and(|at| at.elapsed() <= self.max_age)
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Snapshot> {
        // Nothing panics while holding the lock, so a poisoned one still holds a whole snapshot.
        self.snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Snapshot> {
        self.snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use axum::{Json, Router, routing::get};
    use di_migration_primitives::host_api::Capacity;

    use super::{Fleet, Placement, Resolver};
    use crate::host_client::HostClient;

    /// Serves a host whose `/capacity` reports `queued` of `capacity`.
    async fn host(queued: usize, capacity: usize) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("should bind");
        let addr = listener.local_addr().expect("address");
        let router = Router::new().route(
            "/capacity",
            get(move || async move { Json(Capacity { queued, capacity }) }),
        );
        tokio::spawn(async move { axum::serve(listener, router).await });
        addr
    }

    struct Fixed(Vec<SocketAddr>);

    #[async_trait]
    impl Resolver for Fixed {
        async fn resolve(&self) -> Result<Vec<SocketAddr>, String> {
            Ok(self.0.clone())
        }
    }

    struct Failing(AtomicUsize);

    #[async_trait]
    impl Resolver for Failing {
        async fn resolve(&self) -> Result<Vec<SocketAddr>, String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err("no such host".to_owned())
        }
    }

    fn fleet(resolver: Arc<dyn Resolver>) -> Fleet {
        Fleet::new(
            resolver,
            HostClient::new().expect("client"),
            Duration::from_secs(15),
            50,
        )
    }

    #[tokio::test]
    async fn the_fleet_is_unknown_until_the_first_refresh() {
        let fleet = fleet(Arc::new(Fixed(vec![host(0, 4).await])));

        assert_eq!(fleet.totals(), None);
        assert_eq!(fleet.place(), Placement::Unknown);
    }

    #[tokio::test]
    async fn totals_sum_every_answering_host() {
        let unreachable: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let fleet = fleet(Arc::new(Fixed(vec![
            host(1, 4).await,
            host(3, 8).await,
            unreachable,
        ])));

        fleet.refresh().await;

        assert_eq!(
            fleet.totals(),
            Some(Capacity {
                queued: 4,
                capacity: 12
            })
        );
    }

    #[tokio::test]
    async fn hosts_at_the_threshold_are_at_capacity() {
        let fleet = fleet(Arc::new(Fixed(vec![host(2, 4).await, host(4, 4).await])));
        fleet.refresh().await;

        assert_eq!(fleet.place(), Placement::AtCapacity);
    }

    #[tokio::test]
    async fn placement_picks_only_hosts_below_the_threshold() {
        let open = host(1, 4).await;
        let fleet = fleet(Arc::new(Fixed(vec![host(2, 4).await, open])));
        fleet.refresh().await;

        for _ in 0..20 {
            assert_eq!(fleet.place(), Placement::Host(open));
        }
    }

    /// Placements are not counted until the next poll; the threshold's headroom absorbs them.
    #[tokio::test]
    async fn placements_leave_the_snapshot_unchanged() {
        let fleet = fleet(Arc::new(Fixed(vec![host(0, 4).await])));
        fleet.refresh().await;

        for _ in 0..10 {
            assert!(matches!(fleet.place(), Placement::Host(_)));
        }
        assert_eq!(
            fleet.totals(),
            Some(Capacity {
                queued: 0,
                capacity: 4
            })
        );
    }

    /// A DNS outage keeps the last snapshot only until it is too old to trust.
    #[tokio::test]
    async fn a_failed_resolve_lets_the_snapshot_go_stale() {
        let resolver = Arc::new(Failing(AtomicUsize::new(0)));
        let fleet = fleet(resolver.clone());

        fleet.refresh().await;

        assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
        assert_eq!(fleet.totals(), None);
    }
}
