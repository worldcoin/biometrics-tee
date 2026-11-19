//! Load generator: many concurrent whole migrations of one PCP.
//!
//! Each job runs under a fresh random `sub`, since the API holds one active job per `sub`. Every
//! finished job is printed to stdout as one JSON line; a summary goes to stderr at the end.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    future::Future,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Args;
use di_migration_primitives::app_api::{InitMigrationResponse, codes};
use reqwest::Url;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::{Device, DeviceArgs, MigrationError, SealArgs, Sealing};

#[derive(Args)]
pub struct LoadArgs {
    #[command(flatten)]
    device: DeviceArgs,

    #[command(flatten)]
    seal: SealArgs,

    /// Migrations to run in total.
    #[arg(long, default_value = "100")]
    jobs: NonZeroUsize,

    /// Migrations in flight at once.
    #[arg(long, default_value = "8")]
    concurrency: NonZeroUsize,

    /// Workers start spread evenly over this many seconds, so load builds up gradually.
    #[arg(long, default_value_t = 0)]
    ramp_up_secs: u64,

    /// Prefix of the random subs, to tell load-test jobs apart in storage and logs.
    #[arg(long, default_value = "loadtest-")]
    sub_prefix: String,

    /// Base back-off after an `at_capacity` rejection; up to as much again is added as jitter.
    #[arg(long, default_value_t = 30)]
    at_capacity_backoff_secs: u64,
}

/// What every worker shares.
struct Context {
    device: Device,
    sealing: Sealing,
    sub_prefix: String,
    at_capacity_backoff_secs: u64,
}

/// Runs the load and prints the summary; fails when any migration failed.
pub async fn run(api_url: &Url, args: LoadArgs) -> Result<(), String> {
    let context = Arc::new(Context {
        device: Device::new(api_url, &args.device)?,
        sealing: Sealing::load(&args.seal)?,
        sub_prefix: args.sub_prefix,
        at_capacity_backoff_secs: args.at_capacity_backoff_secs,
    });
    let jobs = args.jobs.get();
    let concurrency = args.concurrency.get().min(jobs);
    let ramp_up = Duration::from_secs(args.ramp_up_secs);
    let claimed = Arc::new(AtomicUsize::new(0));

    let started = Instant::now();
    let mut workers = JoinSet::new();
    for worker in 0..concurrency {
        let context = Arc::clone(&context);
        let claimed = Arc::clone(&claimed);
        #[allow(clippy::cast_precision_loss)]
        let delay = ramp_up.mul_f64(worker as f64 / concurrency as f64);
        workers.spawn(async move {
            tokio::time::sleep(delay).await;
            let mut reports = Vec::new();
            while claimed.fetch_add(1, Ordering::Relaxed) < jobs {
                let report = run_job(&context).await;
                println!("{}", report.to_json());
                reports.push(report);
            }
            reports
        });
    }

    let mut reports = Vec::with_capacity(jobs);
    while let Some(worker) = workers.join_next().await {
        reports.extend(worker.map_err(|error| format!("a load worker failed: {error}"))?);
    }
    eprint!("{}", summary(&reports, started.elapsed()));

    let failed = reports
        .iter()
        .filter(|report| report.outcome.is_err())
        .count();
    if failed > 0 {
        return Err(format!("{failed} of {jobs} migrations failed"));
    }
    Ok(())
}

async fn run_job(context: &Context) -> JobReport {
    let mut report = JobReport {
        sub: format!("{}{}", context.sub_prefix, Uuid::new_v4()),
        outcome: Ok(()),
        at_capacity: 0,
        phases: Vec::new(),
        total: Duration::ZERO,
    };
    let started = Instant::now();
    report.outcome = migrate(context, &mut report).await;
    report.total = started.elapsed();
    report
}

/// Runs one migration as the app does, acknowledging the download at the end.
async fn migrate(context: &Context, report: &mut JobReport) -> Result<(), MigrationError> {
    let Context {
        device, sealing, ..
    } = context;
    let sub = report.sub.clone();

    let response = admit(context, report).await?;
    let opener = report
        .time(Phase::SealUpload, async {
            let (blob, opener) = sealing.seal(&response)?;
            device.upload(&response.upload_url, blob).await?;
            Ok(opener)
        })
        .await?;
    report.time(Phase::Migrate, device.migrate(&sub)).await?;
    let migrated = report.time(Phase::Wait, device.wait(&sub)).await?;
    report
        .time(
            Phase::Download,
            device.download(&migrated.download_url, opener),
        )
        .await?;
    report
        .time(
            Phase::Acknowledge,
            device.acknowledge(&sub, &migrated.job_id),
        )
        .await
}

/// Inits the migration, backing off while the fleet is at capacity.
async fn admit(
    context: &Context,
    report: &mut JobReport,
) -> Result<InitMigrationResponse, MigrationError> {
    let started = Instant::now();
    loop {
        let attempt = Instant::now();
        match context.device.init_migration(&report.sub).await {
            Ok(response) => {
                report
                    .phases
                    .push((Phase::AdmissionWait, attempt.duration_since(started)));
                report.phases.push((Phase::Init, attempt.elapsed()));
                return Ok(response);
            }
            Err(error) if is_at_capacity(&error) => {
                report.at_capacity += 1;
                let backoff = context.at_capacity_backoff_secs;
                tokio::time::sleep(Duration::from_secs(backoff + fastrand::u64(..=backoff))).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_at_capacity(error: &MigrationError) -> bool {
    matches!(error, MigrationError::Client { source, .. } if source.reason() == codes::AT_CAPACITY)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// From the first init attempt to the admitted one; zero unless `at_capacity`.
    AdmissionWait,
    Init,
    /// Enclave verification, sealing and the S3 upload.
    SealUpload,
    Migrate,
    /// From migrate until the API reports the job migrated, at the poll interval's resolution.
    Wait,
    /// The S3 download and unsealing.
    Download,
    Acknowledge,
}

impl Phase {
    const ALL: [Self; 7] = [
        Self::AdmissionWait,
        Self::Init,
        Self::SealUpload,
        Self::Migrate,
        Self::Wait,
        Self::Download,
        Self::Acknowledge,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::AdmissionWait => "admission_wait",
            Self::Init => "init",
            Self::SealUpload => "seal_upload",
            Self::Migrate => "migrate",
            Self::Wait => "wait",
            Self::Download => "download",
            Self::Acknowledge => "acknowledge",
        }
    }
}

struct JobReport {
    sub: String,
    outcome: Result<(), MigrationError>,
    at_capacity: u32,
    phases: Vec<(Phase, Duration)>,
    total: Duration,
}

impl JobReport {
    /// Runs `step`, recording how long it took whether or not it succeeded.
    async fn time<T>(
        &mut self,
        phase: Phase,
        step: impl Future<Output = Result<T, MigrationError>>,
    ) -> Result<T, MigrationError> {
        let started = Instant::now();
        let result = step.await;
        self.phases.push((phase, started.elapsed()));
        result
    }

    fn outcome(&self) -> String {
        self.outcome
            .as_ref()
            .map_or_else(MigrationError::reason, |()| "migrated".into())
    }

    fn duration(&self, phase: Phase) -> Option<Duration> {
        self.phases
            .iter()
            .find_map(|&(recorded, duration)| (recorded == phase).then_some(duration))
    }

    fn to_json(&self) -> serde_json::Value {
        let mut record = serde_json::Map::new();
        record.insert("sub".into(), self.sub.clone().into());
        record.insert("outcome".into(), self.outcome().into());
        if let Err(error) = &self.outcome {
            record.insert("error".into(), error.to_string().into());
        }
        record.insert("at_capacity".into(), self.at_capacity.into());
        for &(phase, duration) in &self.phases {
            record.insert(format!("{}_ms", phase.as_str()), millis(duration).into());
        }
        record.insert("total_ms".into(), millis(self.total).into());
        record.into()
    }
}

/// Outcome counts, throughput and per-phase percentiles of the migrated jobs.
fn summary(reports: &[JobReport], elapsed: Duration) -> String {
    let migrated: Vec<&JobReport> = reports
        .iter()
        .filter(|report| report.outcome.is_ok())
        .collect();
    let mut outcomes = BTreeMap::<String, usize>::new();
    for report in reports {
        *outcomes.entry(report.outcome()).or_default() += 1;
    }
    let rejections: u32 = reports.iter().map(|report| report.at_capacity).sum();

    let mut out = String::new();
    #[allow(clippy::cast_precision_loss)]
    let per_minute = migrated.len() as f64 / elapsed.as_secs_f64() * 60.0;
    let _ = writeln!(
        out,
        "\n{} of {} migrated in {}, {per_minute:.1} per minute",
        migrated.len(),
        reports.len(),
        seconds(elapsed),
    );
    let _ = writeln!(out, "at_capacity rejections: {rejections}");
    for (outcome, count) in &outcomes {
        let _ = writeln!(out, "  {outcome}: {count}");
    }

    let _ = writeln!(
        out,
        "\n{:<16}{:>10}{:>10}{:>10}{:>10}",
        "migrated jobs", "p50", "p90", "p99", "max"
    );
    let phases = Phase::ALL.iter().map(|&phase| {
        (
            phase.as_str(),
            samples(&migrated, |report| report.duration(phase)),
        )
    });
    let total = ("total", samples(&migrated, |report| Some(report.total)));
    for (name, mut samples) in phases.chain([total]) {
        if samples.is_empty() {
            continue;
        }
        samples.sort_unstable();
        let _ = writeln!(
            out,
            "{name:<16}{:>10}{:>10}{:>10}{:>10}",
            seconds(percentile(&samples, 50)),
            seconds(percentile(&samples, 90)),
            seconds(percentile(&samples, 99)),
            seconds(samples[samples.len() - 1]),
        );
    }
    out
}

fn samples(
    reports: &[&JobReport],
    duration: impl Fn(&JobReport) -> Option<Duration>,
) -> Vec<Duration> {
    reports
        .iter()
        .filter_map(|report| duration(report))
        .collect()
}

/// Nearest-rank percentile of sorted, non-empty `samples`.
fn percentile(samples: &[Duration], percent: usize) -> Duration {
    let rank = (samples.len() * percent).div_ceil(100).max(1);
    samples[rank - 1]
}

fn seconds(duration: Duration) -> String {
    format!("{:.2}s", duration.as_secs_f64())
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;

    use super::percentile;
    use crate::{Cli, Command};

    #[test]
    fn percentiles_use_the_nearest_rank() {
        let samples: Vec<Duration> = (1..=10).map(Duration::from_secs).collect();

        assert_eq!(percentile(&samples, 50), Duration::from_secs(5));
        assert_eq!(percentile(&samples, 90), Duration::from_secs(9));
        assert_eq!(percentile(&samples, 99), Duration::from_secs(10));
        assert_eq!(percentile(&samples[..1], 50), Duration::from_secs(1));
    }

    #[test]
    fn load_needs_no_sub() {
        let cli = Cli::try_parse_from([
            "migration-cli",
            "load",
            "--integrity-token",
            "token",
            "--proof",
            "proof",
            "--challenge-id",
            "challenge",
            "--pcp",
            "pcp.bin",
            "--insecure-skip-measurements",
            "--credential",
            "credential",
            "--device-public-key",
            "key",
            "--jobs",
            "10",
            "--concurrency",
            "4",
        ])
        .expect("load runs under random subs");
        assert!(matches!(cli.command, Command::Load(_)));
    }
}
