//! Load generator: many concurrent whole migrations of one PCP.
//!
//! Each job runs under a fresh random `sub`, since the API holds one active job per `sub`. Every
//! finished job is printed to stdout as one JSON line; a summary goes to stderr at the end.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    future::Future,
    io::{self, Write as _},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use clap::Args;
use di_migration_client::ClientError;
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

    /// Fallback base back-off after an admission rejection when the API omits `Retry-After`;
    /// up to as much again is added as jitter. Must be at least 1s.
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
    at_capacity_backoff_secs: u64,

    /// Give up admitting a job after this many seconds of waiting and back-off (0 = no limit).
    #[arg(long, default_value_t = 600)]
    max_admission_wait_secs: u64,
}

/// What every worker shares.
struct Context {
    device: Device,
    sealing: Sealing,
    sub_prefix: String,
    at_capacity_backoff_secs: u64,
    max_admission_wait: Option<Duration>,
}

/// Runs the load and prints the summary; fails when any migration failed.
pub async fn run(api_url: &Url, args: LoadArgs) -> Result<(), String> {
    let context = Arc::new(Context {
        device: Device::new(api_url, &args.device)?,
        sealing: Sealing::load(&args.seal)?,
        sub_prefix: args.sub_prefix,
        at_capacity_backoff_secs: args.at_capacity_backoff_secs,
        max_admission_wait: (args.max_admission_wait_secs > 0)
            .then(|| Duration::from_secs(args.max_admission_wait_secs)),
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
                emit_json_line(&report);
                reports.push(report);
            }
            reports
        });
    }

    let mut reports = Vec::with_capacity(jobs);
    let mut worker_failures = 0usize;
    while let Some(worker) = workers.join_next().await {
        match worker {
            Ok(batch) => reports.extend(batch),
            Err(error) => {
                worker_failures += 1;
                eprintln!("a load worker failed: {error}");
            }
        }
    }
    eprint!("{}", summary(&reports, started.elapsed(), args.ramp_up_secs));

    let failed = reports
        .iter()
        .filter(|report| report.outcome.is_err())
        .count();
    if worker_failures > 0 {
        return Err(format!(
            "{worker_failures} workers panicked; {failed} of {} migrations failed",
            reports.len()
        ));
    }
    if failed > 0 {
        return Err(format!("{failed} of {} migrations failed", reports.len()));
    }
    Ok(())
}

fn emit_json_line(report: &JobReport) {
    let mut out = io::stdout().lock();
    if let Err(error) = writeln!(out, "{}", report.to_json())
        && error.kind() != io::ErrorKind::BrokenPipe
    {
        eprintln!("failed to write a load result: {error}");
    }
}

async fn run_job(context: &Context) -> JobReport {
    let mut report = JobReport {
        sub: format!("{}{}", context.sub_prefix, Uuid::new_v4()),
        outcome: Ok(()),
        at_capacity: 0,
        capacity_unknown: 0,
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
            let (blob, opener) = sealing.seal(&response).await?;
            device.upload(&response.upload_url, blob).await?;
            Ok(opener)
        })
        .await?;
    report.time(Phase::Migrate, device.migrate(&sub)).await?;
    let migrated = report.time(Phase::Wait, device.wait(&sub)).await?;
    let pcp = report
        .time(
            Phase::Download,
            device.download(&migrated.download_url, opener),
        )
        .await?;
    if pcp.is_empty() {
        return Err(MigrationError::Incomplete("a non-empty PCP"));
    }
    report
        .time(
            Phase::Acknowledge,
            device.acknowledge(&sub, &migrated.job_id),
        )
        .await
}

/// Inits the migration, backing off while the fleet is at capacity or capacity is unknown.
async fn admit(
    context: &Context,
    report: &mut JobReport,
) -> Result<InitMigrationResponse, MigrationError> {
    let started = Instant::now();
    loop {
        if let Some(limit) = context.max_admission_wait
            && started.elapsed() >= limit
        {
            report
                .phases
                .push((Phase::AdmissionWait, started.elapsed()));
            return Err(MigrationError::AdmissionTimeout);
        }

        let attempt = Instant::now();
        match context.device.init_migration(&report.sub).await {
            Ok(response) => {
                report
                    .phases
                    .push((Phase::AdmissionWait, attempt.duration_since(started)));
                report.phases.push((Phase::Init, attempt.elapsed()));
                return Ok(response);
            }
            Err(error) if is_admission_backoff(&error) => {
                record_admission_rejection(report, &error);
                let backoff = admission_backoff_secs(context, &error);
                if let Some(limit) = context.max_admission_wait {
                    let remaining = limit.saturating_sub(started.elapsed());
                    if remaining.is_zero() {
                        report
                            .phases
                            .push((Phase::AdmissionWait, started.elapsed()));
                        return Err(MigrationError::AdmissionTimeout);
                    }
                    tokio::time::sleep(backoff.min(remaining)).await;
                } else {
                    tokio::time::sleep(backoff).await;
                }
            }
            Err(error) => {
                report
                    .phases
                    .push((Phase::AdmissionWait, attempt.duration_since(started)));
                report.phases.push((Phase::Init, attempt.elapsed()));
                return Err(error);
            }
        }
    }
}

fn record_admission_rejection(report: &mut JobReport, error: &MigrationError) {
    match client_reason(error) {
        Some(codes::AT_CAPACITY) => report.at_capacity += 1,
        Some(codes::CAPACITY_UNKNOWN) => report.capacity_unknown += 1,
        _ => {}
    }
}

fn admission_backoff_secs(context: &Context, error: &MigrationError) -> Duration {
    let secs = client_error(error)
        .and_then(ClientError::retry_after)
        .unwrap_or_else(|| {
            let base = context.at_capacity_backoff_secs;
            base + fastrand::u64(..=base)
        });
    Duration::from_secs(secs.max(1))
}

fn is_admission_backoff(error: &MigrationError) -> bool {
    matches!(
        client_reason(error),
        Some(codes::AT_CAPACITY | codes::CAPACITY_UNKNOWN)
    )
}

fn client_error(error: &MigrationError) -> Option<&ClientError> {
    match error {
        MigrationError::Client { source, .. } => Some(source),
        _ => None,
    }
}

fn client_reason(error: &MigrationError) -> Option<&str> {
    client_error(error).map(ClientError::reason)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// From the first init attempt to the admitted one; zero unless admission backed off.
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
    capacity_unknown: u32,
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

    /// End-to-end time without admission back-off, when `admission_wait` was recorded.
    fn migration_time(&self) -> Duration {
        self.total
            .saturating_sub(self.duration(Phase::AdmissionWait).unwrap_or(Duration::ZERO))
    }

    fn to_json(&self) -> serde_json::Value {
        let mut record = serde_json::Map::new();
        record.insert("sub".into(), self.sub.clone().into());
        record.insert("outcome".into(), self.outcome().into());
        if let Err(error) = &self.outcome {
            record.insert("error".into(), error.to_string().into());
        }
        record.insert("at_capacity".into(), self.at_capacity.into());
        record.insert("capacity_unknown".into(), self.capacity_unknown.into());
        for &(phase, duration) in &self.phases {
            record.insert(format!("{}_ms", phase.as_str()), millis(duration).into());
        }
        record.insert("total_ms".into(), millis(self.total).into());
        record.insert(
            "migration_ms".into(),
            millis(self.migration_time()).into(),
        );
        record.into()
    }
}

/// Outcome counts, throughput and per-phase percentiles of the migrated jobs.
fn summary(reports: &[JobReport], elapsed: Duration, ramp_up_secs: u64) -> String {
    let migrated: Vec<&JobReport> = reports
        .iter()
        .filter(|report| report.outcome.is_ok())
        .collect();
    let failed: Vec<&JobReport> = reports
        .iter()
        .filter(|report| report.outcome.is_err())
        .collect();
    let mut outcomes = BTreeMap::<String, usize>::new();
    for report in reports {
        *outcomes.entry(report.outcome()).or_default() += 1;
    }
    let at_capacity: u32 = reports.iter().map(|report| report.at_capacity).sum();
    let capacity_unknown: u32 = reports.iter().map(|report| report.capacity_unknown).sum();

    let mut out = String::new();
    #[allow(clippy::cast_precision_loss)]
    let per_minute = migrated.len() as f64 / elapsed.as_secs_f64().max(f64::EPSILON) * 60.0;
    let _ = writeln!(
        out,
        "\n{} of {} migrated in {} wall time (includes ramp-up and admission back-off), {per_minute:.1} per minute",
        migrated.len(),
        reports.len(),
        seconds(elapsed),
    );
    if ramp_up_secs > 0 {
        let _ = writeln!(out, "ramp-up: {ramp_up_secs}s");
    }
    let _ = writeln!(out, "at_capacity rejections: {at_capacity}");
    let _ = writeln!(out, "capacity_unknown rejections: {capacity_unknown}");
    for (outcome, count) in &outcomes {
        let _ = writeln!(out, "  {outcome}: {count}");
    }

    if !failed.is_empty() {
        let mut times: Vec<Duration> = failed.iter().map(|report| report.total).collect();
        times.sort_unstable();
        let _ = writeln!(
            out,
            "\nfailed jobs time-to-failure: p50 {} p90 {} p99 {} max {}",
            seconds(percentile(&times, 50)),
            seconds(percentile(&times, 90)),
            seconds(percentile(&times, 99)),
            seconds(times[times.len() - 1]),
        );
    }

    let _ = writeln!(
        out,
        "\n{:<18}{:>10}{:>10}{:>10}{:>10}",
        "successful jobs", "p50", "p90", "p99", "max"
    );
    let phases = Phase::ALL.iter().map(|&phase| {
        (
            phase.as_str(),
            samples(&migrated, |report| report.duration(phase)),
        )
    });
    let totals = [
        (
            "total",
            samples(&migrated, |report| Some(report.total)),
        ),
        (
            "migration",
            samples(&migrated, |report| Some(report.migration_time())),
        ),
    ];
    for (name, mut samples) in phases.chain(totals) {
        if samples.is_empty() {
            continue;
        }
        samples.sort_unstable();
        let _ = writeln!(
            out,
            "{name:<18}{:>10}{:>10}{:>10}{:>10}",
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

    #[test]
    fn zero_admission_backoff_is_rejected() {
        let error = match Cli::try_parse_from([
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
            "--at-capacity-backoff-secs",
            "0",
        ]) {
            Ok(_) => panic!("zero back-off would busy-loop the API"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("at-capacity-backoff-secs"),
            "{error}"
        );
    }
}
