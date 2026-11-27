//! Per-job timings as JSON lines, and the summary over a whole run.

use std::{collections::BTreeMap, fmt::Write as _, future::Future, time::Duration};

use crate::migration::MigrationError;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Fetching a challenge and proving ownership of the `sub` on the client.
    Proof,
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
    const ALL: [Self; 8] = [
        Self::Proof,
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
            Self::Proof => "proof",
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

pub struct JobReport {
    pub sub: String,
    pub outcome: Result<(), MigrationError>,
    pub at_capacity: u32,
    phases: Vec<(Phase, Duration)>,
    pub total: Duration,
}

impl JobReport {
    pub const fn new(sub: String) -> Self {
        Self {
            sub,
            outcome: Ok(()),
            at_capacity: 0,
            phases: Vec::new(),
            total: Duration::ZERO,
        }
    }

    pub fn record(&mut self, phase: Phase, duration: Duration) {
        self.phases.push((phase, duration));
    }

    /// Runs `step`, recording how long it took whether or not it succeeded.
    pub async fn time<T>(
        &mut self,
        phase: Phase,
        step: impl Future<Output = Result<T, MigrationError>>,
    ) -> Result<T, MigrationError> {
        let started = std::time::Instant::now();
        let result = step.await;
        self.record(phase, started.elapsed());
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

    pub fn to_json(&self) -> serde_json::Value {
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
pub fn summary(reports: &[JobReport], users: usize, elapsed: Duration) -> String {
    let migrated: Vec<&JobReport> = reports
        .iter()
        .filter(|report| report.outcome.is_ok())
        .collect();
    let mut outcomes = BTreeMap::<String, usize>::new();
    for report in reports {
        *outcomes.entry(report.outcome()).or_default() += 1;
    }
    let rejections: u32 = reports.iter().map(|report| report.at_capacity).sum();
    let mut per_user = BTreeMap::<&str, usize>::new();
    for report in reports {
        *per_user.entry(report.sub.as_str()).or_default() += 1;
    }
    let lock_conflicts = reports
        .iter()
        .filter(|report| {
            report
                .outcome
                .as_ref()
                .is_err_and(MigrationError::is_migration_in_progress)
        })
        .count();

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
    let _ = writeln!(
        out,
        "users: {users}, jobs per user: {}..{}, migration_in_progress: {lock_conflicts}",
        per_user.values().min().unwrap_or(&0),
        per_user.values().max().unwrap_or(&0),
    );
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

    use super::{JobReport, Phase, percentile, summary};
    use crate::migration::MigrationError;

    #[test]
    fn percentiles_use_the_nearest_rank() {
        let samples: Vec<Duration> = (1..=10).map(Duration::from_secs).collect();

        assert_eq!(percentile(&samples, 50), Duration::from_secs(5));
        assert_eq!(percentile(&samples, 90), Duration::from_secs(9));
        assert_eq!(percentile(&samples, 99), Duration::from_secs(10));
        assert_eq!(percentile(&samples[..1], 50), Duration::from_secs(1));
    }

    #[test]
    fn summary_counts_failures_and_times_only_migrated_jobs() {
        let mut migrated = JobReport::new("a".into());
        migrated.record(Phase::Wait, Duration::from_secs(40));
        migrated.total = Duration::from_secs(45);
        let mut failed = JobReport::new("b".into());
        failed.record(Phase::Wait, Duration::from_secs(600));
        failed.outcome = Err(MigrationError::Overdue);

        let summary = summary(&[migrated, failed], 2, Duration::from_secs(60));

        assert!(summary.contains("1 of 2 migrated"), "{summary}");
        assert!(summary.contains("overdue: 1"), "{summary}");
        assert!(summary.contains("40.00s"), "{summary}");
        assert!(!summary.contains("600.00s"), "{summary}");
        assert!(summary.contains("jobs per user: 1..1"), "{summary}");
        assert!(summary.contains("migration_in_progress: 0"), "{summary}");
    }
}
