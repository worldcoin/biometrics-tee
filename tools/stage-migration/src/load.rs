//! Load test: many stage users migrating concurrently, closed-loop or at a fixed start rate.
//!
//! The API holds one active job per `sub`, so the number of users caps the migrations in flight.
//! Users are provisioned before the timed run and deleted after it, also when it is interrupted.

use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use clap::Args;
use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::MissedTickBehavior,
};

use crate::{
    Setup, StageArgs,
    migration::Stage,
    report::{JobReport, summary},
    user::{ReferencePcp, StageUser},
};

#[derive(Args)]
pub struct LoadArgs {
    #[command(flatten)]
    pub(crate) stage: StageArgs,

    /// Stage users to provision; also the most migrations in flight.
    #[arg(long, default_value = "4")]
    users: NonZeroUsize,

    /// Migrations to start in total; 20 unless `--duration-secs` is set.
    #[arg(long)]
    jobs: Option<NonZeroUsize>,

    /// No migration starts after this many seconds; running ones still finish.
    #[arg(long)]
    duration_secs: Option<NonZeroU64>,

    /// Starts this many migrations per minute on an idle user (open loop), instead of one
    /// after another per user; a start with no idle user is skipped and counted.
    #[arg(long, conflicts_with = "ramp_up_secs")]
    rate_per_min: Option<NonZeroU32>,

    /// Users provisioned at once; each one registers, enrolls and refreshes on stage.
    #[arg(long, default_value = "4")]
    provision_concurrency: NonZeroUsize,

    /// Closed loop only: workers start spread evenly over this many seconds.
    #[arg(long, default_value_t = 0)]
    ramp_up_secs: u64,
}

/// Jobs a load run starts when neither a count nor a duration is given.
const DEFAULT_JOBS: usize = 20;

/// Provisions, runs the load and deletes the users; fails when any step of it failed.
pub async fn run(args: LoadArgs) -> Result<()> {
    let Setup {
        stage,
        reference,
        ag_private_key_pem,
    } = args.stage.setup()?;
    let users = Arc::new(Mutex::new(Vec::new()));

    let finished = tokio::select! {
        result = provision_and_load(&args, stage, reference, ag_private_key_pem, Arc::clone(&users)) => Some(result),
        _ = tokio::signal::ctrl_c() => None,
    };
    let users = std::mem::take(&mut *users.lock().expect("users lock"));
    let undeleted = delete_all(users).await;

    let Some(result) = finished else {
        bail!("interrupted");
    };
    let (failed, started) = result?;
    if failed > 0 {
        bail!("{failed} of {started} migrations failed");
    }
    if undeleted > 0 {
        bail!("{undeleted} stage users could not be deleted");
    }
    Ok(())
}

/// Returns how many migrations failed and how many started.
async fn provision_and_load(
    args: &LoadArgs,
    stage: Stage,
    reference: ReferencePcp,
    ag_private_key_pem: String,
    users: Arc<Mutex<Vec<Arc<StageUser>>>>,
) -> Result<(usize, usize)> {
    let provisioned = provision(
        args.users.get(),
        args.provision_concurrency.get(),
        Arc::new(reference),
        Arc::new(ag_private_key_pem),
        Arc::clone(&users),
    )
    .await;
    if provisioned == 0 {
        bail!("no stage user could be provisioned");
    }

    let users = users.lock().expect("users lock").clone();
    let user_count = users.len();
    let started = Instant::now();
    let budget = Arc::new(Budget::new(
        args.jobs.map(NonZeroUsize::get),
        args.duration_secs
            .map(|secs| started + Duration::from_secs(secs.get())),
    ));
    let stage = Arc::new(stage);
    let (reports, skipped) = match args.rate_per_min {
        Some(rate) => open_loop(stage, users, &budget, rate).await?,
        None => (
            closed_loop(stage, users, budget, Duration::from_secs(args.ramp_up_secs)).await?,
            0,
        ),
    };
    eprint!("{}", summary(&reports, user_count, started.elapsed()));
    if skipped > 0 {
        eprintln!("skipped starts with no idle user: {skipped}; raise --users to hold the rate");
    }
    let failed = reports
        .iter()
        .filter(|report| report.outcome.is_err())
        .count();
    Ok((failed, reports.len()))
}

/// When a run stops starting migrations: after a job count, a deadline, or both.
struct Budget {
    jobs: Option<usize>,
    deadline: Option<Instant>,
    claimed: AtomicUsize,
}

impl Budget {
    fn new(jobs: Option<usize>, deadline: Option<Instant>) -> Self {
        let jobs = match (jobs, deadline) {
            (None, None) => Some(DEFAULT_JOBS),
            (jobs, _) => jobs,
        };
        Self {
            jobs,
            deadline,
            claimed: AtomicUsize::new(0),
        }
    }

    fn spent(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
            || self
                .jobs
                .is_some_and(|jobs| self.claimed.load(Ordering::Relaxed) >= jobs)
    }

    /// Claims the next job; false once the budget is spent.
    fn claim(&self) -> bool {
        if self.spent() {
            return false;
        }
        let claimed = self.claimed.fetch_add(1, Ordering::Relaxed);
        self.jobs.is_none_or(|jobs| claimed < jobs)
    }
}

/// Provisions up to `count` users into `users`, reporting failures; returns how many succeeded.
async fn provision(
    count: usize,
    concurrency: usize,
    reference: Arc<ReferencePcp>,
    ag_private_key_pem: Arc<String>,
    users: Arc<Mutex<Vec<Arc<StageUser>>>>,
) -> usize {
    let permits = Arc::new(Semaphore::new(concurrency));
    let mut tasks = JoinSet::new();
    for _ in 0..count {
        let permits = Arc::clone(&permits);
        let reference = Arc::clone(&reference);
        let ag_private_key_pem = Arc::clone(&ag_private_key_pem);
        let users = Arc::clone(&users);
        tasks.spawn(async move {
            let _permit = permits.acquire().await.expect("semaphore is never closed");
            let started = Instant::now();
            let user = StageUser::provision(&ag_private_key_pem, &reference).await?;
            users.lock().expect("users lock").push(Arc::new(user));
            Ok::<_, anyhow::Error>(started.elapsed())
        });
    }

    let mut provisioned = 0;
    while let Some(task) = tasks.join_next().await {
        match task.map_err(anyhow::Error::from).and_then(|result| result) {
            Ok(elapsed) => {
                provisioned += 1;
                eprintln!(
                    "provisioned stage user {provisioned} of {count} in {:.1}s",
                    elapsed.as_secs_f64()
                );
            }
            Err(error) => eprintln!("failed to provision a stage user: {error:#}"),
        }
    }
    provisioned
}

/// One worker per user, each starting its next migration as soon as the last one ends.
async fn closed_loop(
    stage: Arc<Stage>,
    users: Vec<Arc<StageUser>>,
    budget: Arc<Budget>,
    ramp_up: Duration,
) -> Result<Vec<JobReport>> {
    let workers = users.len();
    let mut tasks = JoinSet::new();
    for (worker, user) in users.into_iter().enumerate() {
        let stage = Arc::clone(&stage);
        let budget = Arc::clone(&budget);
        #[allow(clippy::cast_precision_loss)]
        let delay = ramp_up.mul_f64(worker as f64 / workers as f64);
        tasks.spawn(async move {
            tokio::time::sleep(delay).await;
            let mut reports = Vec::new();
            while budget.claim() {
                let (report, _) = stage.run_job(&user).await;
                println!("{}", report.to_json());
                reports.push(report);
            }
            reports
        });
    }

    let mut reports = Vec::new();
    while let Some(worker) = tasks.join_next().await {
        reports.extend(worker?);
    }
    Ok(reports)
}

/// Starts a migration every `60 / rate` seconds on an idle user, whatever the API's latency;
/// returns the reports and how many starts found no idle user.
async fn open_loop(
    stage: Arc<Stage>,
    users: Vec<Arc<StageUser>>,
    budget: &Budget,
    rate_per_min: NonZeroU32,
) -> Result<(Vec<JobReport>, usize)> {
    let (idle_tx, mut idle) = mpsc::unbounded_channel();
    for user in users {
        idle_tx.send(user).expect("the receiver is held here");
    }
    let mut ticks = tokio::time::interval(Duration::from_secs(60) / rate_per_min.get());
    ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut tasks = JoinSet::new();
    let mut skipped = 0;
    loop {
        ticks.tick().await;
        if budget.spent() {
            break;
        }
        let Ok(user) = idle.try_recv() else {
            skipped += 1;
            continue;
        };
        // The only claimer, so this succeeds after `spent` returned false.
        budget.claim();
        let stage = Arc::clone(&stage);
        let idle_tx = idle_tx.clone();
        tasks.spawn(async move {
            let (report, _) = stage.run_job(&user).await;
            println!("{}", report.to_json());
            // Fails only once the dispatcher stopped; the user is still deleted at the end.
            let _ = idle_tx.send(user);
            report
        });
    }

    let mut reports = Vec::new();
    while let Some(report) = tasks.join_next().await {
        reports.push(report?);
    }
    Ok((reports, skipped))
}

/// Deletes every user, reporting failures; returns how many could not be deleted.
async fn delete_all(users: Vec<Arc<StageUser>>) -> usize {
    if users.is_empty() {
        return 0;
    }
    eprintln!("deleting {} stage users", users.len());
    let mut tasks = JoinSet::new();
    for user in users {
        tasks.spawn(async move {
            user.delete()
                .await
                .map_err(|error| format!("{}: {error:#}", user.sub))
        });
    }
    let mut undeleted = 0;
    while let Some(task) = tasks.join_next().await {
        if let Err(error) = task
            .map_err(|error| error.to_string())
            .and_then(|result| result)
        {
            undeleted += 1;
            eprintln!("failed to delete stage user {error}");
        }
    }
    undeleted
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{Budget, DEFAULT_JOBS};

    fn claims(budget: &Budget) -> usize {
        std::iter::from_fn(|| budget.claim().then_some(()))
            .take(1000)
            .count()
    }

    #[test]
    fn without_limits_the_default_job_count_applies() {
        assert_eq!(claims(&Budget::new(None, None)), DEFAULT_JOBS);
    }

    #[test]
    fn the_job_count_caps_a_timed_run() {
        let deadline = Instant::now() + Duration::from_secs(60);
        assert_eq!(claims(&Budget::new(Some(3), Some(deadline))), 3);
    }

    #[test]
    fn nothing_starts_past_the_deadline() {
        let budget = Budget::new(None, Some(Instant::now()));
        assert!(budget.spent());
        assert!(!budget.claim());
    }
}
