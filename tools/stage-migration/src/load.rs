//! Load test: many stage users migrating concurrently, each again as soon as its job ends.
//!
//! The API holds one active job per `sub`, so concurrency is the number of users. Users are
//! provisioned before the timed run and deleted after it, also when the run is interrupted.

use std::{
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, bail};
use clap::Args;
use tokio::{sync::Semaphore, task::JoinSet};

use crate::{
    Setup, StageArgs,
    migration::Stage,
    report::{JobReport, summary},
    user::{ReferencePcp, StageUser},
};

#[derive(Args)]
pub struct LoadArgs {
    #[command(flatten)]
    stage: StageArgs,

    /// Stage users to provision; also the number of migrations in flight.
    #[arg(long, default_value = "4")]
    users: NonZeroUsize,

    /// Migrations to run in total, spread over the users.
    #[arg(long, default_value = "20")]
    jobs: NonZeroUsize,

    /// Users provisioned at once; each one registers, enrolls and refreshes on stage.
    #[arg(long, default_value = "4")]
    provision_concurrency: NonZeroUsize,

    /// Workers start spread evenly over this many seconds, so load builds up gradually.
    #[arg(long, default_value_t = 0)]
    ramp_up_secs: u64,
}

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
    let failed = result?;
    if failed > 0 {
        bail!("{failed} of {} migrations failed", args.jobs);
    }
    if undeleted > 0 {
        bail!("{undeleted} stage users could not be deleted");
    }
    Ok(())
}

/// Returns how many migrations failed.
async fn provision_and_load(
    args: &LoadArgs,
    stage: Stage,
    reference: ReferencePcp,
    ag_private_key_pem: String,
    users: Arc<Mutex<Vec<Arc<StageUser>>>>,
) -> Result<usize> {
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
    let started = Instant::now();
    let reports = load(
        Arc::new(stage),
        users,
        args.jobs.get(),
        Duration::from_secs(args.ramp_up_secs),
    )
    .await?;
    eprint!("{}", summary(&reports, started.elapsed()));
    Ok(reports
        .iter()
        .filter(|report| report.outcome.is_err())
        .count())
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

/// Runs `jobs` migrations, one worker per user.
async fn load(
    stage: Arc<Stage>,
    users: Vec<Arc<StageUser>>,
    jobs: usize,
    ramp_up: Duration,
) -> Result<Vec<JobReport>> {
    let claimed = Arc::new(AtomicUsize::new(0));
    let workers = users.len();
    let mut tasks = JoinSet::new();
    for (worker, user) in users.into_iter().enumerate() {
        let stage = Arc::clone(&stage);
        let claimed = Arc::clone(&claimed);
        #[allow(clippy::cast_precision_loss)]
        let delay = ramp_up.mul_f64(worker as f64 / workers as f64);
        tasks.spawn(async move {
            tokio::time::sleep(delay).await;
            let mut reports = Vec::new();
            while claimed.fetch_add(1, Ordering::Relaxed) < jobs {
                let (report, _) = stage.run_job(&user).await;
                println!("{}", report.to_json());
                reports.push(report);
            }
            reports
        });
    }

    let mut reports = Vec::with_capacity(jobs);
    while let Some(worker) = tasks.join_next().await {
        reports.extend(worker?);
    }
    Ok(reports)
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
