//! Background jobs: slow side work (emails, sweeps, cache warming) off the
//! request path.
//!
//! The seam is [`Jobs`]: a service submits a named job with an optional
//! idempotency key and gets an answer at once. [`InProcessJobs`] runs them on
//! a few threads of this process, from a bounded queue: a full queue refuses
//! (never an unbounded backlog), a key already queued or running is not queued
//! twice, and at shutdown the queued jobs finish until the deadline. A durable
//! runner (task-io: persisted queue, retries, cron) replaces it behind the same
//! trait. [`NoJobs`] refuses every job: what a core without a runner has, so
//! work is never silently dropped.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

/// The work of one job. Returns `Err` with a reason when it failed.
pub type Work = Box<dyn FnOnce() -> Result<(), String> + Send + 'static>;

/// One job.
pub struct Job {
    name: &'static str,
    key: Option<String>,
    work: Work,
}

impl Job {
    /// A job called `name` (for logs and counts) doing `work`.
    pub fn new(
        name: &'static str,
        work: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Job {
        Job {
            name,
            key: None,
            work: Box::new(work),
        }
    }

    /// The same job with an idempotency key: while a job with this key is
    /// queued or running, another one is not queued.
    #[must_use]
    pub fn key(mut self, key: impl Into<String>) -> Job {
        self.key = Some(key.into());
        self
    }

    /// The job's name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Job")
            .field("name", &self.name)
            .field("key", &self.key)
            .finish()
    }
}

/// What a submit answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submitted {
    /// Queued.
    Queued,
    /// A job with the same key is already queued or running.
    Duplicate,
}

/// Why a job was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobRefused {
    /// The queue is full: retry later or tell the visitor.
    Full,
    /// The runner is stopping or there is none.
    Unavailable,
}

impl fmt::Display for JobRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobRefused::Full => f.write_str("the job queue is full"),
            JobRefused::Unavailable => f.write_str("no job runner is accepting jobs"),
        }
    }
}

impl std::error::Error for JobRefused {}

/// Counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JobStats {
    /// Jobs queued.
    pub queued: u64,
    /// Jobs that ran to `Ok`.
    pub done: u64,
    /// Jobs that returned `Err` or panicked.
    pub failed: u64,
    /// Jobs refused (full, stopping).
    pub refused: u64,
    /// Jobs left in the queue when the runner stopped.
    pub abandoned: u64,
}

/// The job seam: submit returns at once.
pub trait Jobs: Send + Sync + 'static {
    /// Submits a job. Never blocks.
    fn submit(&self, job: Job) -> Result<Submitted, JobRefused>;

    /// Shutdown step 3: stop accepting, finish what is queued until
    /// `deadline`, and report what was left.
    fn stop(&self, deadline: Instant) -> JobStats;

    /// Counters so far.
    fn stats(&self) -> JobStats;
}

/// A core without a job runner: every job is refused.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoJobs;

impl Jobs for NoJobs {
    fn submit(&self, _job: Job) -> Result<Submitted, JobRefused> {
        Err(JobRefused::Unavailable)
    }
    fn stop(&self, _deadline: Instant) -> JobStats {
        JobStats::default()
    }
    fn stats(&self) -> JobStats {
        JobStats::default()
    }
}

#[derive(Default)]
struct Counters {
    queued: AtomicU64,
    done: AtomicU64,
    failed: AtomicU64,
    refused: AtomicU64,
    abandoned: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> JobStats {
        JobStats {
            queued: self.queued.load(Ordering::Relaxed),
            done: self.done.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            abandoned: self.abandoned.load(Ordering::Relaxed),
        }
    }
}

struct Shared {
    keys: Mutex<HashSet<String>>,
    counters: Counters,
    /// Past the shutdown deadline: workers drop what is left.
    deadline: Mutex<Option<Instant>>,
}

/// Jobs on a few threads of this process, from a bounded queue.
pub struct InProcessJobs {
    tx: Mutex<Option<SyncSender<Job>>>,
    shared: Arc<Shared>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl InProcessJobs {
    /// `threads` workers (at least 1) and a queue of `queue` jobs (at least 1).
    pub fn new(threads: usize, queue: usize) -> std::io::Result<InProcessJobs> {
        let (tx, rx) = mpsc::sync_channel::<Job>(queue.max(1));
        let rx = Arc::new(Mutex::new(rx));
        let shared = Arc::new(Shared {
            keys: Mutex::new(HashSet::new()),
            counters: Counters::default(),
            deadline: Mutex::new(None),
        });
        let mut workers = Vec::new();
        for i in 0..threads.max(1) {
            let rx = rx.clone();
            let shared = shared.clone();
            workers.push(
                std::thread::Builder::new()
                    .name(format!("jobs-{i}"))
                    .spawn(move || run(&rx, &shared))?,
            );
        }
        Ok(InProcessJobs {
            tx: Mutex::new(Some(tx)),
            shared,
            workers: Mutex::new(workers),
        })
    }
}

fn run(rx: &Mutex<Receiver<Job>>, shared: &Shared) {
    loop {
        let job = match rx.lock() {
            Ok(rx) => rx.recv(),
            Err(_) => return,
        };
        let Ok(job) = job else {
            return; // the sender is gone: stopped and drained
        };
        let late = shared
            .deadline
            .lock()
            .ok()
            .and_then(|d| *d)
            .is_some_and(|d| Instant::now() >= d);
        if late {
            shared.counters.abandoned.fetch_add(1, Ordering::Relaxed);
        } else {
            let work = job.work;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
            match outcome {
                Ok(Ok(())) => shared.counters.done.fetch_add(1, Ordering::Relaxed),
                _ => shared.counters.failed.fetch_add(1, Ordering::Relaxed),
            };
        }
        if let Some(key) = job.key
            && let Ok(mut keys) = shared.keys.lock()
        {
            keys.remove(&key);
        }
    }
}

impl Jobs for InProcessJobs {
    fn submit(&self, job: Job) -> Result<Submitted, JobRefused> {
        let tx = self.tx.lock().ok().and_then(|t| t.clone());
        let Some(tx) = tx else {
            self.shared.counters.refused.fetch_add(1, Ordering::Relaxed);
            return Err(JobRefused::Unavailable);
        };
        if let Some(key) = &job.key {
            let Ok(mut keys) = self.shared.keys.lock() else {
                return Err(JobRefused::Unavailable);
            };
            if !keys.insert(key.clone()) {
                return Ok(Submitted::Duplicate);
            }
        }
        let key = job.key.clone();
        match tx.try_send(job) {
            Ok(()) => {
                self.shared.counters.queued.fetch_add(1, Ordering::Relaxed);
                Ok(Submitted::Queued)
            }
            Err(e) => {
                if let Some(key) = key
                    && let Ok(mut keys) = self.shared.keys.lock()
                {
                    keys.remove(&key);
                }
                self.shared.counters.refused.fetch_add(1, Ordering::Relaxed);
                Err(match e {
                    TrySendError::Full(_) => JobRefused::Full,
                    TrySendError::Disconnected(_) => JobRefused::Unavailable,
                })
            }
        }
    }

    fn stop(&self, deadline: Instant) -> JobStats {
        if let Ok(mut d) = self.shared.deadline.lock() {
            *d = Some(deadline);
        }
        // Dropping the only sender lets the workers drain the queue and end.
        if let Ok(mut tx) = self.tx.lock() {
            tx.take();
        }
        let workers = self
            .workers
            .lock()
            .map(|mut w| std::mem::take(&mut *w))
            .unwrap_or_default();
        for w in workers {
            let _ = w.join();
        }
        self.shared.counters.snapshot()
    }

    fn stats(&self) -> JobStats {
        self.shared.counters.snapshot()
    }
}

impl fmt::Debug for InProcessJobs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessJobs")
            .field("stats", &self.shared.counters.snapshot())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn jobs_run_off_the_caller_and_keys_dedupe() {
        let jobs = InProcessJobs::new(2, 16).expect("runner");
        let ran = Arc::new(AtomicUsize::new(0));
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let gate_rx = Arc::new(Mutex::new(gate_rx));
        let r = ran.clone();
        let g = gate_rx.clone();
        let first = Job::new("email", move || {
            let _ = g.lock().map(|rx| rx.recv_timeout(Duration::from_secs(5)));
            r.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .key("verify:7");
        assert_eq!(jobs.submit(first), Ok(Submitted::Queued));
        let again = Job::new("email", || Ok(())).key("verify:7");
        assert_eq!(
            jobs.submit(again),
            Ok(Submitted::Duplicate),
            "same key while queued"
        );
        gate_tx.send(()).expect("release");
        let stats = jobs.stop(Instant::now() + Duration::from_secs(5));
        assert_eq!(ran.load(Ordering::Relaxed), 1);
        assert_eq!((stats.queued, stats.done), (1, 1));
        assert_eq!(
            jobs.submit(Job::new("late", || Ok(()))),
            Err(JobRefused::Unavailable),
            "stopped"
        );
    }

    #[test]
    fn a_full_queue_refuses_and_failures_are_counted() {
        let jobs = InProcessJobs::new(1, 1).expect("runner");
        let (tx, rx) = mpsc::channel::<()>();
        let rx = Mutex::new(rx);
        let hold = Job::new("hold", move || {
            let _ = rx.lock().map(|r| r.recv_timeout(Duration::from_secs(5)));
            Err("boom".into())
        });
        assert_eq!(jobs.submit(hold), Ok(Submitted::Queued));
        // The worker may or may not have taken it yet: fill until refused.
        let mut refused = false;
        for _ in 0..3 {
            if jobs.submit(Job::new("x", || panic!("a panicking job"))) == Err(JobRefused::Full) {
                refused = true;
            }
        }
        assert!(refused, "the bounded queue refuses");
        tx.send(()).expect("release");
        let stats = jobs.stop(Instant::now() + Duration::from_secs(5));
        assert!(stats.failed >= 1, "{stats:?}");
        assert!(stats.refused >= 1);
    }

    #[test]
    fn no_jobs_refuses() {
        assert_eq!(
            NoJobs.submit(Job::new("x", || Ok(()))),
            Err(JobRefused::Unavailable)
        );
    }
}
