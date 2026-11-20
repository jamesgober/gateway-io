//! The gateway's CPU pool: a few threads that answer the requests whose
//! route is marked `WorkClass::Cpu` (password hashing), so the reactor
//! worker that holds the connection goes straight back to its other
//! connections.
//!
//! The queue is bounded: a request is placed only after a place in the queue
//! is reserved, and a full queue is answered 503 on the worker instead.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

/// One request's work on a pool thread.
pub(crate) type Job = Box<dyn FnOnce() + Send + 'static>;

/// Requests that may wait per thread.
pub const QUEUE_PER_THREAD: usize = 16;

/// The pool. Its threads end when the last handle on the pool is gone (the
/// queue closes); they are never joined, so a job that drops the last handle
/// cannot wait on itself.
pub(crate) struct CpuPool {
    tx: Mutex<Sender<Job>>,
    /// Jobs placed and not finished (queued or running).
    pending: Arc<AtomicUsize>,
    cap: usize,
}

impl std::fmt::Debug for CpuPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpuPool")
            .field("pending", &self.pending.load(Ordering::Relaxed))
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

/// A place in the queue, given back if no job takes it.
pub(crate) struct Place<'a> {
    pool: &'a CpuPool,
    used: bool,
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        if !self.used {
            self.pool.pending.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl Place<'_> {
    /// Places `job` in the queue.
    pub(crate) fn submit(mut self, job: Job) -> Result<(), Job> {
        let sent = self
            .pool
            .tx
            .lock()
            .map_err(|_| ())
            .and_then(|tx| tx.send(job).map_err(|e| drop(e.0)));
        match sent {
            Ok(()) => {
                self.used = true;
                Ok(())
            }
            // The pool is gone (only while the process stops): nothing ran.
            Err(()) => Err(Box::new(|| {})),
        }
    }
}

impl CpuPool {
    /// `threads` threads named `gateway-cpu-<n>`; `None` for none.
    pub(crate) fn start(threads: u16) -> std::io::Result<Option<Arc<CpuPool>>> {
        if threads == 0 {
            return Ok(None);
        }
        let (tx, rx) = channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        let pending = Arc::new(AtomicUsize::new(0));
        for n in 0..threads {
            let rx = Arc::clone(&rx);
            let pending = Arc::clone(&pending);
            std::thread::Builder::new()
                .name(format!("gateway-cpu-{n}"))
                .spawn(move || work(&rx, &pending))?;
        }
        Ok(Some(Arc::new(CpuPool {
            tx: Mutex::new(tx),
            pending,
            cap: usize::from(threads) * QUEUE_PER_THREAD,
        })))
    }

    /// A place in the queue, or `None` when it is full.
    pub(crate) fn reserve(&self) -> Option<Place<'_>> {
        let mut n = self.pending.load(Ordering::Acquire);
        loop {
            if n >= self.cap {
                return None;
            }
            match self
                .pending
                .compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Some(Place {
                        pool: self,
                        used: false,
                    });
                }
                Err(now) => n = now,
            }
        }
    }

    /// Jobs placed and not finished.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }
}

/// A pool thread: one job at a time until the queue closes. A job that
/// panics is caught, so the thread and its place in the count survive.
fn work(rx: &Mutex<Receiver<Job>>, pending: &AtomicUsize) {
    loop {
        let job = match rx.lock() {
            Ok(rx) => rx.recv(),
            Err(_) => return,
        };
        let Ok(job) = job else {
            return;
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
        pending.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn the_queue_is_bounded_and_places_come_back() {
        let pool = CpuPool::start(1).expect("start").expect("a pool");
        let (hold, wait) = std::sync::mpsc::channel::<()>();
        let wait = Arc::new(Mutex::new(wait));
        // Fill every place: the first job blocks the thread.
        for _ in 0..QUEUE_PER_THREAD {
            let place = pool.reserve().expect("room");
            let wait = Arc::clone(&wait);
            place
                .submit(Box::new(move || {
                    let _ = wait.lock().map(|w| w.recv_timeout(Duration::from_secs(5)));
                }))
                .map_err(|_| ())
                .expect("placed");
        }
        assert!(pool.reserve().is_none(), "full");
        // A place reserved and not used comes back.
        for _ in 0..QUEUE_PER_THREAD {
            let _ = hold.send(());
        }
        let t = Instant::now();
        while pool.pending() > 0 && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(pool.pending(), 0);
        drop(pool.reserve().expect("room again"));
        assert_eq!(pool.pending(), 0, "an unused place is given back");
        // A panicking job leaves the thread working.
        let (done, got) = std::sync::mpsc::channel();
        pool.reserve()
            .expect("room")
            .submit(Box::new(|| panic!("a handler panicked")))
            .map_err(|_| ())
            .expect("placed");
        pool.reserve()
            .expect("room")
            .submit(Box::new(move || {
                let _ = done.send(());
            }))
            .map_err(|_| ())
            .expect("placed");
        assert!(got.recv_timeout(Duration::from_secs(5)).is_ok());
        assert!(CpuPool::start(0).expect("none").is_none());
    }
}
