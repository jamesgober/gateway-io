//! The passport pool: one shelf of slots per worker, created at boot.
//!
//! The pool's size is the worker's limit on requests in flight: no free
//! passport means the worker is full, and the request gets a 503 without
//! taking anything. Admission ([`PassportPool::admit`]) reserves a passport
//! once the request head is complete; [`PassportPool::take`] hands it out when
//! the request is ready to run; [`PassportPool::give_back`] wipes it and puts
//! it back on its home shelf, from any thread.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::passport::{Exit, Passport};
use crate::slot::{Slot, SlotSizes};
use crate::stage::Arrived;

/// One worker's slots. Cache-line aligned so two workers never share a line.
#[repr(align(64))]
struct Shelf {
    /// Passports reserved by admission and not yet released.
    in_use: AtomicU32,
    /// The free slots. Touched by the owning worker, and by whichever thread
    /// returns a passport, so it is a lock (uncontended on the inline path).
    /// Boxed on purpose: a passport is the box, so moving one moves 8 bytes.
    #[allow(clippy::vec_box)]
    free: Mutex<Vec<Box<Slot>>>,
}

/// Counters, for health and benchmarks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Passports in the pool.
    pub capacity: u64,
    /// Passports reserved right now.
    pub in_use: u64,
    /// Requests refused because a worker had no free passport.
    pub refused: u64,
}

/// The passport pool. See the module docs.
pub struct PassportPool {
    shelves: Box<[Shelf]>,
    per_worker: u32,
    retain: usize,
    refused: AtomicU64,
}

impl PassportPool {
    /// Creates `per_worker` slots for each of `workers` workers, every buffer
    /// at its initial size. This is the only allocation the pool makes.
    #[must_use]
    pub fn new(workers: u16, per_worker: u32, sizes: SlotSizes) -> PassportPool {
        let workers = workers.max(1);
        let per_worker = per_worker.max(1);
        let shelves = (0..workers)
            .map(|w| Shelf {
                in_use: AtomicU32::new(0),
                free: Mutex::new(
                    (0..per_worker)
                        .map(|_| Box::new(Slot::new(w, &sizes)))
                        .collect(),
                ),
            })
            .collect();
        PassportPool {
            shelves,
            per_worker,
            retain: sizes.retain,
            refused: AtomicU64::new(0),
        }
    }

    /// The number of workers the pool has shelves for.
    #[must_use]
    pub fn workers(&self) -> u16 {
        u16::try_from(self.shelves.len()).unwrap_or(u16::MAX)
    }

    /// Passports per worker.
    #[must_use]
    pub fn per_worker(&self) -> u32 {
        self.per_worker
    }

    /// Admission: reserves one of `worker`'s passports. `false` means the
    /// worker is full (or unknown): refuse with 503 and take nothing.
    #[inline]
    #[must_use]
    pub fn admit(&self, worker: u16) -> bool {
        let Some(shelf) = self.shelves.get(usize::from(worker)) else {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let before = shelf.in_use.fetch_add(1, Ordering::AcqRel);
        if before >= self.per_worker {
            shelf.in_use.fetch_sub(1, Ordering::AcqRel);
            self.refused.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Ends a reservation made by [`admit`](Self::admit), exactly once per `true`.
    #[inline]
    pub fn release(&self, worker: u16) {
        if let Some(shelf) = self.shelves.get(usize::from(worker)) {
            // Saturating: a release without an admit is a caller bug and must
            // not wrap the counter into "full forever".
            let mut n = shelf.in_use.load(Ordering::Acquire);
            while n > 0 {
                match shelf.in_use.compare_exchange_weak(
                    n,
                    n - 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(now) => n = now,
                }
            }
        }
    }

    /// Takes a passport reserved by admission. `None` only when the caller
    /// takes more than it reserved.
    #[inline]
    #[must_use]
    pub fn take(&self, worker: u16) -> Option<Passport<Arrived>> {
        let shelf = self.shelves.get(usize::from(worker))?;
        let slot = shelf.free.lock().ok()?.pop()?;
        Some(Passport::from_slot(slot))
    }

    /// Admission and take in one call, for callers without a separate admission
    /// step (tests, benchmarks, other transports). Pair with
    /// [`give_back_and_release`](Self::give_back_and_release).
    #[inline]
    #[must_use]
    pub fn admit_and_take(&self, worker: u16) -> Option<Passport<Arrived>> {
        if !self.admit(worker) {
            return None;
        }
        let taken = self.take(worker);
        if taken.is_none() {
            self.release(worker);
        }
        taken
    }

    /// Wipes the passport (only what the request used) and puts it back on its
    /// home shelf. Callable from any thread.
    #[inline]
    pub fn give_back(&self, exit: Exit) {
        let mut slot = exit.into_slot();
        slot.wipe(self.retain);
        let home = usize::from(slot.home.worker);
        if let Some(shelf) = self.shelves.get(home)
            && let Ok(mut free) = shelf.free.lock()
        {
            free.push(slot);
        }
    }

    /// [`give_back`](Self::give_back) followed by [`release`](Self::release).
    #[inline]
    pub fn give_back_and_release(&self, exit: Exit) {
        let worker = exit.home_worker();
        self.give_back(exit);
        self.release(worker);
    }

    /// Counters. Not a hot path.
    #[must_use]
    pub fn stats(&self) -> PoolStats {
        let capacity = self.shelves.len() as u64 * u64::from(self.per_worker);
        let in_use = self
            .shelves
            .iter()
            .map(|s| u64::from(s.in_use.load(Ordering::Relaxed)))
            .sum();
        PoolStats {
            capacity,
            in_use,
            refused: self.refused.load(Ordering::Relaxed),
        }
    }
}

impl std::fmt::Debug for PassportPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassportPool")
            .field("workers", &self.shelves.len())
            .field("per_worker", &self.per_worker)
            .field("stats", &self.stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::customs::HeadRules;
    use crate::slot::{Lane, ProfileId, RequestId, ServiceTag, Trip};

    fn pool() -> PassportPool {
        PassportPool::new(2, 2, SlotSizes::default())
    }

    #[test]
    fn full_worker_refuses_and_release_frees() {
        let pool = pool();
        assert!(pool.admit(0));
        assert!(pool.admit(0));
        assert!(!pool.admit(0), "third admission on a two-slot worker");
        assert!(pool.admit(1), "the other worker has its own shelf");
        pool.release(0);
        assert!(pool.admit(0));
        assert_eq!(pool.stats().refused, 1);
    }

    #[test]
    fn unknown_worker_is_refused() {
        assert!(!pool().admit(9));
    }

    #[test]
    fn release_without_admit_does_not_wrap() {
        let pool = pool();
        pool.release(0);
        assert!(pool.admit(0) && pool.admit(0) && !pool.admit(0));
    }

    #[test]
    fn give_back_wipes_and_returns_home() {
        let pool = pool();
        let mut p = pool.admit_and_take(1).expect("a passport");
        p.set_trip(Trip {
            id: RequestId::new(),
            worker: 1,
            profile: ProfileId(0),
            service: ServiceTag(0),
            lane: Lane(4),
            ..Trip::empty()
        });
        p.head_mut().set_line("GET", "/secret", 1);
        p.head_mut().push_field("host", b"localhost");
        p.head_mut().push_field("cookie", b"sid=abc");
        p.body_mut().extend_from_slice(b"password=hunter2");
        let p = p.inspect(&HeadRules::default()).expect("inspected");
        pool.give_back_and_release(p.refuse(403));
        assert_eq!(pool.stats().in_use, 0);
        // The same slot comes back empty.
        let p = pool.admit_and_take(1).expect("a passport");
        assert_eq!(p.head().len_bytes(), 0);
        assert_eq!(p.head().field_count(), 0);
        assert_eq!(p.trip().ticket, 0);
        let exit = p.refuse(400);
        assert_eq!(exit.reply().status_code(), 400);
        pool.give_back_and_release(exit);
    }

    #[test]
    fn passports_cross_threads() {
        let pool = std::sync::Arc::new(pool());
        let p = pool.admit_and_take(0).expect("a passport");
        let pool2 = pool.clone();
        std::thread::spawn(move || pool2.give_back_and_release(p.refuse(500)))
            .join()
            .expect("thread");
        assert_eq!(pool.stats().in_use, 0);
    }
}
