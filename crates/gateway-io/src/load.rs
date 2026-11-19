//! The load watch: the gateway sheds browsing on its own when it is
//! overloaded, and stops once the load has passed.
//!
//! ```text
//!  every check (gateway.shed_check, default 250 ms):
//!    busy = passports in use >= gateway.shed_passports % of the pool (default 90)
//!    slow = the running average of browsing replies' server time
//!           >= gateway.shed_slow (default 1 s)
//!    busy or slow twice in a row, the line at Normal  ─▶ Shed
//!    calm eight times in a row (passports 10 points under the mark,
//!    the average under half of shed_slow)            ─▶ Normal
//!    the average halves at each reading with no reply and nothing in flight
//! ```
//!
//! Under `Shed` the transport refuses lanes 4 and up before admission, so
//! health checks, the administrator, and sign-in keep being served (G-48).
//! The watch only moves the line between `Normal` and `Shed`, and only lowers
//! a `Shed` it raised itself: a level the operator, the memory watch, or the
//! security package set stays theirs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use wasp_core::PassportPool;
use wasp_core::suite::kernel::{Level, UrgentLine};

/// Busy or slow readings in a row before the line is raised.
const PRESSED_READINGS: u8 = 2;
/// Calm readings in a row before the line is lowered again.
const CALM_READINGS: u8 = 8;
/// How far under the passport mark calm is, in percentage points.
const CALM_MARGIN: u8 = 10;

const RAISE_REASON: &str = "the gateway is overloaded";
const CLEAR_REASON: &str = "the gateway's load has passed";

/// What the watch looks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShedMarks {
    /// Busy at this share of the passports in use, in percent; 0 turns the
    /// passport reading off.
    pub passports: u8,
    /// Slow at this running average of browsing replies' server time; zero
    /// turns the time reading off.
    pub slow: Duration,
}

impl ShedMarks {
    /// Whether either reading is on.
    #[must_use]
    pub fn on(&self) -> bool {
        self.passports > 0 || !self.slow.is_zero()
    }
}

/// Server time of browsing replies, as the transport reports them: a running
/// average (each reply counts an eighth) and how many came since the last
/// reading. One load and two stores per reply; a lost update under a race
/// only nudges the average.
#[derive(Debug, Default)]
pub struct LoadSignal {
    average_us: AtomicU64,
    replies: AtomicU64,
}

impl LoadSignal {
    /// A browsing reply's server time.
    #[inline]
    pub fn record(&self, server_time: Duration) {
        let x = u64::try_from(server_time.as_micros()).unwrap_or(u64::MAX);
        let old = self.average_us.load(Ordering::Relaxed);
        let new = old - old / 8 + x / 8;
        self.average_us.store(new, Ordering::Relaxed);
        self.replies.fetch_add(1, Ordering::Relaxed);
    }

    /// The running average now. With no reply since the last reading and
    /// nothing in flight (`idle`) it halves, so a quiet gateway reads as
    /// calm; long requests still running keep it where it is.
    fn read(&self, idle: bool) -> Duration {
        let average = if self.replies.swap(0, Ordering::Relaxed) == 0 && idle {
            let old = self.average_us.load(Ordering::Relaxed);
            self.average_us.store(old / 2, Ordering::Relaxed);
            old / 2
        } else {
            self.average_us.load(Ordering::Relaxed)
        };
        Duration::from_micros(average)
    }
}

/// One look at the gateway's load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reading {
    /// Passports in use, in percent of the pool.
    pub(crate) busy: u8,
    /// The running average of browsing replies' server time.
    pub(crate) average: Duration,
}

/// The watch's state between readings.
#[derive(Debug)]
pub(crate) struct Watch {
    marks: ShedMarks,
    /// The epoch of the change this watch made, while it holds the line.
    held: Option<u64>,
    pressed: u8,
    calm: u8,
}

impl Watch {
    pub(crate) fn new(marks: ShedMarks) -> Watch {
        Watch {
            marks,
            held: None,
            pressed: 0,
            calm: 0,
        }
    }

    /// Acts on one reading.
    pub(crate) fn step(&mut self, reading: Reading, line: &UrgentLine) {
        let busy = self.marks.passports > 0 && reading.busy >= self.marks.passports;
        let slow = !self.marks.slow.is_zero() && reading.average >= self.marks.slow;
        let Some(epoch) = self.held else {
            self.pressed = if busy || slow { self.pressed + 1 } else { 0 };
            if self.pressed >= PRESSED_READINGS {
                self.pressed = 0;
                self.held = line.shift(Level::Normal, Level::Shed, RAISE_REASON).ok();
            }
            return;
        };
        if line.epoch() != epoch {
            // Someone else changed the line since: it is theirs now.
            self.held = None;
            self.calm = 0;
            return;
        }
        let calm_busy = self.marks.passports == 0
            || reading.busy < self.marks.passports.saturating_sub(CALM_MARGIN);
        let calm_slow = self.marks.slow.is_zero() || reading.average < self.marks.slow / 2;
        self.calm = if calm_busy && calm_slow {
            self.calm + 1
        } else {
            0
        };
        if self.calm >= CALM_READINGS {
            self.release(line);
        }
    }

    /// Lowers the line if this watch still holds it.
    pub(crate) fn release(&mut self, line: &UrgentLine) {
        if let Some(epoch) = self.held.take()
            && line.epoch() == epoch
        {
            let _ = line.shift(Level::Shed, Level::Normal, CLEAR_REASON);
        }
        self.calm = 0;
    }

    /// Whether the line is held at `Shed` by this watch.
    #[cfg(test)]
    pub(crate) fn holds(&self) -> bool {
        self.held.is_some()
    }
}

/// Passports in use, in percent of the pool, and whether none is.
fn busy(pool: &PassportPool) -> (u8, bool) {
    let stats = pool.stats();
    if stats.capacity == 0 {
        return (0, stats.in_use == 0);
    }
    let percent = u8::try_from(stats.in_use.saturating_mul(100) / stats.capacity).unwrap_or(100);
    (percent, stats.in_use == 0)
}

/// The watch's thread, stopped when the door closes.
pub(crate) struct Watcher {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}

impl Watcher {
    /// Starts the watch, or nothing when both readings are off.
    pub(crate) fn start(
        marks: ShedMarks,
        every: Duration,
        line: UrgentLine,
        pool: Arc<PassportPool>,
        signal: Arc<LoadSignal>,
    ) -> std::io::Result<Option<Watcher>> {
        if !marks.on() {
            return Ok(None);
        }
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("wasp-load".into())
            .spawn(move || {
                let mut watch = Watch::new(marks);
                let (lock, wake) = &*flag;
                let mut stopped = lock.lock().unwrap_or_else(PoisonError::into_inner);
                loop {
                    let (guard, _) = wake
                        .wait_timeout(stopped, every)
                        .unwrap_or_else(PoisonError::into_inner);
                    stopped = guard;
                    if *stopped {
                        break;
                    }
                    let (busy, idle) = busy(&pool);
                    let reading = Reading {
                        busy,
                        average: signal.read(idle),
                    };
                    watch.step(reading, &line);
                }
                drop(stopped);
                watch.release(&line);
            })?;
        Ok(Some(Watcher {
            stop,
            thread: Some(thread),
        }))
    }

    /// Stops the watch; a `Shed` it holds is lowered.
    pub(crate) fn stop(&mut self) {
        let (lock, wake) = &*self.stop;
        *lock.lock().unwrap_or_else(PoisonError::into_inner) = true;
        wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MARKS: ShedMarks = ShedMarks {
        passports: 90,
        slow: Duration::from_millis(100),
    };

    fn at(busy: u8, ms: u64) -> Reading {
        Reading {
            busy,
            average: Duration::from_millis(ms),
        }
    }

    #[test]
    fn sheds_after_two_pressed_readings_and_clears_after_eight_calm() {
        let line = UrgentLine::detached();
        let mut watch = Watch::new(MARKS);
        watch.step(at(95, 0), &line);
        assert_eq!(line.level(), Level::Normal, "one reading is not enough");
        watch.step(at(0, 0), &line);
        watch.step(at(0, 150), &line);
        assert_eq!(line.level(), Level::Normal, "the run was broken");
        watch.step(at(0, 150), &line);
        assert_eq!(line.level(), Level::Shed);
        assert!(watch.holds());

        // Under the mark but not under the calm margin: still held.
        for _ in 0..20 {
            watch.step(at(85, 0), &line);
        }
        assert_eq!(line.level(), Level::Shed);
        for _ in 0..7 {
            watch.step(at(10, 10), &line);
        }
        assert_eq!(line.level(), Level::Shed);
        watch.step(at(10, 60), &line);
        assert_eq!(line.level(), Level::Shed, "60 ms is over half the mark");
        for _ in 0..8 {
            watch.step(at(10, 10), &line);
        }
        assert_eq!(line.level(), Level::Normal);
        assert!(!watch.holds());
    }

    #[test]
    fn never_lowers_a_level_someone_else_set() {
        let line = UrgentLine::detached();
        let mut watch = Watch::new(MARKS);
        line.set(Level::Shed, "operator").expect("set");
        for _ in 0..4 {
            watch.step(at(99, 999), &line);
        }
        assert!(!watch.holds(), "the line was not at Normal");
        for _ in 0..20 {
            watch.step(at(0, 0), &line);
        }
        assert_eq!(line.level(), Level::Shed, "the operator's shed stays");

        // Raised by the watch, then raised further by someone else.
        let line = UrgentLine::detached();
        let mut watch = Watch::new(MARKS);
        watch.step(at(99, 0), &line);
        watch.step(at(99, 0), &line);
        assert_eq!(line.level(), Level::Shed);
        line.set(Level::Lockdown, "security").expect("set");
        for _ in 0..20 {
            watch.step(at(0, 0), &line);
        }
        watch.release(&line);
        assert_eq!(line.level(), Level::Lockdown);
    }

    #[test]
    fn readings_that_are_off_never_shed() {
        let line = UrgentLine::detached();
        let mut watch = Watch::new(ShedMarks {
            passports: 0,
            slow: Duration::ZERO,
        });
        for _ in 0..10 {
            watch.step(at(100, 60_000), &line);
        }
        assert_eq!(line.level(), Level::Normal);
    }

    #[test]
    fn the_average_follows_replies_and_halves_when_quiet() {
        let signal = LoadSignal::default();
        for _ in 0..40 {
            signal.record(Duration::from_millis(80));
        }
        let busy = signal.read(true);
        assert!(busy > Duration::from_millis(75), "{busy:?}");
        assert_eq!(signal.read(false), busy, "a long request still running");
        assert_eq!(signal.read(true).as_micros(), busy.as_micros() / 2, "quiet");
    }
}
