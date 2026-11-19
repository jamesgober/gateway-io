//! Server time per request: from the head being complete to the reply being
//! handed to the transport, as serve-net reports it. A log-linear histogram of
//! atomics (four buckets per power of two, so a quantile is within 19%): one
//! relaxed add per request, no lock, no allocation.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serve_net::{Envelope, Finished, Observer, RequestEnd};

use crate::control::SHED_FROM;
use crate::load::LoadSignal;

const OCTAVES: usize = 40;
const SUB: usize = 4;
const BUCKETS: usize = OCTAVES * SUB;

/// The histogram: four buckets per power of two of nanoseconds.
#[derive(Debug)]
pub struct ServerTime {
    buckets: [AtomicU64; BUCKETS],
    total_ns: AtomicU64,
    count: AtomicU64,
    refused: AtomicU64,
}

impl Default for ServerTime {
    fn default() -> ServerTime {
        ServerTime {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            total_ns: AtomicU64::new(0),
            count: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }
}

/// A summary of [`ServerTime`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerTimeSummary {
    /// Requests answered.
    pub count: u64,
    /// Requests that ended in a refusal, a shed, or a denial.
    pub refused: u64,
    /// Mean server time.
    pub mean: Duration,
    /// Median, as the upper edge of its bucket.
    pub p50: Duration,
    /// 99th percentile, as the upper edge of its bucket.
    pub p99: Duration,
}

impl ServerTime {
    /// Records one request.
    #[inline]
    pub fn record(&self, took: Duration) {
        let ns = u64::try_from(took.as_nanos()).unwrap_or(u64::MAX).max(1);
        self.buckets[bucket(ns)].fetch_add(1, Ordering::Relaxed);
        self.total_ns.fetch_add(ns, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Clears every counter.
    pub fn reset(&self) {
        for b in &self.buckets {
            b.store(0, Ordering::Relaxed);
        }
        self.total_ns.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
        self.refused.store(0, Ordering::Relaxed);
    }

    /// The summary so far.
    #[must_use]
    pub fn summary(&self) -> ServerTimeSummary {
        let count = self.count.load(Ordering::Relaxed);
        let quantile = |q: f64| {
            let target = ((count as f64) * q).ceil() as u64;
            let mut seen = 0;
            for (i, b) in self.buckets.iter().enumerate() {
                seen += b.load(Ordering::Relaxed);
                if seen >= target.max(1) {
                    return Duration::from_nanos(upper_edge(i));
                }
            }
            Duration::ZERO
        };
        ServerTimeSummary {
            count,
            refused: self.refused.load(Ordering::Relaxed),
            mean: Duration::from_nanos(self.total_ns.load(Ordering::Relaxed) / count.max(1)),
            p50: if count == 0 {
                Duration::ZERO
            } else {
                quantile(0.50)
            },
            p99: if count == 0 {
                Duration::ZERO
            } else {
                quantile(0.99)
            },
        }
    }
}

/// The bucket of `ns` (at least 1).
#[inline]
fn bucket(ns: u64) -> usize {
    let octave = 63 - ns.leading_zeros() as usize;
    // The two bits after the leading one pick the quarter of the octave.
    let quarter = if octave >= 2 {
        ((ns >> (octave - 2)) & 3) as usize
    } else {
        0
    };
    (octave * SUB + quarter).min(BUCKETS - 1)
}

/// The exclusive upper edge of bucket `i`, in nanoseconds.
fn upper_edge(i: usize) -> u64 {
    let octave = (i / SUB) as u32;
    let quarter = (i % SUB) as u64;
    if octave < 2 {
        return 1u64 << (octave + 1);
    }
    let base = 1u64 << octave;
    base + (base / 4) * (quarter + 1)
}

/// serve-net's observer feeding a [`ServerTime`], and the load watch's
/// signal with the server time of browsing (the lanes `Shed` refuses).
#[derive(Clone, Debug, Default)]
pub struct TimeObserver {
    time: Arc<ServerTime>,
    load: Option<Arc<LoadSignal>>,
}

impl TimeObserver {
    /// An observer over this histogram.
    #[must_use]
    pub fn new(time: Arc<ServerTime>) -> TimeObserver {
        TimeObserver { time, load: None }
    }

    /// Also feeds the load watch's signal.
    #[must_use]
    pub fn with_load(mut self, load: Arc<LoadSignal>) -> TimeObserver {
        self.load = Some(load);
        self
    }
}

impl Observer for TimeObserver {
    #[inline]
    fn request_finished(&self, env: &Envelope, finished: &Finished) {
        match finished.end {
            RequestEnd::Replied => {
                if let Some(done) = finished.replied_at {
                    let took = done.saturating_duration_since(finished.head_at);
                    self.time.record(took);
                    if let Some(load) = &self.load
                        && env.lane().0 >= SHED_FROM.0
                    {
                        load.record(took);
                    }
                }
            }
            RequestEnd::Refused(_) | RequestEnd::Shed | RequestEnd::Denied => {
                self.time.refused.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_bound_their_values() {
        for ns in [
            1u64,
            2,
            3,
            4,
            5,
            7,
            8,
            1000,
            1023,
            1024,
            1279,
            1280,
            4095,
            123_456_789,
        ] {
            let b = bucket(ns);
            assert!(
                ns < upper_edge(b),
                "{ns} in bucket {b} edge {}",
                upper_edge(b)
            );
            if b > 0 {
                assert!(ns >= upper_edge(b - 1), "{ns} below bucket {b}");
            }
        }
    }

    #[test]
    fn summary_quantiles() {
        let t = ServerTime::default();
        for _ in 0..99 {
            t.record(Duration::from_nanos(1000));
        }
        t.record(Duration::from_micros(100));
        let s = t.summary();
        assert_eq!(s.count, 100);
        assert!(s.p50 >= Duration::from_nanos(1000) && s.p50 <= Duration::from_nanos(1280));
        assert!(s.p99 <= Duration::from_nanos(1280));
    }
}
