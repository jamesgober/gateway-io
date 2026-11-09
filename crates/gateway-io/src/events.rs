//! The door's decisions in the log.
//!
//! bouncer-io reports every action (a banned source refused, a ban added or
//! lifted, an egress blocked, a revocation) as an [`Event`] on the thread that
//! acted, and the sink must not block. [`LogSink`] copies the fixed-size facts
//! into a bounded channel and returns; one thread writes them to the
//! foundation's log. When the channel is full an event is dropped and counted,
//! never waited for, and the count goes out with the next event that is
//! written. Floods are already sampled by bouncer-io (one refusal per ban per
//! 10 s, with the count since the last).

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};

use bouncer_io::{Event, EventSink, Mode, SignalId};
use wasp_core::suite::Foundation;
use wasp_core::suite::log;

/// Events waiting to be written, at most.
pub const QUEUE: usize = 1024;

/// The facts of one event, copied off the acting thread.
#[derive(Clone, Copy, Debug)]
struct DoorEvent {
    signal: SignalId,
    path: &'static str,
    severity: f32,
    count: u32,
    observe: bool,
    source: Option<IpAddr>,
}

/// bouncer-io's event sink into the foundation's log. See the module docs.
#[derive(Debug)]
pub struct LogSink {
    tx: SyncSender<DoorEvent>,
    dropped: Arc<AtomicU64>,
}

impl LogSink {
    /// The sink and its writer thread. The thread ends when the sink is
    /// dropped (with the bouncer that holds it).
    pub fn spawn(foundation: Foundation) -> std::io::Result<Arc<LogSink>> {
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let lost = dropped.clone();
        std::thread::Builder::new()
            .name("gateway-door-log".into())
            .spawn(move || write_all(&foundation, &rx, &lost))?;
        Ok(Arc::new(LogSink { tx, dropped }))
    }

    /// Events dropped because the queue was full, so far.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl EventSink for LogSink {
    #[inline]
    fn event(&self, e: &Event<'_>) {
        let copy = DoorEvent {
            signal: e.signal,
            path: e.path,
            severity: e.severity,
            count: e.count,
            observe: matches!(e.mode, Mode::Observe),
            source: e.subject.source,
        };
        match self.tx.try_send(copy) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn write_all(foundation: &Foundation, rx: &Receiver<DoorEvent>, dropped: &AtomicU64) {
    let mut reported = 0;
    while let Ok(e) = rx.recv() {
        let lost = dropped.load(Ordering::Relaxed);
        let lost_since = lost - reported;
        reported = lost;
        let signal = e.signal.to_string();
        let source = e.source.map(|a| a.to_string()).unwrap_or_default();
        let logger = foundation.log();
        if e.severity >= 3.0 {
            log::warn!(
                logger,
                "door",
                event = e.path,
                signal = signal.as_str(),
                source = source.as_str(),
                count = u64::from(e.count),
                observe = e.observe,
                dropped = lost_since
            );
        } else {
            log::info!(
                logger,
                "door",
                event = e.path,
                signal = signal.as_str(),
                source = source.as_str(),
                count = u64::from(e.count),
                observe = e.observe,
                dropped = lost_since
            );
        }
    }
}
