//! The access log: one line per request, written off the worker.
//!
//! ```text
//!  head hook:  "GET /posts/hello" kept with the request's ticket
//!  done:       the line, the status, bytes, server time, client, how it ended
//!              ─▶ a bounded queue (full: dropped and counted, never waited for)
//!  one thread: the queue ─▶ the foundation's log ("access", at info)
//! ```
//!
//! The query string is never written: it can carry tokens and personal
//! data, and the path is what an operator reads the log for. A request
//! refused before its head was kept (a banned source, a revoked ticket)
//! is written with `-` for the method and path.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::time::Duration;

use serve_net::{Envelope, Finished, RequestEnd};
use wasp_core::suite::Foundation;
use wasp_core::suite::log;

/// Lines waiting to be written, at most.
pub const QUEUE: usize = 4096;

/// The longest path kept, in bytes; a longer one is cut at a character
/// boundary and ends with `...`.
pub const MAX_PATH: usize = 256;

/// One request, as the access log writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessEntry {
    /// The method and the path (no query), or `-` when the head was never
    /// kept.
    pub method: Box<str>,
    /// The path, without the query.
    pub path: Box<str>,
    /// The status written, if any.
    pub status: Option<u16>,
    /// How the request ended (`replied`, `shed`, `refused`, `denied`,
    /// `timed_out`, `peer_gone`, `drained`, `killed`, `panic`, `dropped`,
    /// `upgraded`).
    pub end: &'static str,
    /// Reply bytes handed to the transport.
    pub bytes_out: u64,
    /// From the head being complete to the reply handed to the transport.
    pub server_time: Option<Duration>,
    /// The client (behind a trusted proxy, the one it names).
    pub client: Option<IpAddr>,
    /// Lines dropped since the last one written because the queue was full.
    pub dropped: u64,
}

/// The request line kept from the head hook to the end of the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Line {
    method: Box<str>,
    path: Box<str>,
}

impl Line {
    pub(crate) fn new(method: &str, path: &str) -> Line {
        Line {
            method: method.into(),
            path: cut(path).into(),
        }
    }
}

/// `path` at most [`MAX_PATH`] bytes, cut at a character boundary.
fn cut(path: &str) -> std::borrow::Cow<'_, str> {
    if path.len() <= MAX_PATH {
        return path.into();
    }
    let mut end = MAX_PATH - 3;
    while !path.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &path[..end]).into()
}

fn end_name(end: RequestEnd) -> &'static str {
    match end {
        RequestEnd::Replied => "replied",
        RequestEnd::Refused(_) => "refused",
        RequestEnd::Shed => "shed",
        RequestEnd::Denied => "denied",
        RequestEnd::TimedOut => "timed_out",
        RequestEnd::PeerGone => "peer_gone",
        RequestEnd::Drained => "drained",
        RequestEnd::Killed => "killed",
        RequestEnd::ServicePanic => "panic",
        RequestEnd::Dropped => "dropped",
        RequestEnd::Upgraded => "upgraded",
        _ => "other",
    }
}

/// The access log's queue and its writer thread. See the module docs.
pub struct AccessLog {
    tx: SyncSender<AccessEntry>,
    dropped: Arc<AtomicU64>,
}

impl AccessLog {
    /// Writes every line to the foundation's log.
    pub fn spawn(foundation: Foundation) -> std::io::Result<Arc<AccessLog>> {
        AccessLog::with_writer(move |e| {
            let method = e.method.as_ref();
            let path = e.path.as_ref();
            let client = e.client.map(|a| a.to_string()).unwrap_or_default();
            let micros = e
                .server_time
                .map_or(0, |t| u64::try_from(t.as_micros()).unwrap_or(u64::MAX));
            log::info!(
                foundation.log(),
                "access",
                method = method,
                path = path,
                status = u64::from(e.status.unwrap_or(0)),
                end = e.end,
                bytes = e.bytes_out,
                micros = micros,
                client = client.as_str(),
                dropped = e.dropped
            );
        })
    }

    /// Hands every line to `write`, on the log's own thread. The thread ends
    /// when the log is dropped.
    pub fn with_writer(
        write: impl Fn(&AccessEntry) + Send + 'static,
    ) -> std::io::Result<Arc<AccessLog>> {
        let (tx, rx) = mpsc::sync_channel::<AccessEntry>(QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let lost = dropped.clone();
        std::thread::Builder::new()
            .name("gateway-access-log".into())
            .spawn(move || {
                let mut reported = 0;
                while let Ok(mut e) = rx.recv() {
                    let now = lost.load(Ordering::Relaxed);
                    e.dropped = now - reported;
                    reported = now;
                    write(&e);
                }
            })?;
        Ok(Arc::new(AccessLog { tx, dropped }))
    }

    /// Lines dropped because the queue was full, so far.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Queues the line of a finished request.
    pub(crate) fn finished(&self, line: Option<Line>, env: &Envelope, finished: &Finished) {
        let (method, path) = match line {
            Some(l) => (l.method, l.path),
            None => ("-".into(), "-".into()),
        };
        let entry = AccessEntry {
            method,
            path,
            status: finished.status,
            end: end_name(finished.end),
            bytes_out: finished.bytes_out,
            server_time: finished
                .replied_at
                .map(|r| r.saturating_duration_since(finished.head_at)),
            client: env.client().addr(),
            dropped: 0,
        };
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = self.tx.try_send(entry)
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for AccessLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessLog")
            .field("dropped", &self.dropped())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_paths_are_cut_at_a_character_boundary() {
        assert_eq!(cut("/short"), "/short");
        let long = format!("/{}", "é".repeat(400));
        let c = cut(&long);
        assert!(c.len() <= MAX_PATH, "{}", c.len());
        assert!(c.ends_with("..."));
        assert!(c.starts_with("/é"));
    }
}
