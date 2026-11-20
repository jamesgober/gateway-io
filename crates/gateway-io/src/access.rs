//! The access log and the log rules: lines per request, written off the
//! worker.
//!
//! ```text
//!  head hook:  "GET /posts/hello" (and what the rules ask for: the query,
//!              the user agent, the referrer) kept with the request's ticket
//!  call ends:  what the service noted (its error code, a message, the
//!              request's reference, the account) kept with it
//!  done:       the entry, with the status, bytes, server time, client, how
//!              it ended ─▶ a bounded queue (full: dropped and counted,
//!              never waited for)
//!  one thread: the queue ─▶ the foundation's log ("access", at info, when
//!              `gateway.access_log` is on) and every matching log rule
//!              (see [`crate::rules`])
//! ```
//!
//! The access line never has the query string: it can carry tokens and
//! personal data, and the path is what an operator reads the log for; a log
//! rule writes it only with `include_query`. A request refused before its
//! head was kept (a banned source, a revoked ticket) is written with `-`
//! for the method and path.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serve_net::{Envelope, Finished, RequestEnd};

use crate::rules::{LogRules, LogRulesCell, Wants};
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
    /// The query, when a log rule asked for it.
    pub query: Option<Box<str>>,
    /// The `User-Agent` header, when a log rule asked for it.
    pub user_agent: Option<Box<str>>,
    /// The `Referer` header, when a log rule asked for it.
    pub referrer: Option<Box<str>>,
    /// The application's error code the service noted, or empty.
    pub code: &'static str,
    /// The message the service noted, or empty.
    pub message: Box<str>,
    /// The request's reference the service noted, or empty.
    pub request: Box<str>,
    /// The signed-in account, when there was one.
    pub user: Option<u128>,
}

/// The request line kept from the head hook to the end of the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Line {
    method: Box<str>,
    path: Box<str>,
    query: Option<Box<str>>,
    user_agent: Option<Box<str>>,
    referrer: Option<Box<str>>,
    note: Option<crate::note::Note>,
}

impl Line {
    pub(crate) fn new(method: &str, path: &str) -> Line {
        Line {
            method: method.into(),
            path: cut(path).into(),
            query: None,
            user_agent: None,
            referrer: None,
            note: None,
        }
    }

    /// The line of `head`, with what `wants` asks for.
    pub(crate) fn of(head: &serve_net::HttpHead<'_>, wants: Wants) -> Line {
        let header = |name: &str| {
            head.header_str(name)
                .map(|v| crate::note::cut(v, crate::rules::MAX_HEADER).into())
        };
        Line {
            query: wants
                .query
                .then(|| {
                    head.query()
                        .map(|q| crate::note::cut(q, crate::rules::MAX_QUERY).into())
                })
                .flatten(),
            user_agent: wants.user_agent.then(|| header("user-agent")).flatten(),
            referrer: wants.referrer.then(|| header("referer")).flatten(),
            ..Line::new(head.method_str(), head.path())
        }
    }

    /// What the service noted about the request.
    pub(crate) fn set_note(&mut self, note: crate::note::Note) {
        self.note = Some(note);
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
    /// Whether anything is written at all: the access line or a rule.
    wanted: AtomicBool,
    /// What the head hook keeps for the rules ([`Wants`] as bits).
    wants: AtomicU8,
    rules: LogRulesCell,
}

impl AccessLog {
    /// Writes the access line to the foundation's log when `access` is on
    /// (`gateway.access_log`), and every line `rules` asks for.
    pub fn spawn(
        foundation: Foundation,
        access: bool,
        rules: LogRules,
    ) -> std::io::Result<Arc<AccessLog>> {
        let cell: LogRulesCell = Arc::new(RwLock::new(Arc::new(rules)));
        let mut writer = crate::rules::Writer::new(cell.clone());
        let f = foundation.clone();
        let log = AccessLog::start(
            move |e| {
                if access {
                    access_line(&f, e);
                }
                writer.write(Some(f.log()), e);
            },
            cell,
        )?;
        log.wanted
            .store(access || log.has_rules(), Ordering::Relaxed);
        Ok(log)
    }

    /// Puts `rules` in force (a reload).
    pub fn set_rules(&self, rules: LogRules, access: bool) {
        let wants = rules.wants();
        let any = !rules.is_empty();
        *self
            .rules
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(rules);
        self.wants.store(bits(wants), Ordering::Relaxed);
        self.wanted.store(access || any, Ordering::Relaxed);
    }

    fn has_rules(&self) -> bool {
        !self
            .rules
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    /// What the head hook keeps, or `None` when nothing is written.
    pub(crate) fn capture(&self) -> Option<Wants> {
        if !self.wanted.load(Ordering::Relaxed) {
            return None;
        }
        let b = self.wants.load(Ordering::Relaxed);
        Some(Wants {
            query: b & 1 != 0,
            user_agent: b & 2 != 0,
            referrer: b & 4 != 0,
        })
    }

    /// Hands every line to `write`, on the log's own thread, with no rules.
    /// The thread ends when the log is dropped.
    pub fn with_writer(
        write: impl FnMut(&AccessEntry) + Send + 'static,
    ) -> std::io::Result<Arc<AccessLog>> {
        AccessLog::start(write, Arc::default())
    }

    /// Hands every line to `write` on the log's own thread, then writes the
    /// lines `rules` asks for (a file destination; a `log` one is skipped
    /// without a foundation). For tests and tools.
    pub fn with_writer_and_rules(
        mut write: impl FnMut(&AccessEntry) + Send + 'static,
        rules: LogRules,
    ) -> std::io::Result<Arc<AccessLog>> {
        let wants = rules.wants();
        let cell: LogRulesCell = Arc::new(RwLock::new(Arc::new(rules)));
        let mut writer = crate::rules::Writer::new(cell.clone());
        let log = AccessLog::start(
            move |e| {
                write(e);
                writer.write(None, e);
            },
            cell,
        )?;
        log.wants.store(bits(wants), Ordering::Relaxed);
        Ok(log)
    }

    fn start(
        mut write: impl FnMut(&AccessEntry) + Send + 'static,
        rules: LogRulesCell,
    ) -> std::io::Result<Arc<AccessLog>> {
        let wants = bits(
            rules
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .wants(),
        );
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
        Ok(Arc::new(AccessLog {
            tx,
            dropped,
            wanted: AtomicBool::new(true),
            wants: AtomicU8::new(wants),
            rules,
        }))
    }

    /// Lines dropped because the queue was full, so far.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Queues the line of a finished request.
    pub(crate) fn finished(&self, line: Option<Line>, env: &Envelope, finished: &Finished) {
        if !self.wanted.load(Ordering::Relaxed) {
            return;
        }
        let line = line.unwrap_or_else(|| Line::new("-", "-"));
        let note = line.note.unwrap_or_default();
        let entry = AccessEntry {
            method: line.method,
            path: line.path,
            query: line.query,
            user_agent: line.user_agent,
            referrer: line.referrer,
            code: note.code,
            message: note.message,
            request: note.reference,
            user: note.user,
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

/// The access line, in the foundation's log.
fn access_line(foundation: &Foundation, e: &AccessEntry) {
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
}

fn bits(w: Wants) -> u8 {
    u8::from(w.query) | u8::from(w.user_agent) << 1 | u8::from(w.referrer) << 2
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
