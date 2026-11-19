//! What the site and its stores report, in the log: web-net's refusals and
//! failures (with the reference a visitor's error page shows) and nex-db's
//! security events (failed sign-ins, lockouts).
//!
//! ```text
//!  web-net Events, nex-db Observer ─▶ a bounded queue (full: dropped)
//!  one thread (started by `connect`): the queue ─▶ the foundation's log
//! ```
//!
//! Until [`connect`] runs (tests, tools) every event is dropped.

use std::sync::OnceLock;
use std::sync::mpsc::{self, SyncSender};

use wasp_core::suite::Foundation;
use wasp_core::suite::log;

/// Events waiting to be written, at most.
const QUEUE: usize = 1024;

/// One event, owned.
#[derive(Debug)]
enum Line {
    Site {
        kind: &'static str,
        reference: String,
        route: String,
        status: u16,
        code: &'static str,
        cause: String,
    },
    Security(&'static str),
}

static QUEUE_TX: OnceLock<SyncSender<Line>> = OnceLock::new();

fn push(line: Line) {
    if let Some(tx) = QUEUE_TX.get() {
        let _ = tx.try_send(line);
    }
}

/// Writes every event to `foundation`'s log from now on: failures at warn,
/// refusals, denials and security events at info. The first call wins.
pub fn connect(foundation: &Foundation) {
    let (tx, rx) = mpsc::sync_channel::<Line>(QUEUE);
    if QUEUE_TX.set(tx).is_err() {
        return;
    }
    let f = foundation.clone();
    let _ = std::thread::Builder::new()
        .name("wasp-events".into())
        .spawn(move || {
            while let Ok(line) = rx.recv() {
                match line {
                    Line::Site {
                        kind,
                        reference,
                        route,
                        status,
                        code,
                        cause,
                    } => {
                        if kind == "failed" || kind == "panicked" {
                            log::warn!(
                                f.log(),
                                "site",
                                event = kind,
                                reference = reference.as_str(),
                                route = route.as_str(),
                                status = u64::from(status),
                                code = code,
                                cause = cause.as_str()
                            );
                        } else {
                            log::info!(
                                f.log(),
                                "site",
                                event = kind,
                                reference = reference.as_str(),
                                route = route.as_str(),
                                status = u64::from(status),
                                code = code
                            );
                        }
                    }
                    Line::Security(what) => {
                        log::info!(f.log(), "security", event = what);
                    }
                }
            }
        });
}

/// web-net's events, for the site's builder.
#[derive(Clone, Copy, Debug, Default)]
pub struct SiteEvents;

impl web_net::Events for SiteEvents {
    fn event(&self, e: &web_net::Event<'_>) {
        if QUEUE_TX.get().is_none() {
            return;
        }
        let kind = match e.kind {
            web_net::EventKind::Refused => "refused",
            web_net::EventKind::Denied => "denied",
            web_net::EventKind::Failed => "failed",
            web_net::EventKind::Panicked => "panicked",
            web_net::EventKind::Revoked => "revoked",
            _ => "other",
        };
        push(Line::Site {
            kind,
            reference: e.id.to_string(),
            route: e.route.unwrap_or("").to_owned(),
            status: e.status,
            code: e.code,
            cause: e.source.map(ToString::to_string).unwrap_or_default(),
        });
    }
}

/// nex-db's security events, for the database's builder.
#[cfg(feature = "store-nex")]
#[derive(Clone, Copy, Debug, Default)]
pub struct StoreEvents;

#[cfg(feature = "store-nex")]
impl nex_db::Observer for StoreEvents {
    fn on_security_event(&self, event: &nex_db::SecurityEvent) {
        use nex_db::SecurityEvent as S;
        let what = match event {
            S::SignInFailed { .. } => "sign_in_failed",
            S::LockedOut { .. } => "locked_out",
            S::SignInBlocked => "sign_in_blocked",
            S::RevokedSessionPresented => "revoked_session_presented",
            S::CanaryRequested => "canary_requested",
            S::DecoyPresented => "decoy_presented",
            _ => "other",
        };
        push(Line::Security(what));
    }
}
