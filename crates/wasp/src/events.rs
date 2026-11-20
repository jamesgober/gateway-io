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

use std::cell::RefCell;
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
    #[cfg(feature = "store-nex")]
    Security(&'static str),
    #[cfg(feature = "store-nex")]
    Warn(String),
    #[cfg(feature = "store-nex")]
    Audit {
        by: String,
        action: &'static str,
        account: String,
    },
}

static QUEUE_TX: OnceLock<SyncSender<Line>> = OnceLock::new();

fn push(line: Line) {
    if let Some(tx) = QUEUE_TX.get() {
        let _ = tx.try_send(line);
    }
}

/// Writes every event to `foundation`'s log from now on: server failures
/// and panics at warn, a missing page at debug, other refusals, denials and
/// security events at info. The first call wins.
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
                        if kind == "failed" && status == 404 {
                            // A missing page (a browser's /favicon.ico, an
                            // old link) is not the site failing.
                            log::debug!(
                                f.log(),
                                "site",
                                event = kind,
                                reference = reference.as_str(),
                                route = route.as_str(),
                                status = u64::from(status),
                                code = code
                            );
                        } else if kind == "panicked" || (kind == "failed" && status >= 500) {
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
                    #[cfg(feature = "store-nex")]
                    Line::Security(what) => {
                        log::info!(f.log(), "security", event = what);
                    }
                    #[cfg(feature = "store-nex")]
                    Line::Warn(message) => {
                        log::warn!(f.log(), "store", detail = message.as_str());
                    }
                    #[cfg(feature = "store-nex")]
                    Line::Audit {
                        by,
                        action,
                        account,
                    } => {
                        log::info!(
                            f.log(),
                            "audit",
                            by = by.as_str(),
                            action = action,
                            account = account.as_str()
                        );
                    }
                }
            }
        });
}

/// A warning from a store while the process boots or runs (a database
/// another process holds), in the log.
#[cfg(feature = "store-nex")]
pub fn warn(message: String) {
    push(Line::Warn(message));
}

/// An account action, in the log as an `audit` line: who did it (an
/// email), what (`password_changed`, `signed_out_everywhere`,
/// `two_step_on`, `two_step_off`, `recovery_codes_made`,
/// `recovery_code_used`, `devices_forgotten`, `account_disabled`,
/// `account_enabled`, `account_removed`), and to which account.
#[cfg(feature = "store-nex")]
pub fn audit(by: &str, action: &'static str, account: &str) {
    push(Line::Audit {
        by: by.to_owned(),
        action,
        account: account.to_owned(),
    });
}

/// web-net's events, for the site's builder.
#[derive(Clone, Copy, Debug, Default)]
pub struct SiteEvents;

thread_local! {
    /// The reference of the request web-net just refused for its CSRF
    /// token, on this thread: web-net reports the refusal, then renders its
    /// error page on the same thread, and the page names no code.
    static EXPIRED_FORM: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Whether web-net refused the request `reference` names for its form's
/// token (expired, from before a key change, missing), so its error page
/// can say so instead of reading like a permissions error. Asked once.
pub fn form_expired(reference: &str) -> bool {
    EXPIRED_FORM.with(|r| {
        let mut r = r.borrow_mut();
        let hit = !r.is_empty() && *r == reference;
        r.clear();
        hit
    })
}

/// A refusal of the token itself, not of where the request came from (a
/// cross-site post stays a plain refusal).
fn token_refused(code: &str) -> bool {
    matches!(
        code,
        "csrf.missing"
            | "csrf.malformed"
            | "csrf.unknown_key"
            | "csrf.bad_mac"
            | "csrf.stale_session"
            | "csrf.expired"
            | "csrf.not_yet_valid"
            | "csrf.wrong_scope"
    )
}

impl web_net::Events for SiteEvents {
    fn event(&self, e: &web_net::Event<'_>) {
        if e.kind == web_net::EventKind::Denied && token_refused(e.code) {
            let reference = e.id.to_string();
            EXPIRED_FORM.with(|r| *r.borrow_mut() = reference);
        }
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
