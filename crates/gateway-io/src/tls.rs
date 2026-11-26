//! TLS termination (G-90): tls-net (rustls, ring) on net-io's TLS seam.
//!
//! The certificate and key are read at start (a bad pair refuses to open),
//! checked again every `tls.reload` and loaded when either changed, and
//! loaded on a configuration reload. A pair that fails to load leaves the
//! one serving in place. ALPN offers `h2` then `http/1.1`; the policy is
//! tls-net's `compatible` (TLS 1.3 and 1.2, AEAD and ECDHE only).

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use crate::settings::TlsSettings;

/// The largest certificate chain file read.
const MAX_CHAIN: u64 = 1 << 20;

/// A certificate with fewer days left than this is warned about.
pub const WARN_DAYS: i64 = 14;

/// What a load of the certificate and key came to, for the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsNote {
    /// Loaded: its last day, and how many days are left.
    Loaded {
        /// When the certificate stops being valid (seconds since 1970).
        not_after: u64,
        /// Whole days left.
        days_left: i64,
        /// Whether this was a reload.
        reload: bool,
    },
    /// A new pair could not be loaded; the one serving stays.
    Refused(String),
}

/// Where load notes go (the log).
pub type TlsNotes = Arc<dyn Fn(TlsNote) + Send + Sync>;

/// The gateway's TLS acceptor: the server when TLS is on. Without it no
/// listener is TLS, so it is never asked for a session.
#[derive(Clone)]
pub(crate) struct DoorTls(pub(crate) Option<tls_net::TlsServer>);

impl net_io::TlsAcceptor for DoorTls {
    type Session = tls_net::ServerSession;

    fn session(&self, info: &net_io::ConnectionInfo) -> Result<Self::Session, net_io::TlsError> {
        match &self.0 {
            Some(server) => server.session(info),
            None => Err(net_io::TlsError::new(
                net_io::TlsFailure::Handshake,
                0,
                None,
            )),
        }
    }
}

/// The key must be its owner's alone: no other account may read it (or
/// change it). tls-net checks the mode on Unix; this checks on every
/// system, Windows' ACLs too.
fn check_key(key: &Path) -> Result<(), String> {
    wasp_core::suite::path::check_owner_private(key).map_err(|e| {
        format!(
            "tls.key {}: {e}; make it readable by this account only",
            key.display()
        )
    })
}

/// Reads the chain, with a size cap.
fn read_chain(cert: &Path) -> Result<Vec<u8>, String> {
    let shown = cert.display();
    let meta = std::fs::metadata(cert).map_err(|e| format!("tls.cert {shown}: {e}"))?;
    if meta.len() > MAX_CHAIN {
        return Err(format!("tls.cert {shown} is over 1 MiB"));
    }
    std::fs::read(cert).map_err(|e| format!("tls.cert {shown}: {e}"))
}

/// The TLS server for `settings`: the files read and checked now.
///
/// # Errors
///
/// When the key may be read by others, a file cannot be read, or the pair
/// does not load (the reason names which).
pub(crate) fn load(settings: &TlsSettings) -> Result<tls_net::TlsServer, String> {
    check_key(&settings.key)?;
    let chain = read_chain(&settings.cert)?;
    tls_net::TlsServer::builder()
        .policy(tls_net::Policy::compatible())
        .alpn(&[tls_net::Alpn::H2, tls_net::Alpn::HTTP_1_1])
        .certificate(&chain, tls_net::KeySource::File(&settings.key))
        .and_then(tls_net::ServerBuilder::build)
        .map_err(|e| {
            format!(
                "tls.cert {} with tls.key {}: {e}",
                settings.cert.display(),
                settings.key.display()
            )
        })
}

/// What a load of `server` came to, for the log.
pub(crate) fn note(server: &tls_net::TlsServer, reload: bool) -> TlsNote {
    let report = server.expiry_report(SystemTime::now());
    let first = report.entries.first();
    TlsNote::Loaded {
        not_after: first.map_or(0, |c| {
            c.not_after
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        }),
        days_left: first.map_or(0, |c| c.days_remaining),
        reload,
    }
}

/// Loads the files again into `server`: the old pair stays when they do
/// not load.
pub(crate) fn reload(server: &tls_net::TlsServer, settings: &TlsSettings) -> TlsNote {
    let tried = check_key(&settings.key).and_then(|()| {
        server
            .reload_from_files(&settings.cert, &settings.key)
            .map_err(|e| format!("{e}"))
    });
    match tried {
        Ok(()) => note(server, true),
        Err(why) => TlsNote::Refused(why),
    }
}

/// When the certificate or key file last changed.
fn stamp(settings: &TlsSettings) -> Option<(SystemTime, SystemTime)> {
    let at = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    Some((at(&settings.cert)?, at(&settings.key)?))
}

/// Checks the files every `settings.reload` and loads them when either
/// changed. Stops when dropped.
pub(crate) struct Watcher {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watcher {
    pub(crate) fn start(
        server: tls_net::TlsServer,
        settings: TlsSettings,
        notes: Option<TlsNotes>,
    ) -> std::io::Result<Option<Watcher>> {
        if settings.reload.is_zero() {
            return Ok(None);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::Builder::new()
            .name("gateway-tls-reload".into())
            .spawn(move || {
                let mut seen = stamp(&settings);
                loop {
                    std::thread::park_timeout(settings.reload);
                    if flag.load(Ordering::Acquire) {
                        return;
                    }
                    let now = stamp(&settings);
                    if now.is_some() && now != seen {
                        seen = now;
                        // A pair written in two steps: give the second file
                        // a moment to land.
                        std::thread::sleep(Duration::from_millis(200));
                        let n = reload(&server, &settings);
                        if let Some(notes) = &notes {
                            notes(n);
                        }
                    }
                }
            })?;
        Ok(Some(Watcher {
            stop,
            thread: Some(thread),
        }))
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            t.thread().unpark();
            let _ = t.join();
        }
    }
}
