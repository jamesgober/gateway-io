//! WebSockets through the gateway (G-81).
//!
//! serve-net switches a connection in the service's `head`, before
//! admission and the body, and never calls `call` for it. So the gateway
//! decides there: it fills a passport from the head, runs customs, asks the
//! core to authenticate only, and asks the request's web service whether
//! the path is one of its WebSocket routes and the caller may open it
//! ([`WebService::upgrade`](crate::WebService::upgrade)).
//!
//! While a connection is open the gateway keeps it honest:
//!
//! - the upgrade's bouncer ticket stays alive, bound to the account and to
//!   the session or key, so every message passes the checkpoint and a
//!   revocation with eject-now ([`Revoker`]) closes it even when it is idle;
//! - every `ws.recheck` the upgrade head is authenticated again, and a
//!   connection whose caller changed, is suspended, or may no longer use
//!   the route is closed;
//! - each connection has a message budget, and each account at most
//!   `ws.per_account` connections.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use bouncer_io::{Bouncer, Directive, Ticket};
use serve_net::{Envelope, HttpHead, Version};
pub use serve_net::{WebSocketConn, WebSocketService, WsMessage, WsSendError, WsSender};
use wasp_core::{
    Core, Decision, Identity, Lane, PassportPool, ProfileId, RequestId, Routed, Rule, ServiceTag,
    Standing, Subject, Trip,
};

use crate::web::Caller;

/// What a web service answers to a request that offers a WebSocket upgrade.
pub enum Upgrade {
    /// No WebSocket route at this path: the request goes on as HTTP.
    NotHere,
    /// Refused with this status (401, 403, 404); nothing is switched.
    Refuse(u16),
    /// Switch to this service.
    Accept(WsAccept),
}

impl std::fmt::Debug for Upgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Upgrade::NotHere => f.write_str("NotHere"),
            Upgrade::Refuse(s) => write!(f, "Refuse({s})"),
            Upgrade::Accept(_) => f.write_str("Accept(..)"),
        }
    }
}

/// An accepted upgrade: the service that talks on the connection, the web
/// pages that may open it, and the access rule its caller must keep passing
/// for as long as it is open.
pub struct WsAccept {
    /// The conversation.
    pub service: Arc<dyn WebSocketService>,
    /// Which pages may open it (`Origin`), checked before the 101.
    pub origins: ws_net::OriginPolicy,
    /// The route's rule, checked again at every recheck.
    pub rule: Rule,
}

/// The `[ws]` settings: sizes, keepalive, budgets, and how often an open
/// connection's caller is checked again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WsSettings {
    /// The largest frame, in bytes (`ws.max_frame`, default 64 KiB).
    pub max_frame: u64,
    /// The largest message, in bytes (`ws.max_message`, default 256 KiB).
    pub max_message: u64,
    /// A ping after this much quiet; a second one with no byte back closes
    /// the connection (`ws.ping`, default 30 s).
    pub ping: Duration,
    /// Open connections per account (`ws.per_account`, default 8; 0 for no
    /// cap).
    pub per_account: u32,
    /// Messages a second per connection (`ws.rate`, default 20; 0 for no
    /// budget).
    pub rate: u32,
    /// The most messages at once after a quiet spell (`ws.burst`, default
    /// twice the rate).
    pub burst: u32,
    /// How often an open connection's caller is authenticated again
    /// (`ws.recheck`, default 15 s).
    pub recheck: Duration,
}

impl Default for WsSettings {
    fn default() -> WsSettings {
        WsSettings {
            max_frame: 64 * 1024,
            max_message: 256 * 1024,
            ping: Duration::from_secs(30),
            per_account: 8,
            rate: 20,
            burst: 40,
            recheck: Duration::from_secs(15),
        }
    }
}

/// How long one message may take, first byte to last.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an upgrade that passed `head` may wait for its connection to
/// open before its record goes.
const PENDING_FOR: Duration = Duration::from_secs(60);

/// Ends open WebSockets (and running requests) when an account, a session
/// or an API key is revoked: the application calls it on those events. Until
/// the gateway opens it does nothing.
///
/// It ends the connections themselves, each by its own connection id, never
/// by revoking the account's or the session's key in the bouncer: a bind is
/// checked against every revocation of its key until the bouncer clears it,
/// so a key revocation would also refuse the account's next connection for a
/// while, which is a ban, not a revocation.
#[derive(Clone, Default)]
pub struct Revoker(Arc<OnceLock<Weak<WsHub>>>);

impl std::fmt::Debug for Revoker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Revoker")
            .field("attached", &self.0.get().is_some())
            .finish()
    }
}

impl Revoker {
    /// A revoker the gateway is attached to when it opens.
    #[must_use]
    pub fn new() -> Revoker {
        Revoker::default()
    }

    /// Connects it to the open gateway: from now on it ends connections
    /// there.
    pub fn attach_to(&self, door: &crate::Door) {
        let _ = self.0.set(Arc::downgrade(door.ws_hub()));
    }

    fn hub(&self) -> Option<Arc<WsHub>> {
        self.0.get().and_then(Weak::upgrade)
    }

    /// Every open WebSocket of `account` ends now, idle or not: disabled,
    /// banned, removed, password changed, signed out everywhere.
    pub fn account(&self, account: u128) {
        if let Some(hub) = self.hub() {
            hub.eject_where(|l| account_of(&l.identity) == Some(account));
        }
    }

    /// What one session or API key opened ends now, by the id the
    /// authenticator gave it (the identity's session id).
    pub fn session(&self, session: u128) {
        if let Some(hub) = self.hub() {
            hub.eject_where(|l| l.identity.session() == Some(wasp_core::SessionId(session)));
        }
    }
}

/// A head the gateway can fill a passport from: the live one in `head`, or
/// an owned copy kept for the recheck.
pub(crate) trait HeadSource {
    fn method_str(&self) -> &str;
    fn target(&self) -> &str;
    fn version(&self) -> Version;
    fn for_each_field(&self, f: &mut dyn FnMut(&str, &[u8]));
}

impl HeadSource for HttpHead<'_> {
    fn method_str(&self) -> &str {
        HttpHead::method_str(self)
    }
    fn target(&self) -> &str {
        HttpHead::target(self)
    }
    fn version(&self) -> Version {
        HttpHead::version(self)
    }
    fn for_each_field(&self, f: &mut dyn FnMut(&str, &[u8])) {
        for (name, value) in self.headers() {
            f(name, value);
        }
    }
}

/// An owned copy of a request head, kept with an open connection for the
/// recheck.
pub(crate) struct OwnedHead {
    method: String,
    target: String,
    version: Version,
    fields: Vec<(String, Vec<u8>)>,
}

impl OwnedHead {
    pub(crate) fn of(head: &HttpHead<'_>) -> OwnedHead {
        OwnedHead {
            method: head.method_str().to_owned(),
            target: head.target().to_owned(),
            version: head.version(),
            fields: head
                .headers()
                .map(|(n, v)| (n.to_owned(), v.to_vec()))
                .collect(),
        }
    }
}

impl HeadSource for OwnedHead {
    fn method_str(&self) -> &str {
        &self.method
    }
    fn target(&self) -> &str {
        &self.target
    }
    fn version(&self) -> Version {
        self.version
    }
    fn for_each_field(&self, f: &mut dyn FnMut(&str, &[u8])) {
        for (name, value) in &self.fields {
            f(name, value);
        }
    }
}

/// What authenticating a head found.
pub(crate) enum Identified {
    /// The identity; the closure ran with the caller and gave its answer.
    Caller(Identity, Upgrade),
    /// Refused with this status (customs, a ban, the store unavailable).
    Refused(u16),
}

/// Fills a passport for the request in `env` from `head`, runs customs and
/// authentication only, and hands the caller to `decide` while the passport
/// is out; the passport goes back before this returns.
pub(crate) fn identify(
    core: &Core,
    pool: &PassportPool,
    env: &Envelope,
    head: &dyn HeadSource,
    decide: &mut dyn FnMut(&Caller<'_>) -> Upgrade,
) -> Identified {
    let worker = env.worker().get();
    let Some(mut p) = pool.admit_and_take(worker) else {
        return Identified::Refused(503);
    };
    p.set_trip(Trip {
        id: RequestId::new(),
        conn: env.connection().get(),
        seq: env.seq().get(),
        worker,
        profile: ProfileId(env.profile().0),
        service: ServiceTag(env.tag()),
        lane: Lane(env.lane().0),
        client: env.client().addr(),
        arrived: env.arrived(),
        deadline: env.deadline(),
        ticket: env.user_word(),
    });
    let minor = match head.version() {
        Version::Http10 => 0,
        _ => 1,
    };
    let slot = p.head_mut();
    slot.set_line(head.method_str(), head.target(), minor);
    head.for_each_field(&mut |name, value| slot.push_field(name, value));
    let p = match p.inspect(core.customs()) {
        Ok(p) => p,
        Err(refused) => {
            let status = refused.reply().status_code();
            pool.give_back_and_release(refused);
            return Identified::Refused(status);
        }
    };
    match core.authenticate(p) {
        Routed::Handoff(h) => {
            let identity = *h.identity();
            let answer = decide(&Caller::new(h.identity(), h.token_any()));
            pool.give_back_and_release(h.finish());
            Identified::Caller(identity, answer)
        }
        Routed::Exit(exit) => {
            let status = exit.reply().status_code();
            pool.give_back_and_release(exit);
            Identified::Refused(status)
        }
    }
}

/// An upgrade that passed `head`, waiting for its connection to open.
struct Pending {
    at: Instant,
    head: Arc<OwnedHead>,
    identity: Identity,
    rule: Rule,
    ticket: Option<Ticket>,
}

/// An open connection.
struct Live {
    env: Envelope,
    head: Arc<OwnedHead>,
    identity: Identity,
    rule: Rule,
    /// Bound to the account and session: the checkpoint every message
    /// passes, and what an eject-now finds. Dropped when the connection ends.
    ticket: Option<Ticket>,
}

/// The gateway's open WebSockets.
pub(crate) struct WsHub {
    pub(crate) settings: WsSettings,
    core: Arc<Core>,
    pool: Arc<PassportPool>,
    bouncer: Bouncer,
    pending: Mutex<HashMap<u64, Pending>>,
    live: Mutex<HashMap<u64, Live>>,
    accounts: Mutex<HashMap<u128, u32>>,
    /// Dropped with the hub: the recheck thread then stops.
    _stop: Sender<()>,
}

impl std::fmt::Debug for WsHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsHub")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn account_of(identity: &Identity) -> Option<u128> {
    match identity.subject() {
        Subject::User(u) => Some(u.0),
        Subject::Guest => None,
    }
}

impl WsHub {
    /// The hub, and its recheck thread (which stops when the hub goes).
    pub(crate) fn start(
        settings: WsSettings,
        core: Arc<Core>,
        pool: Arc<PassportPool>,
        bouncer: Bouncer,
    ) -> std::io::Result<Arc<WsHub>> {
        let (stop, wait) = channel();
        let every = settings.recheck;
        let hub = Arc::new(WsHub {
            settings,
            core,
            pool,
            bouncer,
            pending: Mutex::new(HashMap::new()),
            live: Mutex::new(HashMap::new()),
            accounts: Mutex::new(HashMap::new()),
            _stop: stop,
        });
        let weak = Arc::downgrade(&hub);
        std::thread::Builder::new()
            .name("gateway-ws-recheck".into())
            .spawn(move || recheck_loop(&weak, &wait, every))?;
        Ok(hub)
    }

    /// Whether `identity`'s account has room for one more connection.
    pub(crate) fn has_room(&self, identity: &Identity) -> bool {
        let cap = self.settings.per_account;
        match account_of(identity) {
            Some(a) if cap > 0 => lock(&self.accounts).get(&a).copied().unwrap_or(0) < cap,
            _ => true,
        }
    }

    /// Records an upgrade `head` accepted, for request ticket `tag`.
    pub(crate) fn pend(&self, tag: u64, head: OwnedHead, identity: Identity, rule: Rule) {
        let mut pending = lock(&self.pending);
        pending.retain(|_, p| p.at.elapsed() < PENDING_FOR);
        pending.insert(
            tag,
            Pending {
                at: Instant::now(),
                head: Arc::new(head),
                identity,
                rule,
                ticket: None,
            },
        );
    }

    /// Whether request ticket `tag` is an upgrade waiting to open.
    pub(crate) fn is_pending(&self, tag: u64) -> bool {
        lock(&self.pending).contains_key(&tag)
    }

    /// The upgrade request is done: its ticket stays alive with the record.
    pub(crate) fn keep_ticket(&self, tag: u64, ticket: Ticket) {
        if let Some(p) = lock(&self.pending).get_mut(&tag) {
            p.ticket = Some(ticket);
        }
    }

    /// The connection opened: `false` when its account has no room left
    /// (it is closed at once).
    fn open(&self, tag: u64, env: &Envelope) -> bool {
        let Some(p) = lock(&self.pending).remove(&tag) else {
            return false;
        };
        if let Some(a) = account_of(&p.identity) {
            let mut accounts = lock(&self.accounts);
            let n = accounts.entry(a).or_insert(0);
            if self.settings.per_account > 0 && *n >= self.settings.per_account {
                return false;
            }
            *n += 1;
        }
        lock(&self.live).insert(
            tag,
            Live {
                env: env.clone(),
                head: p.head,
                identity: p.identity,
                rule: p.rule,
                ticket: p.ticket,
            },
        );
        true
    }

    /// The connection ended: its ticket goes, and its account's place.
    fn close(&self, tag: u64) {
        let Some(live) = lock(&self.live).remove(&tag) else {
            return;
        };
        if let Some(a) = account_of(&live.identity) {
            let mut accounts = lock(&self.accounts);
            if let Some(n) = accounts.get_mut(&a) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    accounts.remove(&a);
                }
            }
        }
    }

    /// Open connections (for tests and health).
    #[must_use]
    pub(crate) fn open_count(&self) -> usize {
        lock(&self.live).len()
    }

    /// Authenticates every open connection's head again, and closes the ones
    /// whose caller changed, holds other permissions, is suspended, or fails
    /// the route's rule now.
    fn recheck_all(&self) {
        let open: Vec<(u64, Envelope, Arc<OwnedHead>, Identity, Rule)> = lock(&self.live)
            .iter()
            .map(|(tag, l)| (*tag, l.env.clone(), Arc::clone(&l.head), l.identity, l.rule))
            .collect();
        for (tag, env, head, was, rule) in open {
            let found = identify(&self.core, &self.pool, &env, &*head, &mut |_| {
                Upgrade::NotHere
            });
            let keep = match found {
                Identified::Caller(now, _) => {
                    // Changed permissions end it too: the service read what
                    // they allowed when it opened.
                    now.subject() == was.subject()
                        && now.perms() == was.perms()
                        && now.standing() == Standing::Good
                        && matches!(self.core.access().check(&now, &rule), Decision::Allow)
                }
                // The store cannot answer, or the pool is busy: ask again
                // next time rather than end a connection on a guess.
                Identified::Refused(503) => true,
                Identified::Refused(_) => false,
            };
            if !keep {
                self.eject(tag);
            }
        }
    }

    /// Ends every open connection `which` picks, now.
    fn eject_where(&self, which: impl Fn(&Live) -> bool) {
        let tags: Vec<u64> = lock(&self.live)
            .iter()
            .filter(|(_, l)| which(l))
            .map(|(t, _)| *t)
            .collect();
        for tag in tags {
            self.eject(tag);
        }
    }

    /// Ends connection `tag` now, idle or not.
    fn eject(&self, tag: u64) {
        let connection = lock(&self.live)
            .get(&tag)
            .and_then(|l| l.ticket.as_ref().map(Ticket::connection));
        if let Some(c) = connection {
            let _ = self.bouncer.apply(Directive::revoke(c).eject_now());
        }
    }
}

fn recheck_loop(hub: &Weak<WsHub>, stop: &Receiver<()>, every: Duration) {
    loop {
        match stop.recv_timeout(every) {
            Err(RecvTimeoutError::Timeout) => {}
            _ => return,
        }
        let Some(hub) = hub.upgrade() else {
            return;
        };
        hub.recheck_all();
    }
}

/// A token bucket: `rate` a second, at most `burst`.
struct Bucket {
    tokens: f64,
    at: Instant,
    rate: f64,
    burst: f64,
}

impl Bucket {
    fn new(rate: u32, burst: u32) -> Bucket {
        Bucket {
            tokens: f64::from(burst),
            at: Instant::now(),
            rate: f64::from(rate),
            burst: f64::from(burst),
        }
    }

    /// Takes one message's place: `false` when over the budget.
    fn take(&mut self) -> bool {
        if self.rate <= 0.0 {
            return true;
        }
        let now = Instant::now();
        let refill = now.duration_since(self.at).as_secs_f64() * self.rate;
        self.at = now;
        self.tokens = (self.tokens + refill).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The gateway around a site's WebSocket service, for one connection: the
/// account's room, the message budget, and the record the recheck reads.
pub(crate) struct GatewayWs {
    hub: Arc<WsHub>,
    inner: Arc<dyn WebSocketService>,
    tag: u64,
    bucket: Mutex<Bucket>,
    opened: AtomicBool,
}

impl GatewayWs {
    pub(crate) fn new(hub: Arc<WsHub>, inner: Arc<dyn WebSocketService>, tag: u64) -> GatewayWs {
        let bucket = Bucket::new(hub.settings.rate, hub.settings.burst);
        GatewayWs {
            hub,
            inner,
            tag,
            bucket: Mutex::new(bucket),
            opened: AtomicBool::new(false),
        }
    }

    /// The serve-net target for this connection.
    pub(crate) fn target(self, origins: ws_net::OriginPolicy) -> serve_net::WebSocketTarget {
        let s = &self.hub.settings;
        let limits = ws_net::Limits::new()
            .with_max_frame(s.max_frame)
            .with_max_message(s.max_message);
        let ping = s.ping;
        serve_net::WebSocketTarget::new(self)
            .limits(limits)
            .ping_interval(ping)
            .message_timeout(MESSAGE_TIMEOUT)
            .origins(origins)
    }
}

impl WebSocketService for GatewayWs {
    fn opened(&self, env: &Envelope, conn: &mut WebSocketConn<'_>) {
        if !self.hub.open(self.tag, env) {
            let _ = conn.close(1008, "too many connections");
            return;
        }
        self.opened.store(true, Ordering::Release);
        self.inner.opened(env, conn);
    }

    fn message(&self, env: &Envelope, message: WsMessage<'_>, conn: &mut WebSocketConn<'_>) {
        if !self.opened.load(Ordering::Acquire) {
            return;
        }
        if !lock(&self.bucket).take() {
            let _ = conn.close(1008, "too many messages");
            return;
        }
        self.inner.message(env, message, conn);
    }

    fn closed(&self, env: &Envelope, code: Option<u16>) {
        if self.opened.swap(false, Ordering::AcqRel) {
            self.inner.closed(env, code);
            self.hub.close(self.tag);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_gives_its_burst_then_its_rate() {
        let mut b = Bucket::new(1, 3);
        assert!(b.take() && b.take() && b.take());
        assert!(!b.take(), "the burst is spent");
        b.at -= Duration::from_secs(2);
        assert!(b.take() && b.take());
        assert!(!b.take());
        let mut free = Bucket::new(0, 0);
        assert!((0..1000).all(|_| free.take()), "no budget");
    }
}
