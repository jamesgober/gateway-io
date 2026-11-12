//! The bouncer: the door before a byte is read, a ticket per request, a
//! checkpoint between stages, and the egress check before every write.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bouncer_io::{
    Actor, AllowList, BanSpec, Bouncer, BouncerError, Cidr, CloseKind, ConnId, EJECTED, Ejector,
    EventSink, LiftSpec, Reason, TicketTag,
};
use net_io::{ConnectionId, ServerHandle};
use serve_net::{Checkpoint, CheckpointAt, Envelope, Verdict};

use crate::settings::Settings;

/// How long a ban from configuration lasts: until the configuration lifts
/// it (a year is the longest timed ban; a permanent one could not be lifted
/// by a reload as cleanly).
pub const CONFIG_BAN: Duration = Duration::from_secs(365 * 24 * 3600);

/// The allow list for `door.exempt`: addresses exempt from the door's
/// budgets (they can still be banned).
pub fn allow_list(exempt: &[IpAddr]) -> Result<AllowList, BouncerError> {
    let mut allow = AllowList::new();
    for addr in exempt {
        let bits = if addr.is_ipv4() { 32 } else { 128 };
        allow = allow.exempt_budgets(Cidr::new(*addr, bits)?, "door.exempt");
    }
    Ok(allow)
}

/// A ban from configuration, by the administrator.
pub fn ban(bouncer: &Bouncer, addr: IpAddr) -> Result<(), BouncerError> {
    bouncer
        .ban(
            BanSpec::address(addr)
                .for_duration(CONFIG_BAN)
                .by(Actor::Admin(0))
                .because(Reason::ADMIN),
        )
        .map(|_| ())
}

/// Lifts a ban from configuration. Nothing to lift is not an error.
pub fn lift(bouncer: &Bouncer, addr: IpAddr) -> Result<(), BouncerError> {
    match bouncer.lift(
        LiftSpec::key(addr)
            .by(Actor::Admin(0))
            .because(Reason::ADMIN),
    ) {
        Ok(_) | Err(BouncerError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Closes connections the bouncer ejects, on the transport it is attached
/// to. Unlike bouncer-io's own ejector it can be detached: the bouncer holds
/// the ejector, the transport's service holds the bouncer, so an attached
/// handle would keep the transport (and the core, and its stores) alive
/// after the door closed. The door detaches it when it closes.
#[derive(Default)]
pub struct DoorEjector {
    server: Mutex<Option<ServerHandle>>,
}

impl DoorEjector {
    /// Attaches the transport.
    pub fn attach(&self, server: ServerHandle) {
        if let Ok(mut s) = self.server.lock() {
            *s = Some(server);
        }
    }

    /// Detaches it: later ejections do nothing.
    pub fn detach(&self) {
        if let Ok(mut s) = self.server.lock() {
            s.take();
        }
    }
}

impl Ejector for DoorEjector {
    fn eject(&self, conn: ConnId, _kind: CloseKind) {
        if let (Ok(server), Some(id)) = (self.server.lock(), ConnectionId::new(conn.0))
            && let Some(server) = server.as_ref()
        {
            let _ = server.kill(id, EJECTED);
        }
    }
}

impl std::fmt::Debug for DoorEjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let attached = self.server.lock().map(|s| s.is_some()).unwrap_or(false);
        f.debug_struct("DoorEjector")
            .field("attached", &attached)
            .finish()
    }
}

/// Builds the process's bouncer from the settings: bans from configuration,
/// the exempt list, a maintainer thread, an ejector the gateway attaches to
/// the transport once it is bound, and the event sink (the log).
pub fn build(
    settings: &Settings,
    events: Option<Arc<dyn EventSink>>,
) -> Result<(Bouncer, Arc<DoorEjector>), BouncerError> {
    let ejector = Arc::new(DoorEjector::default());
    let mut builder = Bouncer::builder().maintainer(true).ejector(ejector.clone());
    if !settings.exempt.is_empty() {
        builder = builder.allow(allow_list(&settings.exempt)?);
    }
    if let Some(sink) = events {
        builder = builder.event_sink(sink);
    }
    let bouncer = builder.try_build()?;
    for addr in &settings.ban {
        ban(&bouncer, *addr)?;
    }
    Ok((bouncer, ejector))
}

/// serve-net's checkpoint hook, judged by the bouncer on the connection's tag:
/// after admission, before dispatch, and before the reply. Two atomic loads
/// while nothing is revoked.
#[derive(Clone)]
pub struct DoorCheckpoint {
    bouncer: Bouncer,
}

impl DoorCheckpoint {
    /// The checkpoint for this bouncer.
    #[must_use]
    pub fn new(bouncer: Bouncer) -> DoorCheckpoint {
        DoorCheckpoint { bouncer }
    }
}

impl Checkpoint for DoorCheckpoint {
    /// Judges the request's own ticket (its tag is the envelope's user word,
    /// written when the head was complete), or the connection's before that.
    #[inline]
    fn check(&self, env: &Envelope, _at: CheckpointAt) -> Verdict {
        let tag = match env.user_word() {
            0 => TicketTag::from(env.gate_tag()),
            word => TicketTag::from_raw(word),
        };
        match self.bouncer.egress(tag) {
            bouncer_io::Verdict::Deny(denial) => Verdict::Deny {
                status: denial.code.http_status(),
            },
            _ => Verdict::Pass,
        }
    }
}
