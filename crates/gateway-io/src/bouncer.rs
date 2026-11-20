//! The bouncer: the door before a byte is read, a ticket per request, a
//! checkpoint between stages, and the egress check before every write.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bouncer_io::{
    Actor, AllowList, Bouncer, BouncerError, Budgets, Cidr, CloseKind, Directive, EJECTED, Ejector,
    EventSink, LaneClass, Rate, Reason, TicketTag,
};
use net_io::{ConnectionId, ServerHandle};
use serve_net::{Checkpoint, CheckpointAt, Envelope, Verdict};

use crate::settings::Settings;

/// How long a ban from configuration lasts: until the configuration lifts
/// it (a year is the longest timed ban; a permanent one could not be lifted
/// by a reload as cleanly).
pub const CONFIG_BAN: Duration = Duration::from_secs(365 * 24 * 3600);

/// The bouncer's lane for a core lane.
#[must_use]
pub fn lane_class(lane: wasp_core::Lane) -> LaneClass {
    match lane.0 {
        0 => LaneClass::Critical,
        1 => LaneClass::Admin,
        2 => LaneClass::Auth,
        3 => LaneClass::Write,
        4 => LaneClass::Normal,
        _ => LaneClass::Bulk,
    }
}

/// The door's budgets (bouncer-io's defaults) with the settings' lane
/// budgets.
fn budgets(settings: &Settings) -> Budgets {
    settings.lane_rates.iter().fold(Budgets::default(), |b, r| {
        let per_second = r.per_second.max(1);
        b.lane_rate(
            lane_class(r.lane),
            Rate::per_second(per_second).burst(r.burst.max(per_second)),
        )
    })
}

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
        .apply(
            Directive::ban(addr)
                .for_duration(CONFIG_BAN)
                .by(Actor::Admin(0))
                .because(Reason::ADMIN),
        )
        .map(|_| ())
}

/// Lifts a ban from configuration. Nothing to lift is not an error.
pub fn lift(bouncer: &Bouncer, addr: IpAddr) -> Result<(), BouncerError> {
    match bouncer.apply(
        Directive::lift(addr)
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
    fn eject(&self, conn: bouncer_io::ConnectionId, _kind: CloseKind) {
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
    let mut builder = Bouncer::builder()
        .maintainer(true)
        .ejector(ejector.clone())
        .budgets(budgets(settings));
    let proxies: Vec<Cidr> = settings
        .ingress
        .trusted()
        .into_iter()
        .map(Cidr::from)
        .collect();
    if !proxies.is_empty() {
        // The proxies are hops, not clients: the client each request names
        // is judged and charged instead (bound in the head hook).
        builder = builder.trusted_proxies(&proxies);
    }
    if !settings.exempt.is_empty() {
        builder = builder.allow(allow_list(&settings.exempt)?);
    }
    if let Some(sink) = events {
        builder = builder.event_sink(sink);
    }
    let bouncer = builder.build()?;
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
            // Over a lane's budget: the gateway already answered with its
            // own 429 and `Retry-After`, on a connection that stays open.
            bouncer_io::Verdict::Deny(denial)
                if denial.code != bouncer_io::DenialCode::TooManyRequests =>
            {
                Verdict::Deny {
                    status: denial.code.http_status(),
                }
            }
            _ => Verdict::Pass,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::LaneRate;
    use bouncer_io::RequestId;

    #[test]
    fn core_lanes_map_to_the_bouncer_s_and_budgets_are_per_caller() {
        let lanes = [
            LaneClass::Critical,
            LaneClass::Admin,
            LaneClass::Auth,
            LaneClass::Write,
            LaneClass::Normal,
            LaneClass::Bulk,
        ];
        for (i, want) in lanes.into_iter().enumerate() {
            let lane = wasp_core::Lane(u8::try_from(i).expect("lane"));
            assert_eq!(lane_class(lane), want);
        }
        assert_eq!(lane_class(wasp_core::Lane(9)), LaneClass::Bulk);

        let settings = Settings {
            lane_rates: vec![LaneRate {
                lane: wasp_core::Lane::BULK,
                per_second: 1,
                burst: 1,
            }],
            ..Settings::default()
        };
        let (bouncer, _) = build(&settings, None).expect("bouncer");
        let conn = bouncer
            .door("192.0.2.9".parse().expect("addr"))
            .expect("door");
        let key = |n: u8| bouncer_io::SessionKey::from_digest([n; 16]);
        let mut first = conn.request(RequestId(1)).expect("request");
        assert!(first.bind_session(key(1)).is_pass());
        assert!(first.bind_lane(LaneClass::Bulk).is_pass());
        let mut again = conn.request(RequestId(2)).expect("request");
        assert!(again.bind_session(key(1)).is_pass());
        assert!(
            again.bind_lane(LaneClass::Bulk).is_deny(),
            "the same caller, over"
        );
        let mut other = conn.request(RequestId(3)).expect("request");
        assert!(other.bind_session(key(2)).is_pass());
        assert!(other.bind_lane(LaneClass::Bulk).is_pass(), "another caller");
        let mut page = conn.request(RequestId(4)).expect("request");
        assert!(
            page.bind_lane(LaneClass::Normal).is_pass(),
            "no budget there"
        );
    }
}
