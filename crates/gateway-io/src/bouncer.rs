//! The bouncer: the door before a byte is read, a ticket per request, a
//! checkpoint between stages, and the egress check before every write.

use std::sync::Arc;
use std::time::Duration;

use bouncer_io::{AllowList, Bouncer, BouncerError, Cidr, NetIoEjector, TicketTag};
use serve_net::{Checkpoint, CheckpointAt, Envelope, Verdict};

use crate::settings::Settings;

/// Builds the process's bouncer from the settings: bans from configuration,
/// the exempt list, a maintainer thread, and an ejector the gateway attaches
/// to the transport once it is bound.
pub fn build(settings: &Settings) -> Result<(Bouncer, Arc<NetIoEjector>), BouncerError> {
    let ejector = Arc::new(NetIoEjector::new());
    let mut builder = Bouncer::builder().maintainer(true).ejector(ejector.clone());
    if !settings.exempt.is_empty() {
        let mut allow = AllowList::new();
        for addr in &settings.exempt {
            let bits = if addr.is_ipv4() { 32 } else { 128 };
            allow = allow.exempt_budgets(Cidr::new(*addr, bits)?, "door.exempt");
        }
        builder = builder.allow(allow);
    }
    let bouncer = builder.try_build()?;
    for addr in &settings.ban {
        bouncer.ban(
            bouncer_io::BanSpec::address(*addr)
                .for_duration(Duration::from_secs(365 * 24 * 3600))
                .by(bouncer_io::Actor::Admin(0))
                .because(bouncer_io::Reason::ADMIN),
        )?;
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
