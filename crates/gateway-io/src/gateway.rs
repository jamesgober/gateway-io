//! Opening and closing the door.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bouncer_io::Bouncer;
use serve_net::{DrainReport, KeepAlive, Limits, ListenerSpec, Running, Server, Workers};
use wasp_core::suite::kernel::{Health, UrgentLine};
use wasp_core::suite::lifecycle::{Deadline, Failure, Link, Position, Subsystem};
use wasp_core::suite::log;
use wasp_core::{Core, PassportPool, SlotSizes};

use crate::bouncer::{self, DoorCheckpoint};
use crate::control::UrgentControl;
use crate::observe::{ServerTime, TimeObserver};
use crate::pipeline::{PassportAdmit, Pipeline};
use crate::settings::Settings;

/// Why the gateway did not open.
#[derive(Debug)]
pub struct OpenError(pub String);

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OpenError {}

/// The gateway's door, open: accepting.
pub struct Door {
    running: Running,
    pool: Arc<PassportPool>,
    bouncer: Bouncer,
    time: Arc<ServerTime>,
}

impl Door {
    /// Binds every listener with the door closed, then opens it: the last step
    /// of boot. `line` is the kernel's urgent line.
    pub fn open(core: Arc<Core>, settings: &Settings, line: UrgentLine) -> Result<Door, OpenError> {
        let pool = Arc::new(PassportPool::new(
            settings.workers,
            settings.passports,
            SlotSizes {
                body: 0,
                ..SlotSizes::default()
            },
        ));
        let (bouncer, ejector) =
            bouncer::build(settings).map_err(|e| OpenError(format!("bouncer: {e}")))?;

        let mut builder = Server::builder()
            .listener(
                ListenerSpec::tcp("web", settings.listen.as_str()).profile(serve_net::ProfileId(0)),
            )
            .limits(
                Limits::new()
                    .head_timeout(settings.head_timeout)
                    .max_body(settings.max_body),
            )
            .keep_alive(KeepAlive::new().max_requests(settings.keep_alive_requests))
            .workers(Workers::reactor(settings.workers))
            .drain_deadline(settings.drain)
            .catch_service_panics(true);
        for p in core.profiles() {
            builder = builder.profile(
                serve_net::Profile::new(serve_net::ProfileId(p.id.0))
                    .tag(p.service.0)
                    .lane(serve_net::Lane(p.lane.0))
                    .critical(p.critical)
                    .wipe_buffers(true),
            );
        }
        let time = Arc::new(ServerTime::default());
        let built = builder
            .observer(TimeObserver::new(time.clone()))
            .gate(bouncer.clone())
            .checkpoint(DoorCheckpoint::new(bouncer.clone()))
            .admit(PassportAdmit::new(pool.clone()))
            .control(Arc::new(UrgentControl::new(line)))
            .build()
            .map_err(|e| OpenError(format!("gateway configuration: {e}")))?;
        let bound = built
            .bind(Pipeline::new(core, pool.clone(), bouncer.clone()))
            .map_err(|e| OpenError(e.to_string()))?;
        let running = bound.open().map_err(|e| OpenError(e.to_string()))?;
        ejector.attach(running.server_handle());
        Ok(Door {
            running,
            pool,
            bouncer,
            time,
        })
    }

    /// The first listener's address.
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.running.local_addr()
    }

    /// The passport pool.
    #[must_use]
    pub fn pool(&self) -> &PassportPool {
        &self.pool
    }

    /// The process's bouncer (bans, revocations).
    #[must_use]
    pub fn bouncer(&self) -> &Bouncer {
        &self.bouncer
    }

    /// Server time per request (head complete to reply handed to the transport).
    #[must_use]
    pub fn server_time(&self) -> &ServerTime {
        &self.time
    }

    /// The transport's server, for health and statistics.
    pub fn running(&self) -> &Running {
        &self.running
    }

    /// Shutdown steps 1 and 2: the door closes, then in-flight requests drain
    /// until `deadline`; whatever is left is closed.
    pub fn close(self, deadline: Duration) -> DrainReport {
        self.running.close_door();
        self.running.drain(deadline)
    }
}

/// The gateway as a kernel subsystem, at [`Position::LAST`]: it opens after
/// everything else started and is stopped before anything else.
pub struct Gateway {
    core: Arc<Core>,
    open: Option<Door>,
    link: Option<Link>,
    drain: Duration,
}

impl Gateway {
    /// The gateway for this core.
    #[must_use]
    pub fn new(core: Arc<Core>) -> Gateway {
        Gateway {
            core,
            open: None,
            link: None,
            drain: Settings::default().drain,
        }
    }
}

impl Subsystem for Gateway {
    fn name(&self) -> &str {
        "gateway"
    }

    fn position(&self) -> Position {
        Position::LAST
    }

    fn start(&mut self, link: &Link) -> Result<(), Failure> {
        let settings = Settings::from_config(&link.foundation().config())?;
        let open = Door::open(self.core.clone(), &settings, link.urgent().clone())?;
        let addr = open
            .local_addr()
            .map_or_else(|| settings.listen.clone(), |a| a.to_string());
        let stats = open.pool().stats();
        log::info!(
            link.foundation().log(),
            "gateway open",
            listen = addr.as_str(),
            workers = u64::from(settings.workers),
            passports = stats.capacity,
            banned = settings.ban.len()
        );
        self.drain = settings.drain;
        self.open = Some(open);
        self.link = Some(link.clone());
        Ok(())
    }

    fn stop(&mut self, deadline: Deadline) -> Result<(), Failure> {
        let Some(open) = self.open.take() else {
            return Ok(());
        };
        // Keep a little of the kernel's deadline for the steps after this one.
        let budget = deadline
            .remaining()
            .saturating_sub(Duration::from_millis(500))
            .min(self.drain);
        let time = open.server_time().summary();
        let report = open.close(budget);
        if let Some(link) = &self.link {
            log::info!(
                link.foundation().log(),
                "gateway server time",
                requests = time.count,
                refused = time.refused,
                mean_ns = u64::try_from(time.mean.as_nanos()).unwrap_or(u64::MAX),
                p50_ns_below = u64::try_from(time.p50.as_nanos()).unwrap_or(u64::MAX),
                p99_ns_below = u64::try_from(time.p99.as_nanos()).unwrap_or(u64::MAX)
            );
            log::info!(
                link.foundation().log(),
                "gateway drained",
                graceful = u64::from(report.graceful),
                killed = u64::from(report.killed),
                finished = report.requests_finished,
                refused = report.refused_while_draining,
                elapsed_ms = u64::try_from(report.elapsed.as_millis()).unwrap_or(u64::MAX)
            );
        }
        Ok(())
    }

    fn health(&self) -> Health {
        match &self.open {
            Some(open) if open.running().health().is_ok() => Health::HEALTHY,
            Some(_) => Health::degraded("transport reports an issue"),
            None => Health::unhealthy("door closed"),
        }
    }
}
