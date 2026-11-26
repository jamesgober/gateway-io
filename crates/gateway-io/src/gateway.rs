//! Opening and closing the door.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bouncer_io::{Bouncer, EventSink};
use serve_net::{DrainReport, KeepAlive, Limits, ListenerSpec, Running, Server, Workers};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::{Health, UrgentLine};
use wasp_core::suite::lifecycle::{Commit, Deadline, Failure, Link, Position, Subsystem};
use wasp_core::suite::log;
use wasp_core::{Core, PassportPool, SlotSizes};

use crate::access::AccessLog;
use crate::bouncer::{self, DoorCheckpoint};
use crate::control::UrgentControl;
use crate::events::LogSink;
use crate::load::{LoadSignal, Watcher};
use crate::observe::{ServerTime, TimeObserver};
use crate::pipeline::{PassportAdmit, Pipeline};
use crate::settings::{Driver, IngressMode, Settings};
use crate::stages::StageTimes;
use crate::tickets::RequestTickets;
use crate::web::{WebService, WebServices};

/// Why the gateway did not open.
#[derive(Debug)]
pub struct OpenError(pub String);

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OpenError {}

/// What [`Door::open_with`] can add to a plain open.
#[derive(Clone, Default)]
pub struct Extras {
    /// Where the bouncer's events go (the log).
    pub events: Option<Arc<dyn EventSink>>,
    /// Stage timing (`gateway.stage_timing`).
    pub stages: Option<Arc<StageTimes>>,
    /// A line per request (`gateway.access_log`).
    pub access: Option<Arc<AccessLog>>,
    /// Where TLS loads and reloads are told (the log).
    #[cfg(feature = "tls")]
    pub tls_notes: Option<crate::tls::TlsNotes>,
}

impl std::fmt::Debug for Extras {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extras")
            .field("events", &self.events.is_some())
            .field("stages", &self.stages.as_ref().map(|s| s.enabled()))
            .finish()
    }
}

/// The gateway's door, open: accepting.
pub struct Door {
    stages: Arc<StageTimes>,
    tickets: Arc<RequestTickets>,
    running: Running,
    pool: Arc<PassportPool>,
    bouncer: Bouncer,
    time: Arc<ServerTime>,
    ejector: Arc<bouncer::DoorEjector>,
    /// The load watch, while it runs.
    load: Option<Watcher>,
    /// The open WebSockets.
    ws: Arc<crate::ws::WsHub>,
    /// The TLS server and its settings, when TLS is on.
    #[cfg(feature = "tls")]
    tls: Option<(tls_net::TlsServer, crate::settings::TlsSettings)>,
    /// Checks the certificate files for a change.
    #[cfg(feature = "tls")]
    _tls_watch: Option<crate::tls::Watcher>,
}

impl Door {
    /// Binds every listener with the door closed, then opens it: the last step
    /// of boot. `line` is the kernel's urgent line; `web` holds a web service
    /// for every external service the core declares (a missing one refuses to
    /// open).
    pub fn open(
        core: Arc<Core>,
        settings: &Settings,
        line: UrgentLine,
        web: WebServices,
    ) -> Result<Door, OpenError> {
        Door::open_with(core, settings, line, web, Extras::default())
    }

    /// [`open`](Self::open), with the bouncer's events and stage timing.
    pub fn open_with(
        core: Arc<Core>,
        settings: &Settings,
        line: UrgentLine,
        web: WebServices,
        extras: Extras,
    ) -> Result<Door, OpenError> {
        let Extras {
            events,
            stages,
            access,
            #[cfg(feature = "tls")]
            tls_notes,
        } = extras;
        // TLS: what it needs, then the certificate, read now so a bad pair
        // refuses to open.
        if let Some(t) = &settings.tls {
            if cfg!(not(feature = "tls")) {
                return Err(OpenError(
                    "tls.enabled needs a build with the `tls` feature".into(),
                ));
            }
            if matches!(settings.ingress, IngressMode::Proxy { .. }) {
                return Err(OpenError(
                    "tls.enabled with gateway.ingress = \"proxy\": the proxy in front terminates TLS; turn one of them off".into(),
                ));
            }
            if settings.listen.starts_with(crate::settings::UNIX_PREFIX) {
                return Err(OpenError(
                    "tls.enabled needs an address to listen on, not a Unix socket".into(),
                ));
            }
            let _ = t;
        }
        #[cfg(feature = "tls")]
        let tls = match &settings.tls {
            Some(t) => {
                let server = crate::tls::load(t).map_err(OpenError)?;
                if let Some(notes) = &tls_notes {
                    notes(crate::tls::note(&server, false));
                }
                Some((server, t.clone()))
            }
            None => None,
        };
        let stages = stages.unwrap_or_else(|| Arc::new(StageTimes::new(false)));
        for (tag, name) in core.external_services() {
            if web.get(tag).is_none() {
                return Err(OpenError(format!(
                    "service `{name}` is external but no web service is attached for it"
                )));
            }
        }
        // A blocking worker is one connection's thread: one request at a time.
        // serve-net runs `workers` threads for connections plus a headroom of
        // threads that answer the connections over the cap; every one of
        // them needs a shelf, so both numbers are set here, not derived.
        let mut limits = Limits::new()
            .head_timeout(settings.head_timeout)
            .max_body(settings.max_body);
        let (threads, per_worker) = match settings.driver {
            Driver::Reactor => (settings.workers, settings.passports),
            Driver::Blocking => {
                let headroom = (settings.workers / 8).max(16);
                limits = limits
                    .max_connections(u32::from(settings.workers))
                    .hard_cap_headroom(u32::from(headroom));
                (settings.workers.saturating_add(headroom), 1)
            }
        };
        let tickets = Arc::new(RequestTickets::new(threads));
        // Health checks, the administrator, and sign-in keep passports a
        // flood of browsing cannot take.
        let pool = Arc::new(
            PassportPool::new(
                threads,
                per_worker,
                SlotSizes {
                    body: 0,
                    ..SlotSizes::default()
                },
            )
            .with_reserve(settings.reserve_for(per_worker)),
        );
        let (bouncer, ejector) =
            bouncer::build(settings, events).map_err(|e| OpenError(format!("bouncer: {e}")))?;

        let engine = engine(settings)?;
        let mut builder = Server::builder()
            .listener(listener(settings)?)
            .limits(limits)
            .keep_alive(KeepAlive::new().max_requests(settings.keep_alive_requests))
            .workers(match settings.driver {
                Driver::Reactor => Workers::reactor(settings.workers),
                Driver::Blocking => Workers::blocking(settings.workers),
            })
            .drain_deadline(settings.drain)
            .catch_service_panics(true);
        for p in core.profiles() {
            builder = builder.profile(
                serve_net::Profile::new(serve_net::ProfileId(p.id.0))
                    .engine(engine)
                    .tag(p.service.0)
                    .lane(serve_net::Lane(p.lane.0))
                    .critical(p.critical)
                    .wipe_buffers(true),
            );
        }
        // The plain listener that sends everyone to HTTPS (`tls.redirect_from`),
        // on a profile of its own after the site's.
        let mut redirect_profile = None;
        if let Some(addr) = settings.tls.as_ref().and_then(|t| t.redirect_from) {
            let id = u8::try_from(core.profiles().len()).map_err(|_| {
                OpenError("tls.redirect_from needs a profile id; there are too many hosts".into())
            })?;
            redirect_profile = Some(id);
            builder = builder
                .listener(
                    ListenerSpec::tcp(REDIRECT_LISTENER, addr.to_string().as_str())
                        .profile(serve_net::ProfileId(id)),
                )
                .profile(serve_net::Profile::new(serve_net::ProfileId(id)));
        }
        #[cfg(feature = "tls")]
        let builder = builder.tls(crate::tls::DoorTls(tls.as_ref().map(|(s, _)| s.clone())));
        let time = Arc::new(ServerTime::default());
        let signal = Arc::new(LoadSignal::default());
        let admit = PassportAdmit::new(pool.clone());
        let built = builder
            .observer(TimeObserver::new(time.clone()).with_load(signal.clone()))
            .gate(bouncer.clone())
            .checkpoint(DoorCheckpoint::new(bouncer.clone()))
            .admit(admit.clone())
            .control(Arc::new(UrgentControl::new(line.clone())))
            .build()
            .map_err(|e| OpenError(format!("gateway configuration: {e}")))?;
        if admit.prepared_workers() > pool.workers() {
            return Err(OpenError(format!(
                "serve-net runs {} workers but the gateway has passports for {}",
                admit.prepared_workers(),
                pool.workers()
            )));
        }
        let ws = crate::ws::WsHub::start(
            settings.ws.clone(),
            core.clone(),
            pool.clone(),
            bouncer.clone(),
        )
        .map_err(|e| OpenError(format!("websockets: {e}")))?;
        let https_port = Arc::new(std::sync::atomic::AtomicU16::new(tls_port(settings)));
        let bound = built
            .bind(
                Pipeline::with_stages(
                    core,
                    pool.clone(),
                    bouncer.clone(),
                    tickets.clone(),
                    Arc::new(web),
                    stages.clone(),
                )
                .with_access(access)
                .with_tls_replies(settings.tls.as_ref().map(|t| crate::pipeline::TlsReplies {
                    hsts: t.hsts.clone(),
                    hosts: t.redirect_hosts.clone(),
                    https_port: https_port.clone(),
                    redirect_profile,
                }))
                .with_lane_rates(&settings.lane_rates)
                .with_ws(Some(ws.clone()))
                .with_cpu(match settings.driver {
                    // One thread per connection already: nothing to gain.
                    Driver::Blocking => None,
                    Driver::Reactor => crate::offload::CpuPool::start(settings.cpu_threads)
                        .map_err(|e| OpenError(format!("gateway.cpu_threads: {e}")))?,
                }),
            )
            .map_err(|e| OpenError(e.to_string()))?;
        // The port the redirect names, now that it is known (`:0` binds any).
        if let Some((_, a)) = bound.local_addrs().find(|(name, _)| *name == "web") {
            https_port.store(a.port(), std::sync::atomic::Ordering::Relaxed);
        }
        let load = Watcher::start(
            settings.shed_marks(),
            settings.shed_check,
            line,
            pool.clone(),
            signal,
        )
        .map_err(|e| OpenError(format!("load watch: {e}")))?;
        let running = bound.open().map_err(|e| OpenError(e.to_string()))?;
        ejector.attach(running.server_handle());
        #[cfg(feature = "tls")]
        let tls_watch = match &tls {
            Some((server, t)) => crate::tls::Watcher::start(server.clone(), t.clone(), tls_notes)
                .map_err(|e| OpenError(format!("tls.reload: {e}")))?,
            None => None,
        };
        Ok(Door {
            stages,
            tickets,
            running,
            pool,
            bouncer,
            time,
            ejector,
            load,
            ws,
            #[cfg(feature = "tls")]
            tls,
            #[cfg(feature = "tls")]
            _tls_watch: tls_watch,
        })
    }

    /// The plain listener's address that sends everyone to HTTPS, when there
    /// is one.
    #[must_use]
    pub fn redirect_addr(&self) -> Option<SocketAddr> {
        self.running
            .listeners()
            .into_iter()
            .find(|l| l.name == REDIRECT_LISTENER)
            .and_then(|l| l.local.socket_addr())
    }

    /// Loads the certificate and key again (a configuration reload): the
    /// old pair stays when they do not load. `None` without TLS.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn reload_tls(&self) -> Option<crate::tls::TlsNote> {
        self.tls
            .as_ref()
            .map(|(server, t)| crate::tls::reload(server, t))
    }

    /// WebSocket connections open now.
    #[must_use]
    pub fn websockets(&self) -> usize {
        self.ws.open_count()
    }

    pub(crate) fn ws_hub(&self) -> &Arc<crate::ws::WsHub> {
        &self.ws
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

    /// Request tickets held right now (one per request between its head and
    /// its end); zero when nothing is in flight.
    #[must_use]
    pub fn tickets_held(&self) -> usize {
        self.tickets.held()
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

    /// Stage timing (empty unless it was enabled).
    #[must_use]
    pub fn stage_times(&self) -> &StageTimes {
        &self.stages
    }

    /// The transport's server, for health and statistics.
    pub fn running(&self) -> &Running {
        &self.running
    }

    /// Shutdown steps 1 and 2: the door closes, then in-flight requests drain
    /// until `deadline`; whatever is left is closed.
    pub fn close(mut self, deadline: Duration) -> DrainReport {
        self.running.close_door();
        // A shed the load watch raised is lowered: the next door starts
        // from what the operator set.
        if let Some(mut load) = self.load.take() {
            load.stop();
        }
        // The bouncer's ejector holds the transport; detached here, nothing
        // keeps the transport (and the core and its stores) alive once the
        // drain ends.
        self.ejector.detach();
        self.running.drain(deadline)
    }
}

/// A TLS load or reload in the log: the certificate's last day, a warning
/// when it is near, or why a new pair was refused.
#[cfg(feature = "tls")]
fn log_tls(foundation: &wasp_core::suite::Foundation, note: &crate::tls::TlsNote) {
    match note {
        crate::tls::TlsNote::Loaded {
            not_after,
            days_left,
            reload,
        } => {
            let what = if *reload { "reloaded" } else { "loaded" };
            if *days_left < crate::tls::WARN_DAYS {
                log::warn!(
                    foundation.log(),
                    "tls certificate expires soon",
                    loaded = what,
                    days_left = *days_left,
                    not_after = *not_after
                );
            } else {
                log::info!(
                    foundation.log(),
                    "tls certificate",
                    loaded = what,
                    days_left = *days_left,
                    not_after = *not_after
                );
            }
        }
        crate::tls::TlsNote::Refused(why) => {
            log::warn!(
                foundation.log(),
                "tls certificate not reloaded; the old one still serves",
                reason = why.as_str()
            );
        }
    }
}

/// The listener that sends plain HTTP to HTTPS (`tls.redirect_from`).
const REDIRECT_LISTENER: &str = "redirect";

/// The HTTPS port the redirect names: the main listener's, or 443.
fn tls_port(settings: &Settings) -> u16 {
    settings
        .listen
        .parse::<SocketAddr>()
        .map_or(443, |a| a.port())
}

/// The protocol engine of every profile: with TLS, HTTP/1.1 or HTTP/2 by
/// ALPN (G-90); else HTTP/1.1, or HTTP/1.1 and cleartext HTTP/2 by the
/// connection preface behind a trusted proxy (`gateway.h2c`, G-87).
fn engine(settings: &Settings) -> Result<serve_net::EngineChoice, OpenError> {
    if settings.tls.is_some() {
        return Ok(serve_net::EngineChoice::Http1OrH2ByAlpn);
    }
    // A Unix socket behind the start shim is proxy ingress too (G-79).
    let behind_proxy = matches!(settings.ingress, IngressMode::Proxy { .. });
    match (settings.h2c, behind_proxy) {
        (crate::settings::H2c::Off, _) | (crate::settings::H2c::Auto, false) => {
            Ok(serve_net::EngineChoice::Http1)
        }
        (crate::settings::H2c::On, false) => Err(OpenError(
            "gateway.h2c = true needs a trusted proxy in front (gateway.ingress = \"proxy\" or the start shim's socket): cleartext HTTP/2 on an open port would let any client skip TLS".into(),
        )),
        (_, true) => Ok(serve_net::EngineChoice::Http1OrH2ByPreface),
    }
}

/// The listener for the settings' address and ingress.
fn listener(settings: &Settings) -> Result<ListenerSpec, OpenError> {
    let source = match &settings.ingress {
        IngressMode::Direct => None,
        IngressMode::Proxy {
            forwarded_proto, ..
        } => {
            let trusted = serve_net::TrustedProxies::new(&settings.ingress.trusted())
                .map_err(|e| OpenError(format!("gateway.trusted_proxies: {e}")))?;
            Some(serve_net::ProxySource::forwarded_for(trusted).trust_scheme(*forwarded_proto))
        }
    };
    if let Some(path) = settings.listen.strip_prefix(crate::settings::UNIX_PREFIX) {
        return unix_listener(path, source);
    }
    let spec = ListenerSpec::tcp("web", settings.listen.as_str()).profile(serve_net::ProfileId(0));
    Ok(match source {
        None if settings.tls.is_some() => spec.ingress(serve_net::Ingress::DirectTls),
        None => spec,
        Some(source) => spec.ingress(serve_net::Ingress::Proxy(source)),
    })
}

/// A Unix socket listener at `path`, owner-only (`0600`), whose peers must
/// run as this process's user; behind a front end (`source`), only such a
/// peer may name the client. Whatever is at `path` already must be a socket
/// of this user: net-io then refuses it while something listens on it, and
/// replaces it when it is stale. Anything else there is refused and left as
/// it is.
#[cfg(unix)]
fn unix_listener(
    path: &str,
    source: Option<serve_net::ProxySource>,
) -> Result<ListenerSpec, OpenError> {
    check_socket_path(std::path::Path::new(path))?;
    Ok(ListenerSpec::unix("web", path)
        .profile(serve_net::ProfileId(0))
        .unix_mode(serve_net::UnixMode::new(0o600))
        .ingress(serve_net::Ingress::Unix(
            serve_net::UnixPeerTrust::SameUser,
            source,
        )))
}

/// Refuses a `path` that holds anything but a socket of this process's
/// user.
#[cfg(unix)]
fn check_socket_path(path: &std::path::Path) -> Result<(), OpenError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    let shown = path.display();
    if !meta.file_type().is_socket() {
        return Err(OpenError(format!(
            "gateway.listen: {shown} exists and is not a socket; wasp never removes it, so move it or choose another path"
        )));
    }
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let me = own_uid(dir).map_err(|e| {
        OpenError(format!(
            "gateway.listen: cannot tell who owns {shown} ({e})"
        ))
    })?;
    if meta.uid() != me {
        return Err(OpenError(format!(
            "gateway.listen: {shown} is a socket of another user (uid {}); wasp never removes it",
            meta.uid()
        )));
    }
    Ok(())
}

/// This process's user: the owner of a file it makes in `dir` (a new name,
/// never an existing file), removed at once. No unsafe call needed.
#[cfg(unix)]
fn own_uid(dir: &std::path::Path) -> std::io::Result<u32> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let probe = dir.join(format!(".wasp-owner-{}-{nanos}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)?;
    let uid = file.metadata().map(|m| m.uid());
    drop(file);
    let _ = std::fs::remove_file(&probe);
    uid
}

#[cfg(not(unix))]
fn unix_listener(
    path: &str,
    _source: Option<serve_net::ProxySource>,
) -> Result<ListenerSpec, OpenError> {
    Err(OpenError(format!(
        "gateway.listen `unix:{path}` is a Unix socket, which this system does not have"
    )))
}

/// The gateway as a kernel subsystem, at [`Position::LAST`]: it opens after
/// everything else started and is stopped before anything else.
pub struct Gateway {
    core: Arc<Core>,
    web: Option<WebServices>,
    open: Option<Door>,
    link: Option<Link>,
    /// The settings in force: written at start and by a reload's commit.
    applied: Arc<Mutex<Settings>>,
    stages: Option<Arc<StageTimes>>,
    /// The access log and the log rules, with whether the access line is on
    /// (set at start; a reload swaps the rules).
    access: Option<(Arc<AccessLog>, bool)>,
    /// Lane budgets per caller the application sets (wasp's API budget).
    lane_rates: Vec<crate::settings::LaneRate>,
    /// Attached to the door when it opens: the application's account
    /// events end open WebSockets through it.
    revoker: Option<crate::ws::Revoker>,
}

impl Gateway {
    /// The gateway for this core.
    #[must_use]
    pub fn new(core: Arc<Core>) -> Gateway {
        Gateway {
            core,
            web: Some(WebServices::new()),
            open: None,
            link: None,
            applied: Arc::new(Mutex::new(Settings::default())),
            stages: None,
            access: None,
            lane_rates: Vec::new(),
            revoker: None,
        }
    }

    /// The application's revoker, attached when the door opens.
    #[must_use]
    pub fn revoker(mut self, revoker: crate::ws::Revoker) -> Gateway {
        self.revoker = Some(revoker);
        self
    }

    /// Charges these lanes to each caller (a session, an API key, or a
    /// guest's address); they take effect when the gateway opens.
    #[must_use]
    pub fn lane_rates(mut self, rates: Vec<crate::settings::LaneRate>) -> Gateway {
        self.lane_rates = rates;
        self
    }

    /// Records stage times into `stages` (shared with whatever else records
    /// into it, such as the render engine).
    #[must_use]
    pub fn stages(mut self, stages: Arc<StageTimes>) -> Gateway {
        self.stages = Some(stages);
        self
    }

    /// Attaches a web service for the core's external service `name`.
    /// An unknown name is refused when the gateway opens.
    #[must_use]
    pub fn web(mut self, name: &str, service: impl WebService) -> Gateway {
        if let (Some(tag), Some(web)) = (self.core.service_tag(name), self.web.as_mut()) {
            web.attach(tag, service);
        } else {
            self.web = None;
        }
        self
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
        let settings = Settings {
            lane_rates: self.lane_rates.clone(),
            ..Settings::from_config(&link.foundation().config())?
        };
        let web = self
            .web
            .take()
            .ok_or_else(|| Failure::new("a web service names no service the core declares"))?;
        let events: Arc<dyn EventSink> = LogSink::spawn(link.foundation().clone())?;
        let rules = crate::rules::LogRules::from_config(&link.foundation().config())
            .map_err(Failure::new)?;
        // Always there: a reload can add the first rule.
        let access = AccessLog::spawn(link.foundation().clone(), settings.access_log, rules)?;
        self.access = Some((access.clone(), settings.access_log));
        let access = Some(access);
        let open = Door::open_with(
            self.core.clone(),
            &settings,
            link.foundation().kernel().urgent().clone(),
            web,
            Extras {
                events: Some(events),
                stages: self.stages.clone(),
                access,
                #[cfg(feature = "tls")]
                tls_notes: Some({
                    let foundation = link.foundation().clone();
                    Arc::new(move |n| log_tls(&foundation, &n))
                }),
            },
        )?;
        if let Some(r) = &self.revoker {
            r.attach_to(&open);
        }
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
        if let Ok(mut applied) = self.applied.lock() {
            *applied = settings;
        }
        self.open = Some(open);
        self.link = Some(link.clone());
        Ok(())
    }

    fn stop(&mut self, deadline: Deadline) -> Result<(), Failure> {
        let Some(open) = self.open.take() else {
            return Ok(());
        };
        // Keep a little of the kernel's deadline for the steps after this one.
        let drain = self
            .applied
            .lock()
            .map_or(Settings::default().drain, |s| s.drain);
        let budget = deadline
            .remaining()
            .saturating_sub(Duration::from_millis(500))
            .min(drain);
        let time = open.server_time().summary();
        let stages = open
            .stage_times()
            .enabled()
            .then(|| open.stage_times().summaries());
        let report = open.close(budget);
        if let (Some(stages), Some(link)) = (stages, &self.link) {
            for (stage, s) in stages {
                log::info!(
                    link.foundation().log(),
                    "gateway stage",
                    stage = stage,
                    count = s.count,
                    mean_ns = u64::try_from(s.mean.as_nanos()).unwrap_or(u64::MAX),
                    p50_ns_below = u64::try_from(s.p50.as_nanos()).unwrap_or(u64::MAX),
                    p99_ns_below = u64::try_from(s.p99.as_nanos()).unwrap_or(u64::MAX)
                );
            }
        }
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

    /// A reload: `door.ban` and `door.exempt` take effect at once (new bans
    /// added, removed ones lifted, the allow list swapped whole), and so does
    /// `gateway.drain`. Everything that shapes the listener and the pools
    /// (address, workers, passports, limits, keep-alive) takes effect at the
    /// next start and is logged as such.
    fn reload(&mut self, config: &Config) -> Result<Commit, Failure> {
        let next = Settings::from_config(config)?;
        let rules = crate::rules::LogRules::from_config(config).map_err(Failure::new)?;
        let access = self.access.clone();
        let (Some(open), Some(link)) = (&self.open, &self.link) else {
            return Ok(Commit::none());
        };
        let current = self
            .applied
            .lock()
            .map_err(|_| Failure::new("gateway settings lock poisoned"))?
            .clone();
        // Prepare everything that can fail before anything changes.
        let allow = bouncer::allow_list(&next.exempt)?;
        let ban: Vec<_> = next
            .ban
            .iter()
            .filter(|a| !current.ban.contains(a))
            .copied()
            .collect();
        let lift: Vec<_> = current
            .ban
            .iter()
            .filter(|a| !next.ban.contains(a))
            .copied()
            .collect();
        let mut later = Vec::new();
        if next.listen != current.listen {
            later.push("gateway.listen");
        }
        if next.workers != current.workers {
            later.push("gateway.workers");
        }
        if next.passports != current.passports {
            later.push("gateway.passports");
        }
        if next.head_timeout != current.head_timeout || next.max_body != current.max_body {
            later.push("gateway limits");
        }
        if next.keep_alive_requests != current.keep_alive_requests {
            later.push("gateway.keep_alive_requests");
        }
        if next.driver != current.driver {
            later.push("gateway.driver");
        }
        if next.stage_timing != current.stage_timing {
            later.push("gateway.stage_timing");
        }
        if next.cpu_threads != current.cpu_threads {
            later.push("gateway.cpu_threads");
        }
        if next.ingress != current.ingress {
            later.push("gateway.ingress");
        }
        let bouncer = open.bouncer().clone();
        let applied = self.applied.clone();
        let foundation = link.foundation().clone();
        // The certificate and key are read again; other TLS settings take
        // effect at the next start.
        #[cfg(feature = "tls")]
        let tls = open.tls.clone();
        if next.tls != current.tls {
            later.push("tls");
        }
        Ok(Commit::new(move || {
            #[cfg(feature = "tls")]
            if let Some((server, t)) = &tls {
                log_tls(&foundation, &crate::tls::reload(server, t));
            }
            if let Some((log, on)) = &access {
                log.set_rules(rules, *on);
            }
            let mut failed = 0_u64;
            let exempt_applied = bouncer.replace_allow(allow).is_ok();
            if !exempt_applied {
                failed += 1;
            }
            // Only what took effect is recorded, so a ban that failed (a full
            // table) is tried again by the next reload.
            let mut banned_now: Vec<_> = Vec::new();
            for addr in &ban {
                if bouncer::ban(&bouncer, *addr).is_ok() {
                    banned_now.push(*addr);
                } else {
                    failed += 1;
                }
            }
            let mut lifted_now: Vec<_> = Vec::new();
            for addr in &lift {
                if bouncer::lift(&bouncer, *addr).is_ok() {
                    lifted_now.push(*addr);
                } else {
                    failed += 1;
                }
            }
            log::info!(
                foundation.log(),
                "gateway reloaded",
                banned = ban.len(),
                lifted = lift.len(),
                failed = failed,
                at_restart = later.join(", ").as_str()
            );
            if let Ok(mut s) = applied.lock() {
                // What a restart would need stays as it is running.
                let running = s.clone();
                let mut applied_ban: Vec<_> = running
                    .ban
                    .iter()
                    .filter(|a| !lifted_now.contains(a))
                    .copied()
                    .collect();
                applied_ban.extend(banned_now);
                *s = Settings {
                    listen: running.listen,
                    workers: running.workers,
                    passports: running.passports,
                    head_timeout: running.head_timeout,
                    max_body: running.max_body,
                    keep_alive_requests: running.keep_alive_requests,
                    driver: running.driver,
                    stage_timing: running.stage_timing,
                    cpu_threads: running.cpu_threads,
                    ingress: running.ingress,
                    lane_rates: running.lane_rates,
                    ws: running.ws,
                    ban: applied_ban,
                    exempt: if exempt_applied {
                        next.exempt
                    } else {
                        running.exempt
                    },
                    ..next
                };
            }
        }))
    }

    fn health(&self) -> Health {
        match &self.open {
            // Each lost passport is a panic that unwound past a request: the
            // pool replaced it, but someone should look.
            Some(open) if open.pool().stats().lost > 0 => {
                Health::degraded("passports lost to panics (replaced)")
            }
            Some(open) if open.running().health().is_ok() => Health::HEALTHY,
            Some(_) => Health::degraded("transport reports an issue"),
            None => Health::unhealthy("door closed"),
        }
    }
}
