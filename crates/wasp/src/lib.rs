//! The platform process's wiring: which services the core declares, which
//! profile uses which, the theme, and the web site attached to the gateway.
//! `main` boots it; the tests open the same wiring on a loopback port.

pub mod auth;
pub mod content;
pub mod import;
pub mod nex;
pub mod site;
pub mod theme;

use std::sync::Arc;

use gateway_io::gatekeeper::GatekeeperAuth;
use gateway_io::gatekeeper::gatekeeper_io::Gatekeeper;
use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::config::Config;

/// The core, the site, and the theme watcher, ready for the gateway.
pub struct Wiring {
    /// The loaded core (phases 1 to 3).
    pub core: Arc<Core>,
    /// The web site, attached to the core's external service `web`.
    pub site: site::SiteApp,
    /// The gates: the core's authentication and the site's authorization.
    pub gatekeeper: Arc<Gatekeeper>,
    /// The theme watcher (a kernel subsystem; start it before the gateway).
    pub theme: theme::ThemeWatcher,
    /// Stage timing (`gateway.stage_timing`), shared by the gateway and the
    /// render engine.
    pub stages: Arc<gateway_io::StageTimes>,
    /// Things the operator should know about the boot (written to the log
    /// as warnings).
    pub notices: Vec<String>,
}

impl std::fmt::Debug for Wiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wiring").field("core", &self.core).finish()
    }
}

/// The content store `[content]` names, opened.
fn open_store(
    config: &Config,
    data_dir: &std::path::Path,
    notices: &mut Vec<String>,
) -> Result<Arc<dyn content::ContentStore>, String> {
    let e = |e: wasp_core::suite::Error| e.to_string();
    let store_kind: String = config
        .get_or("content.store", "memory".to_owned())
        .map_err(e)?;
    let store: Arc<dyn content::ContentStore> = match store_kind.as_str() {
        "memory" => Arc::new(content::MemoryStore::new()),
        "nex" => {
            let path: std::path::PathBuf = config
                .get_or("content.path", data_dir.join("nex"))
                .map_err(e)?;
            Arc::new(nex::NexStore::new(
                nex::NexDb::open(&path).map_err(|e| e.0)?,
            ))
        }
        "bison" => {
            let path: std::path::PathBuf = config
                .get_or("content.path", data_dir.join("content.bison"))
                .map_err(e)?;
            let recovery: String = config
                .get_or("content.recovery", "strict".to_owned())
                .map_err(e)?;
            let recovery = match recovery.as_str() {
                "strict" => content::Recovery::Strict,
                "salvage" => content::Recovery::Salvage,
                other => {
                    return Err(format!(
                        "content.recovery must be `strict` or `salvage`, not `{other}`"
                    ));
                }
            };
            let store = content::BisonStore::open_with(&path, recovery).map_err(|e| e.0)?;
            if store.discarded() > 0 {
                notices.push(format!(
                    "content store {}: {} bytes discarded at open (a torn last record, or what a salvage skipped); check the content",
                    path.display(),
                    store.discarded()
                ));
            }
            Arc::new(store)
        }
        other => {
            return Err(format!(
                "content.store must be `memory`, `bison`, or `nex`, not `{other}`"
            ));
        }
    };
    Ok(store)
}

/// Imports the posts and pages in `from` into the content store `[content]`
/// names (see [the import module](mod@import)), with the data folder `data_dir`. The store must be
/// durable, and no running instance may hold it (stop the server first).
pub fn import(
    config: &Config,
    data_dir: &std::path::Path,
    from: &std::path::Path,
) -> Result<import::Report, String> {
    let kind: String = config
        .get_or("content.store", "memory".to_owned())
        .map_err(|e| e.to_string())?;
    if kind == "memory" {
        return Err(
            "content.store is `memory`: an import would be lost at exit; set content.store = \"bison\""
                .to_owned(),
        );
    }
    let mut notices = Vec::new();
    let store = open_store(config, data_dir, &mut notices)?;
    let settings = site::SiteSettings::from_config(config)?;
    let mut manifest =
        content::Manifest::open(store.clone(), &settings.base, false).map_err(|e| e.0)?;
    let report = import::import_into(&mut manifest, from)?;
    store.flush().map_err(|e| e.0)?;
    Ok(report)
}

/// Phases 1 to 3 from configuration, for tests and tools: a bison content
/// store defaults to `./content.bison`, the gates' master secret lasts for
/// this run only (unless `auth.secret` names a file), and no boot account is
/// made from the environment.
pub fn wire(config: &Config) -> Result<Wiring, String> {
    wire_with(config, std::path::Path::new("."), None, None)
}

/// Phases 1 to 3 for the process: the data folder holds the content store
/// and the gates' master secret, and the boot account's password comes from
/// `WASP_ADMIN_PASSWORD`.
pub fn wire_in(config: &Config, data_dir: &std::path::Path) -> Result<Wiring, String> {
    let password = std::env::var(auth::ADMIN_PASSWORD_ENV).ok();
    let mut wiring = wire_with(config, data_dir, Some(data_dir), password.as_deref())?;
    if std::env::var_os("PORT").is_some()
        && site::SiteSettings::from_config(config)?.hosts.is_empty()
    {
        wiring.notices.push(
            "PORT is set (an application server starts this process) but site.hosts is empty: the site answers only localhost; set site.hosts to the site's name".to_owned(),
        );
    }
    Ok(wiring)
}

/// Phases 1 to 3 from configuration.
///
/// Gates: one gatekeeper (`[auth]`, see [`auth`]) authenticates in the core
/// and authorizes in the site; accounts and sessions are in memory.
///
/// Providers: the content store (`[content] store`: `memory`, the default,
/// or `bison`, a bison-db file at `[content] path`, default
/// `<data_dir>/content.bison`; one process at a time; `[content] recovery =
/// "salvage"` opens a damaged file), owned by the core and flushed at
/// shutdown.
/// Jobs: an in-process runner (`[jobs] threads`, default 2; `[jobs] queue`,
/// default 1024).
///
/// Two services are declared: `web` (external: the web site on web-net) and
/// `hello` (a passport service, the step-2 stub, with its slow route when
/// `hello.slow_route` is on, for drain tests). `[site] service` picks the one
/// the `site` profile uses; the default is `web`. The theme is compiled here,
/// so a broken theme refuses to start.
fn wire_with(
    config: &Config,
    data_dir: &std::path::Path,
    secret_dir: Option<&std::path::Path>,
    admin_password: Option<&str>,
) -> Result<Wiring, String> {
    let e = |e: wasp_core::suite::Error| e.to_string();
    let mut notices = Vec::new();
    let store = open_store(config, data_dir, &mut notices)?;
    let threads: u64 = config.get_or("jobs.threads", 2_u64).map_err(e)?;
    let queue: u64 = config.get_or("jobs.queue", 1024_u64).map_err(e)?;
    let jobs = wasp_core::InProcessJobs::new(
        usize::try_from(threads.clamp(1, 64)).unwrap_or(2),
        usize::try_from(queue.clamp(1, 1 << 20)).unwrap_or(1024),
    )
    .map_err(|e| format!("jobs: {e}"))?;
    let slow: bool = config
        .get_or("hello.slow_route", false)
        .map_err(|e| e.to_string())?;
    if slow {
        // The slow route holds a worker for up to 30 s per request: a drain
        // test switch, never on an address others can reach.
        let listen: String = config
            .get_or("gateway.listen", "127.0.0.1:8080".to_owned())
            .map_err(|e| e.to_string())?;
        let loopback = listen
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().is_loopback())
            .unwrap_or_else(|_| listen.starts_with("localhost:"));
        if !loopback {
            return Err(format!(
                "hello.slow_route is for drain tests on a loopback address, not `{listen}`"
            ));
        }
    }
    let service: String = config
        .get_or("site.service", "web".to_owned())
        .map_err(|e| e.to_string())?;
    if service != "web" && service != "hello" {
        return Err(format!(
            "site.service must be `web` or `hello`, not `{service}`"
        ));
    }
    let settings = site::SiteSettings::from_config(config)?;
    let auth_settings = auth::AuthSettings::from_config(config, secret_dir, &settings.hosts)?;
    let gatekeeper = auth::gatekeeper(&auth_settings, admin_password)?;
    let core = Core::builder()
        .authenticator(GatekeeperAuth(gatekeeper.clone()))
        .provider(store.clone())
        .jobs(Arc::new(jobs))
        .external("web")
        .service("hello", move |ctx| {
            if slow {
                Hello::with_slow_route(ctx)
            } else {
                Hello::new(ctx)
            }
        })
        .profile("site", &service, |_| {})
        .load()
        .map_err(|e| e.0)?;
    let core = Arc::new(core);
    let theme = theme::load(&settings.theme).map_err(|e| e.0)?;
    let watcher =
        theme::ThemeWatcher::new(theme.clone(), settings.theme.clone(), settings.theme_poll);
    let timing: bool = config
        .get_or("gateway.stage_timing", false)
        .map_err(|e| e.to_string())?;
    let stages = Arc::new(gateway_io::StageTimes::new(timing));
    let manifest = content::Manifest::open(store, &settings.base, true).map_err(|e| e.0)?;
    let engine = theme::Timed::new(theme, stages.clone());
    // `/ready`: 503 while any provider (the content store, the database)
    // cannot serve, for the front end and the supervisor.
    let ready_core = core.clone();
    let ready = move || ready_core.providers().iter().all(|p| p.healthy());
    let site = site::build(gatekeeper.clone(), manifest, engine, &settings, ready)?;
    Ok(Wiring {
        core,
        site,
        gatekeeper,
        theme: watcher,
        stages,
        notices,
    })
}
