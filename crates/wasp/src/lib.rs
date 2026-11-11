//! The platform process's wiring: which services the core declares, which
//! profile uses which, the theme, and the web site attached to the gateway.
//! `main` boots it; the tests open the same wiring on a loopback port.

pub mod content;
pub mod site;
pub mod theme;

use std::sync::Arc;

use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::config::Config;

/// The core, the site, and the theme watcher, ready for the gateway.
pub struct Wiring {
    /// The loaded core (phases 1 to 3).
    pub core: Arc<Core>,
    /// The web site, attached to the core's external service `web`.
    pub site: site::SiteApp,
    /// The theme watcher (a kernel subsystem; start it before the gateway).
    pub theme: theme::ThemeWatcher,
    /// Stage timing (`gateway.stage_timing`), shared by the gateway and the
    /// render engine.
    pub stages: Arc<gateway_io::StageTimes>,
}

impl std::fmt::Debug for Wiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wiring").field("core", &self.core).finish()
    }
}

/// Phases 1 to 3 from configuration, with the data folder `.` (a memory
/// content store needs none; see [`wire_in`]).
pub fn wire(config: &Config) -> Result<Wiring, String> {
    wire_in(config, std::path::Path::new("."))
}

/// Phases 1 to 3 from configuration.
///
/// Providers: the content store (`[content] store`: `memory`, the default,
/// or `bison`, a bison-db file at `[content] path`, default
/// `<data_dir>/content.bison`), owned by the core and flushed at shutdown.
/// Jobs: an in-process runner (`[jobs] threads`, default 2; `[jobs] queue`,
/// default 1024).
///
/// Two services are declared: `web` (external: the web site on web-net) and
/// `hello` (a passport service, the step-2 stub, with its slow route when
/// `hello.slow_route` is on, for drain tests). `[site] service` picks the one
/// the `site` profile uses; the default is `web`. The theme is compiled here,
/// so a broken theme refuses to start.
pub fn wire_in(config: &Config, data_dir: &std::path::Path) -> Result<Wiring, String> {
    let e = |e: wasp_core::suite::Error| e.to_string();
    let store_kind: String = config
        .get_or("content.store", "memory".to_owned())
        .map_err(e)?;
    let store: Arc<dyn content::ContentStore> = match store_kind.as_str() {
        "memory" => Arc::new(content::MemoryStore::new()),
        "bison" => {
            let path: std::path::PathBuf = config
                .get_or("content.path", data_dir.join("content.bison"))
                .map_err(e)?;
            Arc::new(content::BisonStore::open(&path).map_err(|e| e.0)?)
        }
        other => {
            return Err(format!(
                "content.store must be `memory` or `bison`, not `{other}`"
            ));
        }
    };
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
    let service: String = config
        .get_or("site.service", "web".to_owned())
        .map_err(|e| e.to_string())?;
    if service != "web" && service != "hello" {
        return Err(format!(
            "site.service must be `web` or `hello`, not `{service}`"
        ));
    }
    let core = Core::builder()
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
    let settings = site::SiteSettings::from_config(config)?;
    let theme = theme::load(&settings.theme).map_err(|e| e.0)?;
    let watcher =
        theme::ThemeWatcher::new(theme.clone(), settings.theme.clone(), settings.theme_poll);
    let timing: bool = config
        .get_or("gateway.stage_timing", false)
        .map_err(|e| e.to_string())?;
    let stages = Arc::new(gateway_io::StageTimes::new(timing));
    let manifest = content::Manifest::open(store, &settings.base, true).map_err(|e| e.0)?;
    let engine = theme::Timed::new(theme, stages.clone());
    let site = site::build(core.access().clone(), manifest, engine, &settings)
        .map_err(|e| format!("site: {e}"))?;
    Ok(Wiring {
        core,
        site,
        theme: watcher,
        stages,
    })
}
