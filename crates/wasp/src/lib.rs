//! The platform process's wiring: which services the core declares, which
//! profile uses which, the theme, and the web site attached to the gateway.
//! `main` boots it; the tests open the same wiring on a loopback port.

#[cfg(feature = "gatekeeper")]
pub mod auth;
pub mod content;
pub mod events;
pub mod hosts;
pub mod import;
#[cfg(feature = "store-nex")]
pub mod nex;
// Read by the nex-db site; other builds only refuse its tables.
#[cfg_attr(not(feature = "store-nex"), allow(dead_code))]
pub mod policy;
#[cfg(any(feature = "gatekeeper", feature = "store-nex"))]
pub mod secret;
// The parts both sites share are unused in a build with neither.
#[cfg_attr(
    not(any(feature = "gatekeeper", feature = "store-nex")),
    allow(dead_code)
)]
pub mod site;
#[cfg(feature = "store-nex")]
pub mod site_account;
#[cfg(feature = "store-nex")]
pub mod site_nex;
pub mod theme;

use std::sync::Arc;

#[cfg(feature = "gatekeeper")]
use gateway_io::gatekeeper::GatekeeperAuth;
#[cfg(feature = "gatekeeper")]
use gateway_io::gatekeeper::gatekeeper_io::Gatekeeper;
use wasp_core::Core;

/// The environment variable that holds the boot account's password.
pub const ADMIN_PASSWORD_ENV: &str = "WASP_ADMIN_PASSWORD";
use wasp_core::stub::Hello;
use wasp_core::suite::config::Config;

/// The core, the site, and the theme watcher, ready for the gateway.
pub struct Wiring {
    /// The loaded core (phases 1 to 3).
    pub core: Arc<Core>,
    /// The web site, attached to the core's external service `web`.
    pub site: Box<dyn gateway_io::WebService>,
    /// The gatekeeper, when `auth.store = "gatekeeper"`.
    #[cfg(feature = "gatekeeper")]
    pub gatekeeper: Option<Arc<Gatekeeper>>,
    /// The nex-db database, when content or accounts are kept in it.
    #[cfg(feature = "store-nex")]
    pub nex: Option<nex::NexDb>,
    /// The theme watcher (a kernel subsystem; start it before the gateway).
    pub theme: theme::ThemeWatcher,
    /// The other host profiles' theme watchers, started the same way.
    pub more_themes: Vec<theme::ThemeWatcher>,
    /// The sign-in settings' reload (a kernel subsystem), with nex-db
    /// accounts.
    pub auth_policy: Option<policy::PolicyReload>,
    /// The core's guest output cache, purged whenever the content changes.
    pub guest_pages: Arc<wasp_core::GuestPages>,
    /// How many times the site rendered a page or an error page.
    pub renders: Arc<theme::RenderCounts>,
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

/// Why `nex` is refused in a build without nex-db.
#[cfg(not(feature = "store-nex"))]
const NO_NEX: &str = "this build has no nex-db store: build wasp with the `store-nex` feature";

/// Backends opened once and shared by everything kept in them.
#[derive(Default)]
struct Shared {
    #[cfg(feature = "store-nex")]
    nex: Option<nex::NexDb>,
    /// No data folder: a database without a configured path lasts for this
    /// run only.
    #[cfg(feature = "store-nex")]
    temporary: bool,
}

/// The site's keys, derived from the master secret (`auth.secret`, default
/// `gate.key` in the folder that holds the database: beside `nex.path`,
/// else the data folder), so a form or a half-done sign-in from before a
/// restart still works after it, and a remembered device stays remembered;
/// with neither (tests, tools), for this run only.
#[cfg(feature = "store-nex")]
fn site_keys(
    config: &Config,
    secret_dir: Option<&std::path::Path>,
    boot: Option<String>,
) -> Result<site_nex::SiteKeys, String> {
    let named: Option<std::path::PathBuf> = config.get("auth.secret").map_err(|e| e.to_string())?;
    // Beside the database, so it follows the site (and its backups) and two
    // sites never share it.
    let database: Option<std::path::PathBuf> = config.get("nex.path").map_err(|e| e.to_string())?;
    let beside = database.map(|db| {
        db.parent()
            .unwrap_or_else(|| std::path::Path::new(""))
            .join("gate.key")
    });
    let master = match named
        .or(beside)
        .or_else(|| secret_dir.map(|d| d.join("gate.key")))
    {
        Some(path) => secret::read_or_create(&path)?,
        None => secret::fresh()?,
    };
    Ok(site_nex::SiteKeys {
        csrf: secret::derive(&master, "wasp csrf v1")?,
        cookies: site_account::CookieKeys::new(
            secret::derive(&master, "wasp sign-in step v1")?,
            secret::derive(&master, "wasp device v1")?,
        ),
        boot,
    })
}

/// The nex-db database (`[nex] path`, default `<data_dir>/nex`), opened once
/// and shared by everything kept in it.
#[cfg(feature = "store-nex")]
fn nex_db(
    config: &Config,
    data_dir: &std::path::Path,
    shared: &mut Shared,
) -> Result<nex::NexDb, String> {
    if let Some(db) = &shared.nex {
        return Ok(db.clone());
    }
    let path: Option<std::path::PathBuf> = config.get("nex.path").map_err(|e| e.to_string())?;
    let wait: std::time::Duration = config
        .get_or("nex.lock_wait", nex::LOCK_WAIT)
        .map_err(|e| e.to_string())?;
    let db = match path {
        Some(path) => nex::NexDb::open_waiting(&path, wait),
        None if shared.temporary => nex::NexDb::open_temporary(),
        None => nex::NexDb::open_waiting(&data_dir.join("nex"), wait),
    }
    .map_err(|e| e.to_string())?;
    shared.nex = Some(db.clone());
    Ok(db)
}

/// The content store `[content]` names, opened.
fn open_store(
    config: &Config,
    data_dir: &std::path::Path,
    notices: &mut Vec<String>,
    shared: &mut Shared,
) -> Result<Arc<dyn content::ContentStore>, String> {
    open_store_for(config, data_dir, notices, shared, DEFAULT_CONTENT)
}

/// The content site the site had before host profiles: `content =
/// "default"` in a profile keeps using it.
pub const DEFAULT_CONTENT: &str = "default";

/// The content store `[content]` names, for the content site `label`: nex-db
/// keeps each in its own content site, bison-db in its own file
/// (`content-<label>.bison` beside `content.path`), memory in its own map.
fn open_store_for(
    config: &Config,
    data_dir: &std::path::Path,
    notices: &mut Vec<String>,
    shared: &mut Shared,
    label: &str,
) -> Result<Arc<dyn content::ContentStore>, String> {
    let e = |e: wasp_core::suite::Error| e.to_string();
    let store_kind: String = config
        .get_or("content.store", "memory".to_owned())
        .map_err(e)?;
    let store: Arc<dyn content::ContentStore> = match store_kind.as_str() {
        "memory" => Arc::new(content::MemoryStore::new()),
        #[cfg(feature = "store-nex")]
        "nex" => {
            let store = nex::NexStore::new(nex_db(config, data_dir, shared)?);
            Arc::new(if label == DEFAULT_CONTENT {
                store
            } else {
                store.on_site(label)
            })
        }
        #[cfg(not(feature = "store-nex"))]
        "nex" => {
            let _ = (shared, label);
            return Err(NO_NEX.to_owned());
        }
        "bison" => {
            let path: std::path::PathBuf = config
                .get_or("content.path", data_dir.join("content.bison"))
                .map_err(e)?;
            let path = if label == DEFAULT_CONTENT {
                path
            } else {
                let stem = path.file_stem().map_or_else(
                    || "content".to_owned(),
                    |s| s.to_string_lossy().into_owned(),
                );
                path.with_file_name(format!("{stem}-{label}.bison"))
            };
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
            let store =
                content::BisonStore::open_with(&path, recovery).map_err(|e| e.to_string())?;
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
    let store = open_store(config, data_dir, &mut notices, &mut Shared::default())?;
    let settings = site::SiteSettings::from_config(config)?;
    let fields = content::Fields::from_config(config)?;
    let mut manifest = content::Manifest::open_with(store.clone(), &settings.base, false, fields)
        .map_err(|e| e.to_string())?;
    let report = import::import_into(&mut manifest, from)?;
    store.flush().map_err(|e| e.0)?;
    Ok(report)
}

/// The sign-in store when `auth.store` is not set: the gatekeeper when the
/// build has it, else nex-db, else none (the build refuses to wire a site).
const DEFAULT_AUTH_STORE: &str = if cfg!(feature = "gatekeeper") {
    "gatekeeper"
} else if cfg!(feature = "store-nex") {
    "nex"
} else {
    ""
};

/// The site's lanes: health and readiness first, then the content editor,
/// then signing in and out; everything else is browsing. Under load the
/// browsing lanes are refused first (`Shed`), and they cannot take the
/// passports held back for these (`gateway.reserve`).
fn site_lanes(base: &str) -> Vec<wasp_core::LaneRule> {
    use wasp_core::{Lane, LaneRule};
    let at = |path: &str| format!("{base}{path}");
    vec![
        LaneRule::exact(&at("/health"), Lane::CRITICAL),
        LaneRule::exact(&at("/ready"), Lane::CRITICAL),
        LaneRule::under(&at("/admin"), Lane::ADMIN),
        LaneRule::exact(&at("/sign-in"), Lane::AUTH),
        LaneRule::exact(&at("/sign-in/code"), Lane::AUTH),
        LaneRule::exact(&at("/sign-in/setup"), Lane::AUTH),
        LaneRule::exact(&at("/sign-out"), Lane::AUTH).method("POST"),
    ]
}

/// The gates the site signs in through.
#[derive(Clone)]
enum Gates {
    #[cfg(feature = "gatekeeper")]
    Keeper(Arc<Gatekeeper>),
    #[cfg(feature = "store-nex")]
    Nex(nex::NexAuth),
}

/// Phases 1 to 3 from configuration, for tests and tools: a bison content
/// store defaults to `./content.bison`, the gates' master secret and a nex-db
/// database last for this run only (unless `auth.secret` or `nex.path` names
/// one), and no boot account is made from the environment.
pub fn wire(config: &Config) -> Result<Wiring, String> {
    wire_with(config, std::path::Path::new("."), None, None)
}

/// Phases 1 to 3 for the process: the data folder holds the content store
/// and the gates' master secret, and the boot account's password comes from
/// `WASP_ADMIN_PASSWORD`.
pub fn wire_in(config: &Config, data_dir: &std::path::Path) -> Result<Wiring, String> {
    let password = std::env::var(ADMIN_PASSWORD_ENV).ok();
    // Typos first: `hots = [...]` is named as the typo it is, not as an
    // empty host list.
    check_keys(config)?;
    check_hosts(config, std::env::var_os("PORT").is_some())?;
    wire_with(config, data_dir, Some(data_dir), password.as_deref())
}

/// Behind an application server (`port`), `site.hosts` must name the site:
/// with none it answers only `localhost`, so every visitor would get 421.
/// `site.development = true` allows it (a local run behind a front end).
fn check_hosts(config: &Config, port: bool) -> Result<(), String> {
    let development: bool = config
        .get_or("site.development", false)
        .map_err(|e| e.to_string())?;
    if port && !development && site::SiteSettings::from_config(config)?.hosts.is_empty() {
        return Err(
            "PORT is set (an application server starts this process) but site.hosts is empty, so every visitor would be refused: set site.hosts to the site's names (or site.development = true for a local run)"
                .to_owned(),
        );
    }
    Ok(())
}

/// The keys of the sections the site reads.
const KNOWN_KEYS: &[(&str, &[&str])] = &[
    (
        "site",
        &[
            "assets",
            "base",
            "development",
            "hosts",
            "name",
            "service",
            "theme",
            "theme_poll",
        ],
    ),
    ("content", &["fields", "path", "recovery", "store"]),
    (
        "auth",
        &[
            "admin", "lockout", "mfa", "origin", "password", "role", "secret", "session", "store",
        ],
    ),
    ("nex", &["lock_wait", "path"]),
    ("admin", &["custom_theme", "theme"]),
    ("jobs", &["queue", "threads"]),
    ("hello", &["slow_route"]),
];

/// The foundation's own sections (it checks their keys itself).
const SUITE_SECTIONS: &[&str] = &[
    "audit", "crash", "guard", "ids", "kernel", "log", "metrics", "secrets",
];

/// Refuses a section nothing reads and a key the site or the gateway does
/// not know in theirs: a typo in the configuration never leaves a setting
/// at its default without a word.
fn check_keys(config: &Config) -> Result<(), String> {
    gateway_io::settings::check_section_keys(config, KNOWN_KEYS)?;
    gateway_io::settings::check_section_keys(config, gateway_io::settings::KNOWN_KEYS)?;
    if let wasp_core::suite::config::backend::Value::Table(root) = config.backend().as_value() {
        let known = |k: &str| {
            // `[errors]` checks its own keys (a status or a class each).
            k == "errors"
                // `[host.<name>]` (hosts::HostProfiles checks it).
                || k == "host"
                // `[log_rule.<name>]` too (gateway_io::rules).
                || k == "log_rule"
                || SUITE_SECTIONS.contains(&k)
                || KNOWN_KEYS.iter().any(|(s, _)| *s == k)
                || gateway_io::settings::KNOWN_KEYS
                    .iter()
                    .any(|(s, _)| *s == k)
        };
        if let Some(unknown) = root.keys().find(|k| !known(k)) {
            return Err(format!(
                "unknown section or key `{unknown}` in the configuration: check the spelling"
            ));
        }
    }
    Ok(())
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
#[cfg_attr(
    not(any(feature = "gatekeeper", feature = "store-nex")),
    allow(
        unreachable_code,
        unused_variables,
        unused_assignments,
        clippy::never_loop
    )
)]
fn wire_with(
    config: &Config,
    data_dir: &std::path::Path,
    secret_dir: Option<&std::path::Path>,
    admin_password: Option<&str>,
) -> Result<Wiring, String> {
    check_keys(config)?;
    let e = |e: wasp_core::suite::Error| e.to_string();
    let mut notices = Vec::new();
    let mut shared = Shared::default();
    #[cfg(feature = "store-nex")]
    {
        shared.temporary = secret_dir.is_none();
    }
    // The host profiles, and one content store per content site they name.
    let profiles = hosts::HostProfiles::from_config(config)?;
    let mut labels: Vec<String> = match &profiles {
        None => vec![DEFAULT_CONTENT.to_owned()],
        Some(p) => p.profiles.iter().map(|x| x.content.clone()).collect(),
    };
    labels.sort();
    labels.dedup();
    let mut stores: Vec<(String, Arc<dyn content::ContentStore>)> = Vec::new();
    for label in &labels {
        stores.push((
            label.clone(),
            open_store_for(config, data_dir, &mut notices, &mut shared, label)?,
        ));
    }
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
    #[cfg(not(feature = "gatekeeper"))]
    let _ = secret_dir;
    #[cfg(not(any(feature = "gatekeeper", feature = "store-nex")))]
    let _ = admin_password;
    let auth_store: String = config
        .get_or("auth.store", DEFAULT_AUTH_STORE.to_owned())
        .map_err(|e| e.to_string())?;
    let builder = Core::builder();
    // Set by the arm that does not return.
    let auth_policy: Option<policy::PolicyReload>;
    #[cfg(feature = "store-nex")]
    let boot: Option<String>;
    let (builder, gates): (wasp_core::CoreBuilder, Gates) = match auth_store.as_str() {
        #[cfg(feature = "gatekeeper")]
        "gatekeeper" => {
            auth_policy = None;
            #[cfg(feature = "store-nex")]
            {
                boot = None;
            }
            if policy::any_set(config) {
                return Err(
                    "[auth.password], [auth.mfa], [auth.session], [auth.lockout] and [auth.role] are for nex-db accounts: set auth.store = \"nex\", or remove them"
                        .to_owned(),
                );
            }
            let auth_settings =
                auth::AuthSettings::from_config(config, secret_dir, &settings.hosts)?;
            let gk = auth::gatekeeper(&auth_settings, admin_password)?;
            (
                builder.authenticator(GatekeeperAuth(gk.clone())),
                Gates::Keeper(gk),
            )
        }
        #[cfg(feature = "store-nex")]
        "nex" => {
            let db = nex_db(config, data_dir, &mut shared)?;
            let cell = policy::PolicyCell::new(policy::Policy::from_config(
                config,
                cfg!(feature = "mfa"),
            )?);
            let a = nex::NexAuth::new(db.clone()).with_policy(cell.clone());
            a.apply_lockout().map_err(|e| e.to_string())?;
            let applied = a.clone();
            auth_policy = Some(policy::PolicyReload::new(
                cell,
                cfg!(feature = "mfa"),
                move |_| {
                    if let Err(e) = applied.apply_lockout() {
                        events::warn(format!("the new lockout settings were not written: {e}"));
                    }
                },
            ));
            let admin: Option<String> = config.get("auth.admin").map_err(|e| e.to_string())?;
            boot = admin.clone();
            if let Some(admin) = admin {
                let roles = [nex::MEMBER_ROLE, nex::EDITOR_ROLE, nex::ADMIN_ROLE];
                // The password is needed only to make the account: once it
                // exists, a boot without it starts as usual (and gives back
                // any of its roles it lacks).
                match admin_password {
                    Some(password) => {
                        a.ensure_account(&admin, password, &roles)
                            .map_err(|e| e.to_string())?;
                    }
                    None if a.ensure_roles(&admin, &roles).map_err(|e| e.to_string())? => {}
                    None => {
                        return Err(format!(
                            "auth.admin `{admin}` has no account yet: put its password in {ADMIN_PASSWORD_ENV} for the start that makes it"
                        ));
                    }
                }
            }
            (
                builder.authenticator(a.clone()).provider(Arc::new(db)),
                Gates::Nex(a),
            )
        }
        #[cfg(not(feature = "store-nex"))]
        "nex" => return Err(NO_NEX.to_owned()),
        #[cfg(not(feature = "gatekeeper"))]
        "gatekeeper" => {
            return Err(
                "this build has no gatekeeper: build wasp with the `gatekeeper` feature".to_owned(),
            );
        }
        "" => {
            return Err(
                "this build has no sign-in store: build wasp with the `gatekeeper` or `store-nex` feature"
                    .to_owned(),
            );
        }
        other => {
            return Err(format!(
                "auth.store must be `gatekeeper` or `nex`, not `{other}`"
            ));
        }
    };
    let guest_pages = Arc::new(wasp_core::GuestPages::default());
    let builder = stores
        .iter()
        .fold(builder, |b, (_, store)| b.provider(store.clone()));
    let core = builder
        .guest_cache(guest_pages.clone())
        .jobs(Arc::new(jobs))
        .external("web")
        .service("hello", move |ctx| {
            if slow {
                Hello::with_slow_route(ctx)
            } else {
                Hello::new(ctx)
            }
        })
        .profile("site", &service, |p| p.lanes = site_lanes(&settings.base))
        .load()
        .map_err(|e| e.0)?;
    let core = Arc::new(core);
    let timing: bool = config
        .get_or("gateway.stage_timing", false)
        .map_err(|e| e.to_string())?;
    let stages = Arc::new(gateway_io::StageTimes::new(timing));
    let fields = content::Fields::from_config(config)?;
    // `/ready`: 503 while any provider (a content store, the database)
    // cannot serve, for the front end and the supervisor.
    let ready_core = core.clone();
    let ready: Arc<dyn Fn() -> bool + Send + Sync> =
        Arc::new(move || ready_core.providers().iter().all(|p| p.healthy()));
    #[cfg(feature = "gatekeeper")]
    let gatekeeper = match &gates {
        Gates::Keeper(gk) => Some(gk.clone()),
        #[allow(unreachable_patterns)]
        _ => None,
    };
    // One site per host profile, or the one site `[site]` describes: its
    // settings, its content site, and its own `[host.<name>.errors]` table
    // when it has one.
    let plans: Vec<(site::SiteSettings, String, Option<String>)> = match &profiles {
        None => vec![(settings.clone(), DEFAULT_CONTENT.to_owned(), None)],
        Some(p) => p
            .profiles
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let mut s = settings.clone();
                s.hosts.clone_from(&x.exact);
                // A wildcard, or the default profile, answers names its
                // list does not hold: the router chose it for them.
                s.any_host = !x.wildcards.is_empty() || p.default == Some(i);
                if let Some(n) = &x.site_name {
                    s.name.clone_from(n);
                }
                if let Some(t) = &x.theme {
                    s.theme.clone_from(t);
                }
                (
                    s,
                    x.content.clone(),
                    Some(format!("host.{}.errors", x.name)),
                )
            })
            .collect(),
    };
    let mut sites: Vec<Box<dyn gateway_io::WebService>> = Vec::new();
    let mut watchers = Vec::new();
    let mut renders = None;
    for (s, label, own_errors) in plans {
        let store = stores
            .iter()
            .find(|(l, _)| *l == label)
            .map(|(_, st)| st.clone())
            .ok_or_else(|| format!("no content store for `{label}`"))?;
        let theme = theme::load(&s.theme).map_err(|e| e.0)?;
        let section = own_errors
            .clone()
            .filter(|sec| config.contains(sec))
            .unwrap_or_else(|| "errors".to_owned());
        let error_rules = theme::ErrorRules::from_section(config, &section)?;
        error_rules.check(theme.error_pages())?;
        let error_rules: theme::ErrorRulesCell =
            Arc::new(std::sync::RwLock::new(Arc::new(error_rules)));
        let purge = guest_pages.clone();
        watchers.push(
            theme::ThemeWatcher::new(theme.clone(), s.theme.clone(), s.theme_poll)
                .on_change(move || purge.purge())
                .with_rules(error_rules.clone())
                .with_own_errors(own_errors),
        );
        let manifest = content::Manifest::open_with(store, &s.base, true, fields.clone())
            .map_err(|e| e.to_string())?;
        let purge = guest_pages.clone();
        let manifest = content::Content::new(manifest).on_change(move || purge.purge());
        let admin = theme::load_admin(&s.admin_theme).map_err(|e| e.0)?;
        let engine = theme::Timed::new(
            theme::SiteRender::new(theme, admin).with_rules(error_rules),
            stages.clone(),
        );
        if renders.is_none() {
            renders = Some(engine.counts().clone());
        }
        let ready = ready.clone();
        let ready = move || ready();
        let site: Box<dyn gateway_io::WebService> = match gates.clone() {
            #[cfg(feature = "gatekeeper")]
            Gates::Keeper(gk) => Box::new(site::build(gk, manifest, engine, &s, ready)?),
            #[cfg(feature = "store-nex")]
            Gates::Nex(a) => Box::new(site_nex::build(
                a,
                core.access().clone(),
                manifest,
                engine,
                &s,
                site_keys(config, secret_dir, boot.clone())?,
                ready,
            )?),
        };
        sites.push(site);
    }
    let site: Box<dyn gateway_io::WebService> = match profiles {
        None => sites.pop().ok_or_else(|| "no site was built".to_owned())?,
        Some(p) => Box::new(hosts::HostRouter::new(p, sites)),
    };
    let mut watchers = watchers.into_iter();
    let theme = watchers
        .next()
        .ok_or_else(|| "no theme was loaded".to_owned())?;
    Ok(Wiring {
        core,
        site,
        #[cfg(feature = "gatekeeper")]
        gatekeeper,
        #[cfg(feature = "store-nex")]
        nex: shared.nex,
        theme,
        more_themes: watchers.collect(),
        auth_policy,
        guest_pages,
        renders: renders.unwrap_or_default(),
        stages,
        notices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(text: &str) -> Config {
        Config::from_text(text).expect("config")
    }

    #[test]
    fn unknown_keys_and_sections_are_refused() {
        let err = check_keys(&conf("[site]\nhots = [\"example.com\"]\n")).expect_err("typo");
        assert!(err.contains("site.hots"), "{err}");
        let err = check_keys(&conf("[gateway]\nacess_log = true\n")).expect_err("typo");
        assert!(err.contains("gateway.acess_log"), "{err}");
        let err = check_keys(&conf("[sitee]\nhosts = []\n")).expect_err("section");
        assert!(err.contains("sitee"), "{err}");
        assert!(
            check_keys(&conf(
                "[log]\nlevel = \"info\"\n[site]\nhosts = [\"example.com\"]\n[gateway]\naccess_log = true\n[door]\nban = []\n[nex]\npath = \"data/nex\"\n"
            ))
            .is_ok()
        );
    }

    #[test]
    fn the_example_configuration_passes_the_checks() {
        let example = conf(include_str!("../../../deploy/wasp.conf.example"));
        check_keys(&example).expect("known keys");
        check_hosts(&example, true).expect("hosts named");
        let gateway = gateway_io::Settings::from_config(&example).expect("gateway settings");
        assert_eq!((gateway.workers, gateway.passports), (2, 64));
    }

    #[test]
    fn behind_port_the_hosts_must_be_named() {
        let empty = conf("[site]\n");
        assert!(
            check_hosts(&empty, false).is_ok(),
            "no PORT: localhost only"
        );
        let err = check_hosts(&empty, true).expect_err("PORT with no hosts");
        assert!(err.contains("site.hosts"), "{err}");
        assert!(check_hosts(&conf("[site]\nhosts = [\"example.com\"]\n"), true).is_ok());
        assert!(check_hosts(&conf("[site]\ndevelopment = true\n"), true).is_ok());
    }
}
