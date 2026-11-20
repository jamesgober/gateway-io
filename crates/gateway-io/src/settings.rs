//! The gateway's settings, from the `[gateway]` and `[door]` sections.

use std::net::IpAddr;
use std::time::Duration;

use wasp_core::suite::config::Config;

/// The largest `gateway.max_body` accepted: every admitted request may buffer
/// that much.
pub const MAX_BODY_CEILING: u64 = 64 << 20;

/// net-io's driver.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Driver {
    /// One worker per CPU, each owning many connections (the default).
    #[default]
    Reactor,
    /// One thread per connection, `workers` threads; a worker holds one
    /// request at a time, so it gets one passport.
    Blocking,
}

/// What the gateway opens and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The listening address (`[gateway] listen`, default `127.0.0.1:8080`).
    pub listen: String,
    /// Reactor workers (`[gateway] workers`, default one per logical CPU, at most 64).
    pub workers: u16,
    /// Passports per worker: the worker's limit on requests in flight
    /// (`[gateway] passports`, default 256).
    pub passports: u32,
    /// Passports per worker held back from browsing for health checks, the
    /// administrator, and sign-in (`[gateway] reserve`; `None` for the
    /// default, an eighth of `passports`, at least one when there are two).
    pub reserve: Option<u32>,
    /// The load watch sheds browsing on its own at this share of the
    /// passports in use, in percent (`[gateway] shed_passports`, default 90;
    /// 0 turns this reading off).
    pub shed_passports: u8,
    /// The load watch sheds browsing on its own when browsing replies take
    /// this long on average (`[gateway] shed_slow`, default 1 s; "0s" turns
    /// this reading off).
    pub shed_slow: Duration,
    /// How often the load watch reads the load (`[gateway] shed_check`,
    /// default 250 ms, 10 ms to one minute).
    pub shed_check: Duration,
    /// The longest a drain may take (`[gateway] drain`, default 10 s).
    pub drain: Duration,
    /// The head deadline (`[gateway] head_timeout`, default 10 s).
    pub head_timeout: Duration,
    /// The largest buffered body (`[gateway] max_body`, default 1 MiB).
    pub max_body: u64,
    /// Requests per keep-alive connection before the close signal
    /// (`[gateway] keep_alive_requests`, default 1,000).
    pub keep_alive_requests: u32,
    /// net-io's driver (`[gateway] driver`, `reactor` by default, or
    /// `blocking`: one thread per connection, `workers` threads).
    pub driver: Driver,
    /// Stage timing (`[gateway] stage_timing`, default off).
    pub stage_timing: bool,
    /// Threads that answer the routes marked `WorkClass::Cpu` (password
    /// hashing) off the reactor workers (`[gateway] cpu_threads`, default
    /// 2; 0 answers them on the worker).
    pub cpu_threads: u16,
    /// A line per request in the log (`[gateway] access_log`, default off).
    pub access_log: bool,
    /// Addresses banned at the door from boot (`[door] ban`, default none).
    pub ban: Vec<IpAddr>,
    /// Addresses exempt from the door's budgets, for local load tests
    /// (`[door] exempt`, default none).
    pub exempt: Vec<IpAddr>,
    /// How clients reach the listener (`[gateway] ingress`, `direct` by
    /// default, or `proxy` behind a reverse proxy).
    pub ingress: IngressMode,
    /// Budgets per caller on some lanes (none by default): the application
    /// sets them (wasp's `[api] rate`), never the configuration reader.
    pub lane_rates: Vec<LaneRate>,
}

/// A lane's budget for each caller: a signed-in caller (a session or an API
/// key, by the id authentication gave it) or, for a guest, its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneRate {
    /// The lane.
    pub lane: wasp_core::Lane,
    /// Requests a second, at least 1.
    pub per_second: u32,
    /// The most at once after a quiet spell, at least `per_second`.
    pub burst: u32,
}

/// How clients reach the listener.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum IngressMode {
    /// Clients connect themselves; the TCP peer is the client.
    #[default]
    Direct,
    /// Behind a reverse proxy (Apache, nginx): the client is the address the
    /// proxy names in `X-Forwarded-For`, believed only from `trusted`
    /// (`[gateway] trusted_proxies`, required). A request from a trusted
    /// proxy without the header is refused. With `forwarded_proto`
    /// (`[gateway] forwarded_proto`, default true) the scheme comes from
    /// `X-Forwarded-Proto`, so a site behind an https proxy knows it is https.
    Proxy {
        /// The proxies' addresses or blocks (`127.0.0.1`, `10.0.0.0/8`).
        trusted: Vec<String>,
        /// Take the scheme from `X-Forwarded-Proto`.
        forwarded_proto: bool,
    },
}

/// The default worker count behind an application server (`PORT` set), at
/// most.
pub const PORT_WORKERS: u16 = 4;

/// The variable a start shim sets to the Unix socket wasp listens on
/// (`<app>/run/wasp.sock`): it takes the place of `PORT`, and only this
/// account's own processes can connect.
pub const SOCKET_ENV: &str = "WASP_SOCKET";

/// The prefix of a `gateway.listen` that is a Unix socket's path.
pub const UNIX_PREFIX: &str = "unix:";

/// Whether an application server or a start shim runs this process: `PORT`
/// or [`SOCKET_ENV`] is set.
#[must_use]
pub fn behind_front_end() -> bool {
    std::env::var_os("PORT").is_some() || std::env::var_os(SOCKET_ENV).is_some()
}

/// `listen` checked: an address, or `unix:<path>` on a system with Unix
/// sockets.
fn check_listen(listen: &str) -> Result<(), SettingsError> {
    let Some(path) = listen.strip_prefix(UNIX_PREFIX) else {
        return Ok(());
    };
    if path.trim().is_empty() {
        return Err(SettingsError(
            "gateway.listen `unix:` needs the socket's path (`unix:/home/me/app/run/wasp.sock`)"
                .into(),
        ));
    }
    if cfg!(unix) {
        Ok(())
    } else {
        Err(SettingsError(format!(
            "gateway.listen `{listen}` is a Unix socket, which this system does not have: use an address"
        )))
    }
}

/// The keys of the sections the gateway reads.
pub const KNOWN_KEYS: &[(&str, &[&str])] = &[
    (
        "gateway",
        &[
            "access_log",
            "cpu_threads",
            "drain",
            "driver",
            "forwarded_proto",
            "head_timeout",
            "ingress",
            "keep_alive_requests",
            "listen",
            "max_body",
            "passports",
            "reserve",
            "shed_check",
            "shed_passports",
            "shed_slow",
            "stage_timing",
            "trusted_proxies",
            "workers",
        ],
    ),
    ("door", &["ban", "exempt"]),
];

/// Refuses a key not in `known` in each of its sections.
///
/// # Errors
///
/// The first unknown key, with the section's keys.
pub fn check_section_keys(config: &Config, known: &[(&str, &[&str])]) -> Result<(), String> {
    for (section, keys) in known {
        if let Some(unknown) = config.keys(section).into_iter().find(|k| !keys.contains(k)) {
            return Err(format!(
                "unknown key `{section}.{unknown}`: check the spelling; the keys of [{section}] are: {}",
                keys.join(", ")
            ));
        }
    }
    Ok(())
}

fn check_keys(config: &Config) -> Result<(), String> {
    check_section_keys(config, KNOWN_KEYS)
}

impl Default for Settings {
    fn default() -> Settings {
        let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
        Settings {
            listen: "127.0.0.1:8080".to_owned(),
            workers: u16::try_from(cpus.clamp(1, 64)).unwrap_or(4),
            passports: 256,
            reserve: None,
            shed_passports: 90,
            shed_slow: Duration::from_secs(1),
            shed_check: Duration::from_millis(250),
            drain: Duration::from_secs(10),
            head_timeout: Duration::from_secs(10),
            max_body: 1024 * 1024,
            keep_alive_requests: 1000,
            driver: Driver::Reactor,
            stage_timing: false,
            cpu_threads: 2,
            access_log: false,
            ban: Vec::new(),
            exempt: Vec::new(),
            ingress: IngressMode::Direct,
            lane_rates: Vec::new(),
        }
    }
}

/// A setting that is present but wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsError(pub String);

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SettingsError {}

impl Settings {
    /// The passports per worker held back for the reserved lanes: `reserve`,
    /// or an eighth of `passports_per_worker` (at least one when there are
    /// two or more, none with one).
    #[must_use]
    pub fn reserve_for(&self, passports_per_worker: u32) -> u32 {
        let default = if passports_per_worker < 2 {
            0
        } else {
            (passports_per_worker / 8).max(1)
        };
        self.reserve
            .unwrap_or(default)
            .min(passports_per_worker.saturating_sub(1))
    }

    /// What the load watch looks for.
    #[must_use]
    pub fn shed_marks(&self) -> crate::load::ShedMarks {
        crate::load::ShedMarks {
            passports: self.shed_passports,
            slow: self.shed_slow,
        }
    }

    /// Reads the settings; every key is optional, and a key the gateway does
    /// not know in `[gateway]` or `[door]` is refused (a typo never leaves a
    /// setting at its default). Behind an application server (`PORT` or
    /// `WASP_SOCKET` set) the default worker count is at most [`PORT_WORKERS`]: a shared host
    /// reports all of its CPUs, not the account's share.
    pub fn from_config(config: &Config) -> Result<Settings, SettingsError> {
        check_keys(config).map_err(SettingsError)?;
        let d = Settings::default();
        let err = |e: wasp_core::suite::Error| SettingsError(e.to_string());
        let default_workers = if behind_front_end() {
            d.workers.min(PORT_WORKERS)
        } else {
            d.workers
        };
        let workers: u64 = config
            .get_or("gateway.workers", u64::from(default_workers))
            .map_err(err)?;
        let keep_alive: u64 = config
            .get_or(
                "gateway.keep_alive_requests",
                u64::from(d.keep_alive_requests),
            )
            .map_err(err)?;
        let passports: u64 = config
            .get_or("gateway.passports", u64::from(d.passports))
            .map_err(err)?;
        let reserve: Option<u64> = config.get("gateway.reserve").map_err(err)?;
        let shed_passports: u64 = config
            .get_or("gateway.shed_passports", u64::from(d.shed_passports))
            .map_err(err)?;
        let shed_check: Duration = config
            .get_or("gateway.shed_check", d.shed_check)
            .map_err(err)?;
        if !(Duration::from_millis(10)..=Duration::from_secs(60)).contains(&shed_check) {
            return Err(SettingsError(
                "gateway.shed_check must be from 10ms to 60s".into(),
            ));
        }
        let driver: String = config
            .get_or("gateway.driver", "reactor".to_owned())
            .map_err(err)?;
        let driver = match driver.as_str() {
            "reactor" => Driver::Reactor,
            "blocking" => Driver::Blocking,
            other => {
                return Err(SettingsError(format!(
                    "gateway.driver must be `reactor` or `blocking`, not `{other}`"
                )));
            }
        };
        let settings = Settings {
            listen: config.get_or("gateway.listen", d.listen).map_err(err)?,
            workers: u16::try_from(workers)
                .ok()
                .filter(|w| (1..=256).contains(w))
                .ok_or_else(|| SettingsError("gateway.workers must be 1 to 256".into()))?,
            passports: u32::try_from(passports)
                .ok()
                .filter(|p| (1..=65_536).contains(p))
                .ok_or_else(|| SettingsError("gateway.passports must be 1 to 65536".into()))?,
            reserve: match reserve {
                None => None,
                Some(r) if r < passports => u32::try_from(r).ok(),
                Some(_) => {
                    return Err(SettingsError(
                        "gateway.reserve must be less than gateway.passports".into(),
                    ));
                }
            },
            shed_passports: u8::try_from(shed_passports)
                .ok()
                .filter(|p| *p <= 100)
                .ok_or_else(|| {
                    SettingsError("gateway.shed_passports must be 0 to 100 (percent)".into())
                })?,
            shed_slow: config
                .get_or("gateway.shed_slow", d.shed_slow)
                .map_err(err)?,
            shed_check,
            drain: config.get_or("gateway.drain", d.drain).map_err(err)?,
            head_timeout: config
                .get_or("gateway.head_timeout", d.head_timeout)
                .map_err(err)?,
            max_body: {
                let max: u64 = config.get_or("gateway.max_body", d.max_body).map_err(err)?;
                if max > MAX_BODY_CEILING {
                    return Err(SettingsError(format!(
                        "gateway.max_body is at most {MAX_BODY_CEILING} bytes (64 MiB)"
                    )));
                }
                max
            },
            keep_alive_requests: u32::try_from(keep_alive)
                .ok()
                .filter(|n| *n >= 1)
                .ok_or_else(|| {
                    SettingsError("gateway.keep_alive_requests must be 1 to 4294967295".into())
                })?,
            driver,
            stage_timing: config
                .get_or("gateway.stage_timing", d.stage_timing)
                .map_err(err)?,
            cpu_threads: {
                let n: u64 = config
                    .get_or("gateway.cpu_threads", u64::from(d.cpu_threads))
                    .map_err(err)?;
                u16::try_from(n)
                    .ok()
                    .filter(|n| *n <= 64)
                    .ok_or_else(|| SettingsError("gateway.cpu_threads must be 0 to 64".into()))?
            },
            access_log: config
                .get_or("gateway.access_log", d.access_log)
                .map_err(err)?,
            ban: addresses(config, "door.ban")?,
            exempt: addresses(config, "door.exempt")?,
            ingress: ingress(config)?,
            lane_rates: Vec::new(),
        };
        let explicit_ingress = config
            .get::<String>("gateway.ingress")
            .map_err(|e| SettingsError(e.to_string()))?
            .is_some();
        check_listen(&settings.listen)?;
        settings.with_front_end(
            std::env::var("PORT").ok().as_deref(),
            std::env::var(SOCKET_ENV).ok().as_deref(),
            explicit_ingress,
        )
    }

    /// [`with_port`](Self::with_port), or with `socket` (the start shim's
    /// [`SOCKET_ENV`]) the gateway listens on that Unix socket instead,
    /// whatever `PORT` and `gateway.listen` say; the ingress is as for
    /// `PORT`. Only processes of this account's user may connect to it.
    pub fn with_front_end(
        self,
        port: Option<&str>,
        socket: Option<&str>,
        explicit_ingress: bool,
    ) -> Result<Settings, SettingsError> {
        let Some(socket) = socket else {
            return self.with_port(port, explicit_ingress);
        };
        let listen = format!("{UNIX_PREFIX}{socket}");
        check_listen(&listen).map_err(|_| {
            SettingsError(format!(
                "{SOCKET_ENV} must be a Unix socket's path on a system that has them, not `{socket}`"
            ))
        })?;
        let mut s = self;
        s.listen = listen;
        s.trust_front_end(explicit_ingress);
        Ok(s)
    }

    /// The settings for a process an application server starts (Phusion
    /// Passenger, cPanel's application setup): with `port` (the `PORT` it
    /// sets), the gateway listens on `127.0.0.1:<port>` whatever
    /// `gateway.listen` says, and, unless `gateway.ingress` was configured
    /// (`explicit_ingress`), sits behind that local front end: proxy ingress
    /// trusting only loopback. Without `port`, nothing changes.
    pub fn with_port(
        mut self,
        port: Option<&str>,
        explicit_ingress: bool,
    ) -> Result<Settings, SettingsError> {
        let Some(port) = port else {
            return Ok(self);
        };
        let port: u16 = port
            .trim()
            .parse()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| SettingsError(format!("PORT must be a port number, not `{port}`")))?;
        self.listen = format!("127.0.0.1:{port}");
        self.trust_front_end(explicit_ingress);
        Ok(self)
    }

    /// Unless `gateway.ingress` was configured (`explicit_ingress`), the
    /// local front end names the client: proxy ingress trusting only
    /// loopback.
    fn trust_front_end(&mut self, explicit_ingress: bool) {
        if !explicit_ingress {
            self.ingress = IngressMode::Proxy {
                trusted: vec!["127.0.0.1".into(), "::1".into()],
                forwarded_proto: true,
            };
        }
    }
}

fn ingress(config: &Config) -> Result<IngressMode, SettingsError> {
    let err = |e: wasp_core::suite::Error| SettingsError(e.to_string());
    let mode: String = config
        .get_or("gateway.ingress", "direct".to_owned())
        .map_err(err)?;
    match mode.as_str() {
        "direct" => Ok(IngressMode::Direct),
        "proxy" => {
            let trusted: Vec<String> = config
                .get_or("gateway.trusted_proxies", Vec::new())
                .map_err(err)?;
            if trusted.is_empty() {
                return Err(SettingsError(
                    "gateway.ingress = \"proxy\" needs gateway.trusted_proxies (the proxies' addresses)"
                        .into(),
                ));
            }
            for t in &trusted {
                net_io::Cidr::parse(t)
                    .map_err(|e| SettingsError(format!("gateway.trusted_proxies: `{t}`: {e}")))?;
            }
            Ok(IngressMode::Proxy {
                trusted,
                forwarded_proto: config
                    .get_or("gateway.forwarded_proto", true)
                    .map_err(err)?,
            })
        }
        other => Err(SettingsError(format!(
            "gateway.ingress must be `direct` or `proxy`, not `{other}`"
        ))),
    }
}

impl IngressMode {
    /// The trusted proxies as CIDR blocks (empty for direct ingress).
    #[must_use]
    pub fn trusted(&self) -> Vec<net_io::Cidr> {
        match self {
            IngressMode::Direct => Vec::new(),
            IngressMode::Proxy { trusted, .. } => trusted
                .iter()
                .filter_map(|t| net_io::Cidr::parse(t).ok())
                .collect(),
        }
    }
}

fn addresses(config: &Config, key: &str) -> Result<Vec<IpAddr>, SettingsError> {
    let list: Vec<String> = config
        .get_or(key, Vec::new())
        .map_err(|e| SettingsError(e.to_string()))?;
    list.iter()
        .map(|a| {
            a.parse()
                .map_err(|_| SettingsError(format!("{key}: `{a}` is not an IP address")))
        })
        .collect()
}
