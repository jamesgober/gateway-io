//! The gateway's settings, from the `[gateway]` and `[door]` sections.

use std::net::IpAddr;
use std::time::Duration;

use wasp_core::suite::config::Config;

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
    /// The longest a drain may take (`[gateway] drain`, default 10 s).
    pub drain: Duration,
    /// The head deadline (`[gateway] head_timeout`, default 10 s).
    pub head_timeout: Duration,
    /// The largest buffered body (`[gateway] max_body`, default 1 MiB).
    pub max_body: u64,
    /// Requests per keep-alive connection before the close signal
    /// (`[gateway] keep_alive_requests`, default 1,000).
    pub keep_alive_requests: u32,
    /// Addresses banned at the door from boot (`[door] ban`, default none).
    pub ban: Vec<IpAddr>,
    /// Addresses exempt from the door's budgets, for local load tests
    /// (`[door] exempt`, default none).
    pub exempt: Vec<IpAddr>,
}

impl Default for Settings {
    fn default() -> Settings {
        let cpus = std::thread::available_parallelism().map_or(4, |n| n.get());
        Settings {
            listen: "127.0.0.1:8080".to_owned(),
            workers: u16::try_from(cpus.clamp(1, 64)).unwrap_or(4),
            passports: 256,
            drain: Duration::from_secs(10),
            head_timeout: Duration::from_secs(10),
            max_body: 1024 * 1024,
            keep_alive_requests: 1000,
            ban: Vec::new(),
            exempt: Vec::new(),
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
    /// Reads the settings; every key is optional.
    pub fn from_config(config: &Config) -> Result<Settings, SettingsError> {
        let d = Settings::default();
        let err = |e: wasp_core::suite::Error| SettingsError(e.to_string());
        let workers: u64 = config
            .get_or("gateway.workers", u64::from(d.workers))
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
            drain: config.get_or("gateway.drain", d.drain).map_err(err)?,
            head_timeout: config
                .get_or("gateway.head_timeout", d.head_timeout)
                .map_err(err)?,
            max_body: config.get_or("gateway.max_body", d.max_body).map_err(err)?,
            keep_alive_requests: u32::try_from(keep_alive)
                .ok()
                .filter(|n| *n >= 1)
                .ok_or_else(|| {
                    SettingsError("gateway.keep_alive_requests must be 1 to 4294967295".into())
                })?,
            ban: addresses(config, "door.ban")?,
            exempt: addresses(config, "door.exempt")?,
        };
        Ok(settings)
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
