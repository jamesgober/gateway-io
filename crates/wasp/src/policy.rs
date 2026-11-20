//! The sign-in settings: `[auth.password]`, `[auth.mfa]`, `[auth.session]`,
//! `[auth.lockout]`, and per-role overrides in `[auth.role.<role>]`. Read at
//! boot and on every configuration reload; a value under a hard floor
//! refuses the boot, or the reload (the running settings stay).
//!
//! | Key | Default | Floor |
//! |---|---|---|
//! | `auth.password.min_length` | 12 | at least 8 |
//! | `auth.password.max_length` | 128 | the minimum to 1024 |
//! | `auth.password.require_upper`, `require_lower`, `require_digit`, `require_symbol` | false | |
//! | `auth.mfa.enabled` | false | needs the `mfa` feature |
//! | `auth.mfa.mode` | `optional` | `off`, `optional`, `required` (`required` needs `enabled`) |
//! | `auth.mfa.methods` | `["totp"]` | `totp` only |
//! | `auth.mfa.remember_device` | `30d` | `0` (never) to `400d` |
//! | `auth.mfa.every_login` | false | |
//! | `auth.mfa.recovery_codes` | 10 | 0 to 10 |
//! | `auth.session.idle` | `7d` | `0` (none) or at least `1m` |
//! | `auth.session.absolute` | `30d` | `1m` to `400d` |
//! | `auth.session.max_concurrent` | 0 (no cap) | |
//! | `auth.session.recheck` | `1m` | `1s` to `1h` |
//! | `auth.lockout.attempts` | 10 | 1 to 1000 |
//! | `auth.lockout.window` | `15m` | at least `1s` |
//! | `auth.lockout.duration` | `15m` | at least `1s` |
//! | `auth.lockout.address_attempts` | 10 | 1 to 100000 |
//! | `auth.lockout.address_window` | `10m` | at least `1s` |
//!
//! A role table takes the `password` keys, `mfa.mode`,
//! `mfa.remember_device`, `mfa.every_login`, and the `session` keys but
//! `recheck`. An account with several roles gets the strictest of each.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use wasp_core::suite::config::Config;

/// The roles a `[auth.role.<role>]` table may name.
pub const ROLES: &[&str] = &["member", "editor", "admin"];

/// The longest a session or a remembered device lasts (nex-db's limit).
pub const MAX_DAYS: Duration = Duration::from_secs(400 * 24 * 60 * 60);

/// The longest password nex-db takes, in bytes.
pub const PASSWORD_CAP: usize = 1024;

/// The shortest minimum password length a configuration may set.
pub const MIN_LENGTH_FLOOR: usize = 8;

/// The most recovery codes nex-db makes.
pub const RECOVERY_CAP: usize = 10;

/// Two-step sign-in for a role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MfaMode {
    /// Not offered (an account that has it on is still asked for codes).
    Off,
    /// Offered on the account page.
    Optional,
    /// Every account with the role must have it: set up at sign-in.
    Required,
}

impl MfaMode {
    fn parse(text: &str, key: &str) -> Result<MfaMode, String> {
        match text {
            "off" => Ok(MfaMode::Off),
            "optional" => Ok(MfaMode::Optional),
            "required" => Ok(MfaMode::Required),
            other => Err(format!(
                "{key} must be `off`, `optional`, or `required`, not `{other}`"
            )),
        }
    }
}

/// The settings for one account (its roles' strictest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rules {
    /// The shortest password, in characters.
    pub min_length: usize,
    /// The longest password, in characters.
    pub max_length: usize,
    /// An upper-case letter is required.
    pub upper: bool,
    /// A lower-case letter is required.
    pub lower: bool,
    /// A digit is required.
    pub digit: bool,
    /// A character that is not a letter or a digit is required.
    pub symbol: bool,
    /// Two-step sign-in for the account.
    pub mfa: MfaMode,
    /// How long a remembered device skips the code (zero: never).
    pub remember: Duration,
    /// A code at every sign-in, even on a remembered device.
    pub every_login: bool,
    /// A session ends after this long unused (zero: no idle limit).
    pub idle: Duration,
    /// A session ends this long after sign-in, used or not.
    pub absolute: Duration,
    /// The most sessions the account holds at once (zero: no cap); a new
    /// sign-in past it ends the oldest.
    pub max_sessions: u32,
}

impl Default for Rules {
    fn default() -> Rules {
        Rules {
            min_length: 12,
            max_length: 128,
            upper: false,
            lower: false,
            digit: false,
            symbol: false,
            mfa: MfaMode::Optional,
            remember: Duration::from_secs(30 * 24 * 60 * 60),
            every_login: false,
            idle: Duration::from_secs(7 * 24 * 60 * 60),
            absolute: Duration::from_secs(30 * 24 * 60 * 60),
            max_sessions: 0,
        }
    }
}

impl Rules {
    /// The stricter of `self` and `other`, key by key.
    #[must_use]
    pub fn strictest(&self, other: &Rules) -> Rules {
        let shortest_nonzero = |a: Duration, b: Duration| match (a.is_zero(), b.is_zero()) {
            (true, _) => b,
            (_, true) => a,
            _ => a.min(b),
        };
        let min_length = self.min_length.max(other.min_length);
        Rules {
            min_length,
            max_length: self.max_length.min(other.max_length).max(min_length),
            upper: self.upper || other.upper,
            lower: self.lower || other.lower,
            digit: self.digit || other.digit,
            symbol: self.symbol || other.symbol,
            mfa: self.mfa.max(other.mfa),
            // Zero (never remember) is the strictest.
            remember: self.remember.min(other.remember),
            every_login: self.every_login || other.every_login,
            // Zero (no idle limit) is the loosest.
            idle: shortest_nonzero(self.idle, other.idle),
            absolute: self.absolute.min(other.absolute),
            max_sessions: match (self.max_sessions, other.max_sessions) {
                (0, b) => b,
                (a, 0) => a,
                (a, b) => a.min(b),
            },
        }
    }

    /// Why `password` breaks these rules, in words for the person typing it;
    /// `None` when it keeps them.
    #[must_use]
    pub fn refuse(&self, password: &str) -> Option<String> {
        let n = password.chars().count();
        if n < self.min_length {
            return Some(format!(
                "The password must be at least {} characters.",
                self.min_length
            ));
        }
        if n > self.max_length || password.len() > PASSWORD_CAP {
            return Some(format!(
                "The password must be at most {} characters.",
                self.max_length
            ));
        }
        let mut missing = Vec::new();
        if self.upper && !password.chars().any(char::is_uppercase) {
            missing.push("an upper-case letter");
        }
        if self.lower && !password.chars().any(char::is_lowercase) {
            missing.push("a lower-case letter");
        }
        if self.digit && !password.chars().any(|c| c.is_ascii_digit()) {
            missing.push("a digit");
        }
        if self.symbol && !password.chars().any(|c| !c.is_alphanumeric()) {
            missing.push("a character that is not a letter or a digit");
        }
        if missing.is_empty() {
            None
        } else {
            Some(format!("The password needs {}.", missing.join(", ")))
        }
    }
}

/// The lockout settings (every account, and every client address).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lockout {
    /// Failed sign-ins (passwords and codes) of one account within
    /// `window` that lock it out.
    pub attempts: u32,
    /// The window `attempts` are counted in.
    pub window: Duration,
    /// How long a lockout lasts.
    pub duration: Duration,
    /// Sign-in attempts one client address may make per `address_window`.
    pub address_attempts: u32,
    /// The window `address_attempts` are counted in.
    pub address_window: Duration,
}

impl Default for Lockout {
    fn default() -> Lockout {
        Lockout {
            attempts: 10,
            window: Duration::from_secs(15 * 60),
            duration: Duration::from_secs(15 * 60),
            address_attempts: 10,
            address_window: Duration::from_secs(10 * 60),
        }
    }
}

/// Every sign-in setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Two-step sign-in is offered at all.
    pub mfa_enabled: bool,
    /// Recovery codes shown when two-step sign-in is turned on.
    pub recovery_codes: usize,
    /// How often a session's roles and standing are read again.
    pub recheck: Duration,
    /// The lockout.
    pub lockout: Lockout,
    base: Rules,
    roles: Vec<(String, Rules)>,
}

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            mfa_enabled: false,
            recovery_codes: RECOVERY_CAP,
            recheck: Duration::from_secs(60),
            lockout: Lockout::default(),
            base: Rules::default(),
            roles: Vec::new(),
        }
    }
}

/// The settings in force, swapped whole by a reload.
#[derive(Clone, Debug, Default)]
pub struct PolicyCell(Arc<RwLock<Arc<Policy>>>);

impl PolicyCell {
    /// A cell holding `policy`.
    #[must_use]
    pub fn new(policy: Policy) -> PolicyCell {
        PolicyCell(Arc::new(RwLock::new(Arc::new(policy))))
    }

    /// The settings now.
    #[must_use]
    pub fn get(&self) -> Arc<Policy> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Puts `policy` in force.
    pub fn set(&self, policy: Policy) {
        *self
            .0
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(policy);
    }
}

/// `"30d"`, `"12h"`, `"15m"`, `"30s"`, `"500ms"`, or `"0"`.
pub fn parse_duration(text: &str) -> Option<Duration> {
    let text = text.trim();
    if text == "0" {
        return Some(Duration::ZERO);
    }
    let split = text.find(|c: char| !c.is_ascii_digit())?;
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().ok()?;
    let millis: u64 = match unit.trim() {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return None,
    };
    number.checked_mul(millis).map(Duration::from_millis)
}

const PASSWORD_KEYS: &[&str] = &[
    "max_length",
    "min_length",
    "require_digit",
    "require_lower",
    "require_symbol",
    "require_upper",
];
const MFA_KEYS: &[&str] = &[
    "enabled",
    "every_login",
    "methods",
    "mode",
    "recovery_codes",
    "remember_device",
];
const MFA_ROLE_KEYS: &[&str] = &["every_login", "mode", "remember_device"];
const SESSION_KEYS: &[&str] = &["absolute", "idle", "max_concurrent", "recheck"];
const SESSION_ROLE_KEYS: &[&str] = &["absolute", "idle", "max_concurrent"];
const LOCKOUT_KEYS: &[&str] = &[
    "address_attempts",
    "address_window",
    "attempts",
    "duration",
    "window",
];

/// The tables under `[auth]` this module reads.
pub const TABLES: &[&str] = &["lockout", "mfa", "password", "role", "session"];

/// Whether the configuration sets any sign-in table.
#[must_use]
pub fn any_set(config: &Config) -> bool {
    TABLES.iter().any(|t| config.contains(&format!("auth.{t}")))
}

fn known(config: &Config, section: &str, keys: &[&str]) -> Result<(), String> {
    if let Some(k) = config.keys(section).into_iter().find(|k| !keys.contains(k)) {
        return Err(format!(
            "unknown key `{section}.{k}`: check the spelling; the keys of [{section}] are: {}",
            keys.join(", ")
        ));
    }
    Ok(())
}

struct Reader<'a>(&'a Config);

impl Reader<'_> {
    fn bool(&self, key: &str, default: bool) -> Result<bool, String> {
        self.0.get_or(key, default).map_err(|e| e.to_string())
    }

    fn count(&self, key: &str, default: u64) -> Result<u64, String> {
        self.0.get_or(key, default).map_err(|e| e.to_string())
    }

    fn duration(&self, key: &str, default: Duration) -> Result<Duration, String> {
        match self.0.get::<String>(key) {
            Ok(Some(text)) => parse_duration(&text).ok_or_else(|| {
                format!("{key} must be a time like `30s`, `15m`, `12h`, or `30d`, not `{text}`")
            }),
            Ok(None) => Ok(default),
            // A bare number: only zero means anything without a unit.
            Err(_) => match self.0.get::<u64>(key) {
                Ok(Some(0)) => Ok(Duration::ZERO),
                _ => Err(format!(
                    "{key} must be a time like `30s`, `15m`, `12h`, or `30d`"
                )),
            },
        }
    }

    fn text(&self, key: &str) -> Result<Option<String>, String> {
        self.0.get(key).map_err(|e| e.to_string())
    }
}

/// Reads one set of rules from `prefix` (`auth` or `auth.role.<role>`),
/// starting from `from`.
fn rules(r: &Reader<'_>, prefix: &str, from: &Rules) -> Result<Rules, String> {
    let k = |table: &str, key: &str| format!("{prefix}.{table}.{key}");
    let min_length = r.count(&k("password", "min_length"), from.min_length as u64)?;
    let max_length = r.count(&k("password", "max_length"), from.max_length as u64)?;
    let min_length = usize::try_from(min_length).unwrap_or(usize::MAX);
    let max_length = usize::try_from(max_length).unwrap_or(usize::MAX);
    if min_length < MIN_LENGTH_FLOOR {
        return Err(format!(
            "{} is {min_length}: it must be at least {MIN_LENGTH_FLOOR}",
            k("password", "min_length")
        ));
    }
    if max_length < min_length || max_length > PASSWORD_CAP {
        return Err(format!(
            "{} is {max_length}: it must be between the minimum length ({min_length}) and {PASSWORD_CAP}",
            k("password", "max_length")
        ));
    }
    let mfa = match r.text(&k("mfa", "mode"))? {
        Some(text) => MfaMode::parse(&text, &k("mfa", "mode"))?,
        None => from.mfa,
    };
    let remember = r.duration(&k("mfa", "remember_device"), from.remember)?;
    if remember > MAX_DAYS {
        return Err(format!(
            "{} is longer than 400 days",
            k("mfa", "remember_device")
        ));
    }
    let idle = r.duration(&k("session", "idle"), from.idle)?;
    if !idle.is_zero() && idle < Duration::from_secs(60) {
        return Err(format!(
            "{} must be `0` (no idle limit) or at least `1m`",
            k("session", "idle")
        ));
    }
    let absolute = r.duration(&k("session", "absolute"), from.absolute)?;
    if absolute < Duration::from_secs(60) || absolute > MAX_DAYS {
        return Err(format!(
            "{} must be between `1m` and `400d`",
            k("session", "absolute")
        ));
    }
    let max_sessions = r.count(
        &k("session", "max_concurrent"),
        u64::from(from.max_sessions),
    )?;
    Ok(Rules {
        min_length,
        max_length,
        upper: r.bool(&k("password", "require_upper"), from.upper)?,
        lower: r.bool(&k("password", "require_lower"), from.lower)?,
        digit: r.bool(&k("password", "require_digit"), from.digit)?,
        symbol: r.bool(&k("password", "require_symbol"), from.symbol)?,
        mfa,
        remember,
        every_login: r.bool(&k("mfa", "every_login"), from.every_login)?,
        idle,
        absolute,
        max_sessions: u32::try_from(max_sessions).unwrap_or(u32::MAX),
    })
}

impl Policy {
    /// The settings `config` sets. `mfa_built`: whether this build has
    /// two-step sign-in (the `mfa` feature).
    pub fn from_config(config: &Config, mfa_built: bool) -> Result<Policy, String> {
        known(config, "auth.password", PASSWORD_KEYS)?;
        known(config, "auth.mfa", MFA_KEYS)?;
        known(config, "auth.session", SESSION_KEYS)?;
        known(config, "auth.lockout", LOCKOUT_KEYS)?;
        let r = Reader(config);
        let mfa_enabled = r.bool("auth.mfa.enabled", false)?;
        if mfa_enabled && !mfa_built {
            return Err(
                "auth.mfa.enabled is true, but this build has no two-step sign-in: build wasp with the `mfa` feature"
                    .to_owned(),
            );
        }
        let methods: Vec<String> = config
            .get_or("auth.mfa.methods", vec!["totp".to_owned()])
            .map_err(|e| e.to_string())?;
        if let Some(m) = methods.iter().find(|m| m.as_str() != "totp") {
            return Err(format!(
                "auth.mfa.methods names `{m}`: the only method is `totp`"
            ));
        }
        if mfa_enabled && methods.is_empty() {
            return Err("auth.mfa.methods is empty while auth.mfa.enabled is true".to_owned());
        }
        let recovery = r.count("auth.mfa.recovery_codes", RECOVERY_CAP as u64)?;
        if recovery > RECOVERY_CAP as u64 {
            return Err(format!(
                "auth.mfa.recovery_codes is {recovery}: at most {RECOVERY_CAP}"
            ));
        }
        let recheck = r.duration("auth.session.recheck", Duration::from_secs(60))?;
        if recheck < Duration::from_secs(1) || recheck > Duration::from_secs(3600) {
            return Err("auth.session.recheck must be between `1s` and `1h`".to_owned());
        }
        let lockout = Lockout {
            attempts: u32::try_from(r.count("auth.lockout.attempts", 10)?).unwrap_or(u32::MAX),
            window: r.duration("auth.lockout.window", Duration::from_secs(15 * 60))?,
            duration: r.duration("auth.lockout.duration", Duration::from_secs(15 * 60))?,
            address_attempts: u32::try_from(r.count("auth.lockout.address_attempts", 10)?)
                .unwrap_or(u32::MAX),
            address_window: r.duration("auth.lockout.address_window", Duration::from_secs(600))?,
        };
        if lockout.attempts == 0 || lockout.attempts > 1000 {
            return Err(format!(
                "auth.lockout.attempts is {}: it must be between 1 and 1000 (an account is never left without a lockout)",
                lockout.attempts
            ));
        }
        if lockout.address_attempts == 0 || lockout.address_attempts > 100_000 {
            return Err("auth.lockout.address_attempts must be between 1 and 100000".to_owned());
        }
        for (key, d) in [
            ("auth.lockout.window", lockout.window),
            ("auth.lockout.duration", lockout.duration),
            ("auth.lockout.address_window", lockout.address_window),
        ] {
            if d < Duration::from_secs(1) {
                return Err(format!("{key} must be at least `1s`"));
            }
        }
        let base = rules(&r, "auth", &Rules::default())?;
        let mut roles = Vec::new();
        for role in config.keys("auth.role") {
            if !ROLES.contains(&role) {
                return Err(format!(
                    "auth.role.{role}: no such role; the roles are {}",
                    ROLES.join(", ")
                ));
            }
            let at = format!("auth.role.{role}");
            known(config, &at, &["mfa", "password", "session"])?;
            known(config, &format!("{at}.password"), PASSWORD_KEYS)?;
            known(config, &format!("{at}.mfa"), MFA_ROLE_KEYS)?;
            known(config, &format!("{at}.session"), SESSION_ROLE_KEYS)?;
            roles.push((role.to_owned(), rules(&r, &at, &base)?));
        }
        let policy = Policy {
            mfa_enabled,
            recovery_codes: usize::try_from(recovery).unwrap_or(RECOVERY_CAP),
            recheck,
            lockout,
            base,
            roles,
        };
        if !mfa_enabled {
            let required = std::iter::once(("every role", &policy.base))
                .chain(policy.roles.iter().map(|(n, r)| (n.as_str(), r)))
                .find(|(_, r)| r.mfa == MfaMode::Required);
            if let Some((who, _)) = required {
                return Err(format!(
                    "two-step sign-in is `required` for {who}, but auth.mfa.enabled is false"
                ));
            }
        }
        Ok(policy)
    }

    /// The rules for an account holding `roles`: the strictest of their
    /// tables (the base rules for a role without one, or no role).
    #[must_use]
    pub fn rules_for<'a>(&self, roles: impl IntoIterator<Item = &'a str>) -> Rules {
        let mut out: Option<Rules> = None;
        for role in roles {
            let r = self
                .roles
                .iter()
                .find(|(n, _)| n == role)
                .map_or(&self.base, |(_, r)| r);
            out = Some(match out {
                Some(o) => o.strictest(r),
                None => r.clone(),
            });
        }
        let mut rules = out.unwrap_or_else(|| self.base.clone());
        if !self.mfa_enabled {
            rules.mfa = MfaMode::Off;
        }
        rules
    }
}

/// The kernel subsystem that reads the sign-in settings again on every
/// configuration reload: a reload that breaks a floor is refused (and the
/// running settings stay); one that passes swaps them in, then runs
/// `applied` (which writes the lockout into the database).
pub struct PolicyReload {
    cell: PolicyCell,
    mfa_built: bool,
    applied: Arc<dyn Fn(&Policy) + Send + Sync>,
}

impl std::fmt::Debug for PolicyReload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyReload")
            .field("policy", &self.cell.get())
            .finish_non_exhaustive()
    }
}

impl PolicyReload {
    /// Reloads into `cell`, then calls `applied` with the new settings.
    #[must_use]
    pub fn new(
        cell: PolicyCell,
        mfa_built: bool,
        applied: impl Fn(&Policy) + Send + Sync + 'static,
    ) -> PolicyReload {
        PolicyReload {
            cell,
            mfa_built,
            applied: Arc::new(applied),
        }
    }
}

impl wasp_core::suite::lifecycle::Subsystem for PolicyReload {
    fn name(&self) -> &str {
        "auth-policy"
    }

    fn start(
        &mut self,
        _link: &wasp_core::suite::lifecycle::Link,
    ) -> Result<(), wasp_core::suite::lifecycle::Failure> {
        Ok(())
    }

    fn stop(
        &mut self,
        _deadline: wasp_core::suite::lifecycle::Deadline,
    ) -> Result<(), wasp_core::suite::lifecycle::Failure> {
        Ok(())
    }

    fn reload(
        &mut self,
        config: &Config,
    ) -> Result<wasp_core::suite::lifecycle::Commit, wasp_core::suite::lifecycle::Failure> {
        let policy = Policy::from_config(config, self.mfa_built)
            .map_err(wasp_core::suite::lifecycle::Failure::new)?;
        let cell = self.cell.clone();
        let applied = self.applied.clone();
        Ok(wasp_core::suite::lifecycle::Commit::new(move || {
            cell.set(policy.clone());
            applied(&policy);
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(text: &str) -> Result<Policy, String> {
        let config = wasp_core::suite::config::Config::from_text(text).expect("toml");
        Policy::from_config(&config, true)
    }

    #[test]
    fn the_defaults_hold_without_any_table() {
        let p = policy("").expect("defaults");
        assert_eq!(p, Policy::default());
        let r = p.rules_for(["member"]);
        assert_eq!(r.min_length, 12);
        assert_eq!(r.mfa, MfaMode::Off, "two-step is off until enabled");
    }

    #[test]
    fn every_floor_refuses() {
        for (text, says) in [
            ("[auth.password]\nmin_length = 7\n", "at least 8"),
            ("[auth.password]\nmax_length = 2000\n", "1024"),
            (
                "[auth.password]\nmin_length = 20\nmax_length = 16\n",
                "between",
            ),
            (
                "[auth.lockout]\nattempts = 0\n",
                "never left without a lockout",
            ),
            ("[auth.lockout]\nwindow = \"0\"\n", "at least `1s`"),
            ("[auth.session]\nabsolute = \"401d\"\n", "400d"),
            ("[auth.session]\nidle = \"30s\"\n", "at least `1m`"),
            ("[auth.mfa]\nrecovery_codes = 11\n", "at most 10"),
            ("[auth.mfa]\nmethods = [\"sms\"]\n", "only method"),
            ("[auth.mfa]\nmode = \"required\"\n", "enabled is false"),
            (
                "[auth.role.admin.mfa]\nmode = \"required\"\n",
                "required` for admin",
            ),
            (
                "[auth.role.owner.password]\nmin_length = 20\n",
                "no such role",
            ),
            ("[auth.password]\nminlength = 20\n", "unknown key"),
            ("[auth.session]\nidle = \"7 days\"\n", "a time like"),
        ] {
            let e = policy(text).expect_err(text);
            assert!(e.contains(says), "{text}: {e}");
        }
    }

    #[test]
    fn mfa_needs_the_feature() {
        let config = wasp_core::suite::config::Config::from_text("[auth.mfa]\nenabled = true\n")
            .expect("toml");
        let e = Policy::from_config(&config, false).expect_err("no feature");
        assert!(e.contains("`mfa` feature"), "{e}");
    }

    #[test]
    fn several_roles_get_the_strictest_of_each() {
        let p = policy(
            "[auth.mfa]\nenabled = true\nremember_device = \"30d\"\n\
             [auth.session]\nmax_concurrent = 5\n\
             [auth.role.editor.password]\nmin_length = 16\n\
             [auth.role.editor.session]\nidle = \"1h\"\n\
             [auth.role.admin.mfa]\nmode = \"required\"\nremember_device = \"0\"\n\
             [auth.role.admin.session]\nmax_concurrent = 2\nabsolute = \"1d\"\n",
        )
        .expect("policy");
        let member = p.rules_for(["member"]);
        assert_eq!(member.min_length, 12);
        assert_eq!(member.mfa, MfaMode::Optional);
        let all = p.rules_for(["member", "editor", "admin"]);
        assert_eq!(all.min_length, 16);
        assert_eq!(all.mfa, MfaMode::Required);
        assert_eq!(all.remember, Duration::ZERO);
        assert_eq!(all.idle, Duration::from_secs(3600));
        assert_eq!(all.absolute, Duration::from_secs(86_400));
        assert_eq!(all.max_sessions, 2);
    }

    #[test]
    fn a_password_is_checked_against_the_rules() {
        let rules = Rules {
            upper: true,
            digit: true,
            ..Rules::default()
        };
        assert!(
            rules
                .refuse("short")
                .expect("short")
                .contains("at least 12")
        );
        let e = rules.refuse("all lower case letters").expect("classes");
        assert!(e.contains("upper-case") && e.contains("digit"), "{e}");
        assert_eq!(rules.refuse("Twelve chars 1"), None);
    }

    #[test]
    fn durations_take_days() {
        assert_eq!(
            parse_duration("30d"),
            Some(Duration::from_secs(30 * 86_400))
        );
        assert_eq!(parse_duration("0"), Some(Duration::ZERO));
        assert_eq!(parse_duration("12h"), Some(Duration::from_secs(43_200)));
        assert_eq!(parse_duration("7 days"), None);
    }
}
