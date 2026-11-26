//! Backups of a running site (G-89): nex-db's own online backup of the
//! database, and the master secret beside it, so a backup restores into a
//! site that serves the same accounts, sessions, keys, content and
//! messages.
//!
//! ```text
//!  <backup.path>/
//!  ├─ nex/        nex-db's backup: a base, then the log since, appended
//!  └─ gate.key    the master secret (owner-only), as it was at the backup
//! ```
//!
//! A backup is made when the site starts, every `backup.every` while it
//! runs, and once more when it stops cleanly. nex-db writes its base while
//! writes wait (reads go on) and later backups append only what was
//! committed since. A plain copy of the database folder while the site
//! runs is not a backup: use these, or copy the folder while it is
//! stopped. `wasp restore` makes a data folder from one.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use wasp_core::suite::config::Config;
use wasp_core::suite::lifecycle::{Deadline, Failure, Link, Subsystem};
use wasp_core::suite::log;

use crate::nex::NexDb;

/// The backups' settings (`[backup]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupSettings {
    /// Where backups go (`backup.path`): a folder of their own.
    pub path: PathBuf,
    /// How often a running site backs up (`backup.every`, 1 h).
    pub every: Duration,
}

/// The keys of `[backup]`.
pub const KEYS: &[&str] = &["every", "path"];

impl BackupSettings {
    /// Reads `[backup]`: `None` when `backup.path` is not set (no backups).
    ///
    /// # Errors
    ///
    /// When `backup.every` is under a minute or over a week.
    pub fn from_config(config: &Config) -> Result<Option<BackupSettings>, String> {
        let e = |e: wasp_core::suite::Error| e.to_string();
        let Some(path) = config.get::<PathBuf>("backup.path").map_err(e)? else {
            return Ok(None);
        };
        let every: Duration = config
            .get_or("backup.every", Duration::from_secs(3600))
            .map_err(e)?;
        if every < Duration::from_secs(60) || every > Duration::from_secs(7 * 24 * 3600) {
            return Err("backup.every must be 1m to 7d".to_owned());
        }
        Ok(Some(BackupSettings { path, every }))
    }
}

/// What one backup did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Made {
    /// Whether it appended to the backup there (else it wrote a base).
    pub incremental: bool,
    /// Whether the master secret was copied beside it.
    pub secret: bool,
    /// The backup that could not be added to and was put aside, when one
    /// was.
    pub set_aside: Option<PathBuf>,
}

/// Makes one backup of `db` into `to`, with the master secret at `secret`
/// copied beside it. A backup the database can no longer add to (its log
/// moved past it) is put aside as `nex.<time>.old`, and a new one begun.
///
/// # Errors
///
/// When the folder cannot be made, or nex-db cannot back up.
pub fn make(db: &NexDb, to: &Path, secret: Option<&Path>) -> Result<Made, String> {
    std::fs::create_dir_all(to).map_err(|e| format!("backup.path {}: {e}", to.display()))?;
    private(to);
    let into = to.join("nex");
    let mut set_aside = None;
    let incremental = match db.backup(&into) {
        Ok(incremental) => incremental,
        Err(e) if e.kind() == crate::content::StoreErrorKind::Invalid && into.exists() => {
            let at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let old = to.join(format!("nex.{at}.old"));
            std::fs::rename(&into, &old)
                .map_err(|e| format!("backup.path: setting {} aside: {e}", into.display()))?;
            set_aside = Some(old);
            prune_set_aside(to);
            db.backup(&into).map_err(|e| e.to_string())?
        }
        Err(e) => return Err(e.to_string()),
    };
    let secret = match secret.filter(|s| s.exists()) {
        Some(s) => {
            crate::secret::copy(s, &to.join("gate.key"))?;
            true
        }
        None => false,
    };
    Ok(Made {
        incremental,
        secret,
        set_aside,
    })
}

/// How many backups put aside are kept: the newest, the oldest go.
const KEEP_SET_ASIDE: usize = 2;

/// Removes the backups put aside in `to` but the newest
/// [`KEEP_SET_ASIDE`]: each restart of the database begins a new one, and
/// the old ones are complete copies.
fn prune_set_aside(to: &Path) {
    let Ok(entries) = std::fs::read_dir(to) else {
        return;
    };
    let mut old: Vec<(u64, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let at: u64 = name
                .strip_prefix("nex.")?
                .strip_suffix(".old")?
                .parse()
                .ok()?;
            Some((at, e.path()))
        })
        .collect();
    old.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
    for (_, path) in old.into_iter().skip(KEEP_SET_ASIDE) {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// Makes a data folder from a backup: the database into `<data>/nex`, at
/// the last commit the backup holds, and the master secret beside it.
/// Revocations made after the backup's point are applied again when the
/// restored database first opens, so a restore never brings back access
/// that was taken away.
///
/// # Errors
///
/// When `<data>/nex` is not empty, a `gate.key` already there differs from
/// the backup's, or the backup fails nex-db's checks.
pub fn restore(backup: &Path, data: &Path) -> Result<String, String> {
    let from = backup.join("nex");
    if !from.join("BACKUP").exists() {
        return Err(format!(
            "{} holds no backup (no nex/BACKUP)",
            backup.display()
        ));
    }
    let into = data.join("nex");
    if into.read_dir().is_ok_and(|mut d| d.next().is_some()) {
        return Err(format!(
            "{} is not empty: restore into a new folder, never over a database",
            into.display()
        ));
    }
    let key = backup.join("gate.key");
    let key_to = data.join("gate.key");
    if key.exists() && key_to.exists() {
        let same = std::fs::read(&key).ok() == std::fs::read(&key_to).ok();
        if !same {
            return Err(format!(
                "{} is there already and is not the backup's: move it away first",
                key_to.display()
            ));
        }
    }
    std::fs::create_dir_all(data).map_err(|e| format!("{}: {e}", data.display()))?;
    private(data);
    crate::nex::restore(&from, &into).map_err(|e| e.to_string())?;
    let secret = if key.exists() {
        crate::secret::copy(&key, &key_to)?;
        "and its master secret"
    } else {
        "without a master secret (none was in the backup: open forms and remembered devices start again)"
    };
    Ok(format!(
        "restored {} into {}, {secret}",
        backup.display(),
        into.display()
    ))
}

/// Makes `dir` owner-only on Unix (backups hold the site).
fn private(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// The backups of a running site, as a subsystem: one at start, every
/// `backup.every`, one at a clean stop.
pub struct Backups {
    settings: BackupSettings,
    db: NexDb,
    secret: Option<PathBuf>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    link: Option<Link>,
}

impl std::fmt::Debug for Backups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backups")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl Backups {
    /// Backups of `db` (and the master secret at `secret`) by `settings`.
    #[must_use]
    pub fn new(settings: BackupSettings, db: NexDb, secret: Option<PathBuf>) -> Backups {
        Backups {
            settings,
            db,
            secret,
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            link: None,
        }
    }

    fn once(db: &NexDb, to: &Path, secret: Option<&Path>, link: Option<&Link>, when: &str) {
        let result = make(db, to, secret);
        let Some(link) = link else {
            return;
        };
        let log = link.foundation().log();
        let shown = to.display().to_string();
        match result {
            Ok(made) => {
                if let Some(old) = &made.set_aside {
                    let old = old.display().to_string();
                    log::warn!(
                        log,
                        "backup begun again",
                        path = shown.as_str(),
                        set_aside = old.as_str()
                    );
                }
                log::info!(
                    log,
                    "backup made",
                    when = when,
                    path = shown.as_str(),
                    incremental = made.incremental,
                    master_key_copied = made.secret
                );
            }
            Err(reason) => {
                log::warn!(
                    log,
                    "backup failed",
                    when = when,
                    path = shown.as_str(),
                    reason = reason.as_str()
                );
            }
        }
    }
}

impl Subsystem for Backups {
    fn name(&self) -> &str {
        "backup"
    }

    fn start(&mut self, link: &Link) -> Result<(), Failure> {
        self.link = Some(link.clone());
        let (db, to, secret, every, stop, link) = (
            self.db.clone(),
            self.settings.path.clone(),
            self.secret.clone(),
            self.settings.every,
            self.stop.clone(),
            link.clone(),
        );
        // The first at once: a site never runs long without one.
        Self::once(&db, &to, secret.as_deref(), Some(&link), "start");
        let thread = std::thread::Builder::new()
            .name("wasp-backup".into())
            .spawn(move || {
                loop {
                    std::thread::park_timeout(every);
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    Self::once(&db, &to, secret.as_deref(), Some(&link), "every");
                }
            })?;
        self.thread = Some(thread);
        Ok(())
    }

    fn stop(&mut self, _deadline: Deadline) -> Result<(), Failure> {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            t.thread().unpark();
            let _ = t.join();
        }
        // The last one after the door closed: nothing more is written.
        Self::once(
            &self.db,
            &self.settings.path,
            self.secret.as_deref(),
            self.link.as_ref(),
            "stop",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_off_until_a_path_is_given() {
        let read = |t: &str| BackupSettings::from_config(&Config::from_text(t).expect("toml"));
        assert_eq!(read("").expect("read"), None);
        let s = read("[backup]\npath = \"/srv/backups\"\n")
            .expect("read")
            .expect("on");
        assert_eq!(s.every, Duration::from_secs(3600));
        assert!(read("[backup]\npath = \"x\"\nevery = \"10s\"\n").is_err());
        assert!(read("[backup]\npath = \"x\"\nevery = \"30d\"\n").is_err());
    }

    #[test]
    fn only_the_newest_set_aside_backups_are_kept() {
        let dir = std::env::temp_dir().join(format!("wasp-backup-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for at in [100, 300, 200, 400] {
            std::fs::create_dir_all(dir.join(format!("nex.{at}.old"))).expect("dir");
        }
        std::fs::create_dir_all(dir.join("nex")).expect("dir");
        prune_set_aside(&dir);
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .expect("read")
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        left.sort();
        assert_eq!(left, ["nex", "nex.300.old", "nex.400.old"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restore_never_goes_over_a_database() {
        let dir = std::env::temp_dir().join(format!("wasp-backup-over-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("backup/nex")).expect("dir");
        std::fs::write(dir.join("backup/nex/BACKUP"), b"x").expect("file");
        std::fs::create_dir_all(dir.join("data/nex")).expect("dir");
        std::fs::write(dir.join("data/nex/LOCK"), b"x").expect("file");
        let refused = restore(&dir.join("backup"), &dir.join("data")).expect_err("refused");
        assert!(refused.contains("not empty"), "{refused}");
        assert!(restore(&dir.join("nothing"), &dir.join("new")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
