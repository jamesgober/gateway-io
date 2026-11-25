//! nex-db as the process's durable store: one database, opened at boot and
//! shared by the content store and the accounts, held by the core as a
//! provider.
//!
//! ```text
//!  NexDb      the database (a Provider: healthy while nex-db says Ready)
//!  NexStore   content: posts at /posts/<slug>, pages at /<slug>, found by route
//!  NexAuth    the core's authenticator over nex-db sessions (cookie __Host-nex)
//! ```
//!
//! Nothing outside this module names a nex-db type: the rest of the process
//! sees the backend-neutral seams ([`ContentStore`], [`Authenticator`],
//! [`Provider`]) and the adapter's own types.
//!
//! nex-db refuses a second open of the same folder, keeps every commit that
//! returned, and stops writes after a failed write (its health is then
//! read-only: the provider reports unhealthy and the site's `/ready` answers
//! 503).

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use nex_db::{Entity, Health, Listing, PasswordCheck, Patch, SessionSpec, Validation};
use wasp_core::{
    AuthOut, Authentication, Authenticator, Identity, PermSet, Profile, Provider, ProviderError,
    RequestView, SessionId, Standing, UserId,
};

use crate::content::{ContentStore, FIELD_PREFIX, Meta, StoreError, StoreErrorKind, Stored};
use crate::policy::{MfaMode, Policy, PolicyCell, Rules};

mod accounts;
pub mod chat;
mod keys;
pub use accounts::{AccountRow, CodeCheck, SessionRow, SignInFrom};
pub use keys::{
    DEFAULT_EXPIRY, EXPIRIES, KeyRow, MAX_KEYS, MAX_LABEL, NewKey, SCOPES, SESSION, Scope, Scopes,
};

/// The site in nex-db's routes.
const SITE: &str = nex_db::DEFAULT_SITE;

/// The content site wasp keeps its account directory on: one entity per
/// account it made or saw sign in, at `/<account id>`, holding the
/// identifier. nex-db finds an account by its identifier only with its
/// password; the directory lets a boot know the boot account exists, and an
/// administrator list accounts.
const DIRECTORY: &str = "wasp-accounts";

/// nex-db's default realm.
pub const DEFAULT_REALM: &str = "users";

/// The directory's entity type.
const DIRECTORY_KIND: &str = "account";

/// The session cookie (`__Host-`: secure, whole site, no domain).
pub const SESSION_COOKIE: &str = "__Host-nex";

/// A guest's pre-session cookie: what the sign-in form's CSRF token is bound
/// to before there is a session.
pub const PRE_COOKIE: &str = "__Host-nexpre";

/// The role every account that may use the site holds.
pub const MEMBER_ROLE: &str = "member";

/// The role that may edit the content.
pub const EDITOR_ROLE: &str = "editor";

/// The role that manages the accounts.
pub const ADMIN_ROLE: &str = "admin";

/// What the authenticator keeps for the web service: the value CSRF tokens
/// are bound to (the session's id, or a guest's pre-session cookie; empty
/// when there is neither).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NexToken {
    binding: [u8; 48],
    len: u8,
    via: Via,
}

/// How a request's caller came in, for the API.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Via {
    /// A browser: no credential, or a session cookie.
    #[default]
    Browser,
    /// An API key that counts, with its scopes.
    Key(Scopes),
    /// A bearer key that does not count: malformed, unknown, revoked,
    /// expired, or its account gone. The request is a guest's.
    BadKey,
    /// A key whose account may not sign in now (disabled, locked out). The
    /// request is a guest's.
    KeyRefused,
}

impl NexToken {
    fn new(bytes: &[u8]) -> NexToken {
        let mut binding = [0u8; 48];
        let len = bytes.len().min(48);
        binding[..len].copy_from_slice(&bytes[..len]);
        NexToken {
            binding,
            len: u8::try_from(len).unwrap_or(48),
            via: Via::Browser,
        }
    }

    /// A program's token: no CSRF binding (a key never posts a form).
    fn by_key(via: Via) -> NexToken {
        NexToken {
            via,
            ..NexToken::new(&[])
        }
    }

    /// How the caller came in.
    #[must_use]
    pub fn via(&self) -> Via {
        self.via
    }

    /// No binding.
    #[must_use]
    pub fn empty() -> NexToken {
        NexToken::new(&[])
    }

    /// The CSRF binding, or empty.
    #[must_use]
    pub fn binding(&self) -> &[u8] {
        &self.binding[..usize::from(self.len)]
    }
}

/// The most entries read from one listing at boot.
const MAX_ENTRIES: usize = 100_000;

/// How long a boot waits for another process to let go of the database
/// (`nex.lock_wait`): a restart can overlap the old process's drain.
pub const LOCK_WAIT: Duration = Duration::from_secs(15);

/// ` (pid N)` when the database's lock file names the process holding it,
/// else nothing.
fn holder(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("LOCK"))
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok())
        .map(|pid| format!(" (pid {pid})"))
        .unwrap_or_default()
}

/// Makes `dir` (and any missing parent) and keeps it to its owner: on Unix,
/// mode 0700, tightened when it is open to the group or others.
fn private_folder(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        let mode = std::fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode & 0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

fn nex(e: nex_db::Error) -> StoreError {
    StoreError::new(kind_of(&e), format!("nex-db: {e}"))
}

/// The backend-neutral kind of a nex-db error.
fn kind_of(e: &nex_db::Error) -> StoreErrorKind {
    use nex_db::Error as E;
    match e {
        E::Locked | E::Busy { .. } | E::KeyUnavailable | E::Storage { .. } => {
            StoreErrorKind::Unavailable
        }
        E::SnapshotTooOld => StoreErrorKind::Timeout,
        E::Conflict | E::AlreadyExists { .. } | E::Restricted { .. } => StoreErrorKind::Conflict,
        E::Invalid { .. } => StoreErrorKind::Invalid,
        _ => StoreErrorKind::Other,
    }
}

/// The shared database.
#[derive(Clone)]
pub struct NexDb {
    // Dropped before `temporary`: the last handle closes the database, then
    // removes its folder.
    db: Arc<nex_db::Database>,
    temporary: Option<Arc<TemporaryFolder>>,
}

/// A folder removed when the last handle to its database is dropped.
struct TemporaryFolder(std::path::PathBuf);

impl Drop for TemporaryFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl NexDb {
    /// Opens (or creates) the database in `dir`. Refused while another
    /// process holds it (after waiting [`LOCK_WAIT`] for it to let go: a
    /// restart can overlap the old process's drain), or when it is not ready
    /// to serve.
    pub fn open(dir: &Path) -> Result<NexDb, StoreError> {
        NexDb::open_waiting(dir, LOCK_WAIT)
    }

    /// [`open`](Self::open), waiting at most `wait` for another process to
    /// let go of the database.
    pub fn open_waiting(dir: &Path, wait: Duration) -> Result<NexDb, StoreError> {
        private_folder(dir)
            .map_err(|e| StoreError::unavailable(format!("nex-db {}: {e}", dir.display())))?;
        let until = std::time::Instant::now() + wait;
        let mut warned = false;
        let db = loop {
            match nex_db::Database::builder(dir)
                .observer(crate::events::StoreEvents)
                .open()
            {
                Ok(db) => break db,
                Err(nex_db::Error::Locked) if std::time::Instant::now() < until => {
                    if !warned {
                        warned = true;
                        crate::events::warn(format!(
                            "{} is locked by another process{}; waiting up to {} s for it to finish",
                            dir.display(),
                            holder(dir),
                            wait.as_secs()
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(nex_db::Error::Locked) => {
                    let waited = if wait.is_zero() {
                        String::new()
                    } else {
                        format!(", still after {} s", wait.as_secs())
                    };
                    return Err(StoreError::unavailable(format!(
                        "the database {} is in use by another process{}{waited} (its lock file is {}): another wasp is probably still running on this data folder; stop it, or give this one its own `nex.path`",
                        dir.display(),
                        holder(dir),
                        dir.join("LOCK").display()
                    )));
                }
                Err(other) => {
                    return Err(StoreError::new(
                        kind_of(&other),
                        format!("nex-db {}: {other}", dir.display()),
                    ));
                }
            }
        };
        match db.health() {
            Health::Ready => Ok(NexDb {
                db: Arc::new(db),
                temporary: None,
            }),
            other => Err(StoreError::unavailable(format!(
                "nex-db {} is not ready: {other:?}",
                dir.display()
            ))),
        }
    }

    /// A database in a new temporary folder, removed when the last handle
    /// is dropped: for tests and tools that wire the process without a data
    /// folder.
    pub fn open_temporary() -> Result<NexDb, StoreError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let dir =
            std::env::temp_dir().join(format!("wasp-nex-{}-{n}-{nanos:08x}", std::process::id()));
        let guard = TemporaryFolder(dir.clone());
        let mut db = NexDb::open(&dir)?;
        db.temporary = Some(Arc::new(guard));
        Ok(db)
    }

    /// The database, for this adapter only: nothing outside it names nex-db.
    fn db(&self) -> &nex_db::Database {
        &self.db
    }
}

impl std::fmt::Debug for NexDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NexDb")
            .field("path", &self.db.path())
            .finish()
    }
}

impl Provider for NexDb {
    fn name(&self) -> &str {
        "nex-db"
    }

    /// Every commit that returned is durable already; a database that went
    /// read-only (a failed write) is reported.
    fn flush(&self) -> Result<(), ProviderError> {
        match self.db.health() {
            Health::ReadOnly { .. } => Err(ProviderError(
                "nex-db is read-only after a failed write".into(),
            )),
            _ => Ok(()),
        }
    }

    fn healthy(&self) -> bool {
        matches!(self.db.health(), Health::Ready)
    }
}

/// Content in nex-db: one entity per entry, published at its path.
#[derive(Clone, Debug)]
pub struct NexStore {
    db: NexDb,
    site: Arc<str>,
}

impl NexStore {
    /// The content store over `db`, on nex-db's default content site.
    #[must_use]
    pub fn new(db: NexDb) -> NexStore {
        NexStore {
            db,
            site: Arc::from(SITE),
        }
    }

    /// The same store on the content site `site` (a host profile's own).
    #[must_use]
    pub fn on_site(mut self, site: &str) -> NexStore {
        self.site = Arc::from(site);
        self
    }
}

fn path_of(kind: &str, slug: &str) -> String {
    match kind {
        "post" => format!("/posts/{slug}"),
        _ => format!("/{slug}"),
    }
}

impl Provider for NexStore {
    fn name(&self) -> &str {
        "content-nex"
    }
    fn flush(&self) -> Result<(), ProviderError> {
        self.db.flush()
    }
    fn healthy(&self) -> bool {
        self.db.healthy()
    }
}

impl ContentStore for NexStore {
    /// Every post and page. A slug held by both a post and a page (an entry
    /// whose kind changed, saved by an older build) reads as the one that
    /// changed last.
    fn load(&self) -> Result<Vec<Stored>, StoreError> {
        let content = self.db.db().content();
        let mut out: Vec<Stored> = Vec::new();
        let mut changed: std::collections::HashMap<String, (usize, SystemTime)> =
            std::collections::HashMap::new();
        for kind in ["post", "page"] {
            let mut page = content
                .list(&Listing::latest(kind).site(self.site.as_ref()).limit(1000))
                .map_err(nex)?;
            loop {
                for e in page.items() {
                    let text = |name: &str| {
                        e.field(name)
                            .and_then(nex_db::Value::as_text)
                            .unwrap_or("")
                            .to_owned()
                    };
                    let mut meta = Meta::default();
                    for name in Meta::FIELDS {
                        if let Some(f) = meta.get_mut(name) {
                            *f = text(name);
                        }
                    }
                    let stored = Stored {
                        kind: kind.to_owned(),
                        slug: text("slug"),
                        title: text("title"),
                        summary: text("summary"),
                        body: text("body"),
                        date: text("date"),
                        meta,
                        fields: e
                            .fields()
                            .filter_map(|(k, v)| {
                                let name = k.strip_prefix(FIELD_PREFIX)?;
                                Some((name.to_owned(), v.as_text()?.to_owned()))
                            })
                            .collect(),
                    };
                    let at = e.updated_at();
                    match changed.get(&stored.slug).copied() {
                        Some((i, before)) => {
                            if at > before {
                                changed.insert(stored.slug.clone(), (i, at));
                                out[i] = stored;
                            }
                        }
                        None => {
                            changed.insert(stored.slug.clone(), (out.len(), at));
                            out.push(stored);
                        }
                    }
                    if out.len() > MAX_ENTRIES {
                        return Err(StoreError::other(format!(
                            "more than {MAX_ENTRIES} entries"
                        )));
                    }
                }
                let next = match page.next() {
                    Some(cursor) => content.next_page(cursor).map_err(nex)?,
                    None => break,
                };
                page = next;
            }
        }
        Ok(out)
    }

    fn put(&self, entry: &Stored) -> Result<(), StoreError> {
        let content = self.db.db().content();
        let path = path_of(&entry.kind, &entry.slug);
        let mut fields: Vec<(&str, &str)> = vec![
            ("slug", &entry.slug),
            ("title", &entry.title),
            ("summary", &entry.summary),
            ("body", &entry.body),
            ("date", &entry.date),
        ];
        for name in Meta::FIELDS {
            fields.push((name, entry.meta.get(name).unwrap_or("")));
        }
        let custom: Vec<(String, &str)> = entry
            .fields
            .iter()
            .map(|(n, v)| (format!("{FIELD_PREFIX}{n}"), v.as_str()))
            .collect();
        for (name, value) in &custom {
            fields.push((name.as_str(), value));
        }
        match content.resolve(&self.site, &path).map_err(nex)? {
            Some(route) => {
                let patch = fields.iter().fold(Patch::new(), |p, (k, v)| p.set(*k, *v));
                content.save_draft(route.entity(), patch).map_err(nex)?;
                content.publish(route.entity()).map_err(nex)?;
            }
            None => {
                let entity = fields
                    .iter()
                    .fold(Entity::new(entry.kind.as_str()), |e, (k, v)| {
                        e.field(*k, *v)
                    })
                    .site(self.site.as_ref())
                    .path(path);
                content.put(entity).map_err(nex)?;
            }
        }
        // A slug is one entry: when its kind changed, the other kind's
        // route goes, or the next boot could read the old one back.
        let other = if entry.kind == "post" { "page" } else { "post" };
        if let Some(route) = content
            .resolve(&self.site, &path_of(other, &entry.slug))
            .map_err(nex)?
        {
            content.delete(route.entity()).map_err(nex)?;
        }
        Ok(())
    }

    fn remove(&self, slug: &str) -> Result<bool, StoreError> {
        let content = self.db.db().content();
        let mut any = false;
        for kind in ["post", "page"] {
            if let Some(route) = content
                .resolve(&self.site, &path_of(kind, slug))
                .map_err(nex)?
            {
                content.delete(route.entity()).map_err(nex)?;
                any = true;
            }
        }
        Ok(any)
    }
}

/// The core's authenticator over nex-db sessions.
///
/// The session cookie holds nex-db's token. A valid session becomes
/// `Identity::user`: the account (`AccountId`'s 128 bits as `UserId`), the
/// session (a digest of the token as `SessionId`), and the permission bits
/// written into the session at sign-in. The account's standing is read
/// again every `auth.session.recheck` (`recheck_at`): a ban refuses the
/// request (403), a suspension marks the identity, and an account whose
/// roles now require two-step sign-in it has not set up is signed out. Any
/// other token is a guest whose cookie is cleared.
///
/// The sign-in settings (`[auth.*]`, see [`crate::policy`]) are read from a
/// [`PolicyCell`] a configuration reload swaps.
#[derive(Clone, Debug)]
pub struct NexAuth {
    db: NexDb,
    roles: Arc<[(Box<str>, u64)]>,
    checked: Arc<Checked>,
    policy: PolicyCell,
    failures: Arc<accounts::Failures>,
    /// The realm its accounts and sessions are in (`users`, nex-db's
    /// default, or a host profile's own).
    realm: Arc<str>,
    /// The realm's account directory (a content site of its own).
    directory: Arc<str>,
    /// Ends open WebSockets (and running requests) when an account, a
    /// session or a key is revoked.
    revoker: gateway_io::Revoker,
}

/// What a session's last recheck read (its account's permissions and
/// standing), so the store is read at most once per recheck per session.
#[derive(Debug, Default)]
struct Checked(
    std::sync::Mutex<std::collections::HashMap<SessionId, (std::time::Instant, PermSet, Standing)>>,
);

/// Sessions whose last recheck is kept at once; past it, older ones go.
const CHECKED: usize = 100_000;

impl Checked {
    fn get(&self, session: SessionId, recheck: Duration) -> Option<(PermSet, Standing)> {
        let map = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.get(&session)
            .filter(|(at, _, _)| at.elapsed() < recheck)
            .map(|(_, p, s)| (*p, *s))
    }

    fn put(&self, session: SessionId, perms: PermSet, standing: Standing, recheck: Duration) {
        let mut map = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= CHECKED {
            map.retain(|_, (at, _, _)| at.elapsed() < recheck);
            if map.len() >= CHECKED {
                map.clear();
            }
        }
        map.insert(session, (std::time::Instant::now(), perms, standing));
    }
}

/// The shortest boot account password made from `WASP_ADMIN_PASSWORD`, in
/// characters, under the default settings (the `admin` role's
/// `[auth.password]` rules apply).
pub const MIN_ADMIN_PASSWORD: usize = 12;

/// How long a session lasts without a request, under the default settings.
pub const IDLE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// What a matching password leads to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordStep {
    /// Signed in: open the session.
    Done(UserId),
    /// The account has two-step sign-in on: ask for a code.
    Code(UserId),
    /// The account's roles require two-step sign-in it has not set up.
    Setup(UserId),
    /// Wrong identifier or password, or the account may not sign in.
    Refused,
}

impl NexAuth {
    /// The authenticator over `db`, with `member` granting permission bit 0
    /// (the site's account page), `editor` bit 1 (the content editor), and
    /// `admin` bit 2 (the accounts), under the default sign-in settings.
    #[must_use]
    pub fn new(db: NexDb) -> NexAuth {
        NexAuth::with_roles(db, &[(MEMBER_ROLE, 1), (EDITOR_ROLE, 2), (ADMIN_ROLE, 4)])
    }

    /// The authenticator over `db`, with a role-to-permission-bits table.
    #[must_use]
    pub fn with_roles(db: NexDb, roles: &[(&str, u64)]) -> NexAuth {
        NexAuth {
            db,
            roles: roles.iter().map(|(n, b)| (Box::from(*n), *b)).collect(),
            checked: Arc::default(),
            policy: PolicyCell::default(),
            failures: Arc::default(),
            realm: Arc::from(DEFAULT_REALM),
            directory: Arc::from(DIRECTORY),
            revoker: gateway_io::Revoker::new(),
        }
    }

    /// The same authenticator over the realm `name` (made when it is not
    /// there yet): its own accounts, sessions, keys and account directory,
    /// apart from every other realm's. `users` is nex-db's default realm.
    pub fn in_realm(mut self, name: &str) -> Result<NexAuth, StoreError> {
        if name != DEFAULT_REALM {
            match self.db.db().define_realm(name, nex_db::RealmPolicy::new()) {
                Ok(()) | Err(nex_db::Error::AlreadyExists { .. }) => {}
                Err(e) => return Err(nex(e)),
            }
            self.directory = Arc::from(format!("{DIRECTORY}-{name}"));
        } else {
            self.directory = Arc::from(DIRECTORY);
        }
        self.realm = Arc::from(name);
        // Every call goes through `auth`, which fails rather than fall back
        // to another realm.
        let _ = self.auth()?;
        Ok(self)
    }

    /// The realm's name.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The realm's auth engine.
    fn auth(&self) -> Result<nex_db::Auth<'_>, StoreError> {
        if &*self.realm == DEFAULT_REALM {
            Ok(self.db.db().auth())
        } else {
            self.db.db().auth_realm(&self.realm).map_err(nex)
        }
    }

    /// The same authenticator, ending open WebSockets through `revoker` on
    /// account, session and key events.
    #[must_use]
    pub fn with_revoker(mut self, revoker: gateway_io::Revoker) -> NexAuth {
        self.revoker = revoker;
        self
    }

    /// The same authenticator, reading its settings from `policy`.
    #[must_use]
    pub fn with_policy(mut self, policy: PolicyCell) -> NexAuth {
        self.policy = policy;
        self
    }

    /// The sign-in settings in force.
    #[must_use]
    pub fn policy(&self) -> Arc<Policy> {
        self.policy.get()
    }

    /// Writes the lockout settings into the database (they apply to every
    /// sign-in from now on).
    pub fn apply_lockout(&self) -> Result<(), StoreError> {
        let l = self.policy().lockout;
        self.db
            .db()
            .set_realm_policy(
                &self.realm,
                nex_db::RealmPolicy::new().lockout(l.attempts, l.window, l.duration),
            )
            .map_err(nex)
    }

    /// The permission bits the account's roles grant, and the roles' names.
    fn roles_of(&self, account: nex_db::AccountId) -> Result<(PermSet, Vec<String>), StoreError> {
        let auth = self.auth()?;
        let mut bits = 0u64;
        let mut names = Vec::new();
        for id in auth.roles(account).map_err(nex)? {
            if let Some(role) = auth.role(id) {
                for (name, b) in self.roles.iter() {
                    if role.name() == &**name {
                        bits |= *b;
                    }
                }
                names.push(role.name().to_owned());
            }
        }
        Ok((PermSet(bits), names))
    }

    /// The messenger's store for this realm.
    #[must_use]
    pub fn chat_store(&self) -> chat::NexChat {
        chat::NexChat::new(self.db.clone(), &self.realm)
    }

    /// The names of `user`'s roles.
    pub fn role_names(&self, user: UserId) -> Result<Vec<String>, StoreError> {
        self.roles_of(account_of(user)).map(|(_, names)| names)
    }

    /// The sign-in rules for `user` (its roles' strictest).
    pub fn rules(&self, user: UserId) -> Result<Rules, StoreError> {
        let (_, names) = self.roles_of(account_of(user))?;
        Ok(self.policy().rules_for(names.iter().map(String::as_str)))
    }

    /// The role ids for `roles`, defined when missing.
    fn role_ids(&self, roles: &[&str]) -> Result<Vec<nex_db::RoleId>, StoreError> {
        let auth = self.auth()?;
        let mut ids = Vec::with_capacity(roles.len());
        for role in roles {
            ids.push(match auth.role_named(role) {
                Some(id) => id,
                None => auth.define_role(nex_db::Role::new(*role)).map_err(nex)?,
            });
        }
        Ok(ids)
    }

    /// Gives `account` every role in `ids` it lacks.
    fn grant(&self, account: nex_db::AccountId, ids: &[nex_db::RoleId]) -> Result<(), StoreError> {
        let auth = self.auth()?;
        let held = auth.roles(account).map_err(nex)?;
        if ids.iter().any(|id| !held.contains(id)) {
            let mut all = held;
            all.extend(
                ids.iter()
                    .filter(|id| !all.contains(id))
                    .collect::<Vec<_>>(),
            );
            auth.assign_roles(account, &all).map_err(nex)?;
        }
        Ok(())
    }

    /// Makes `identifier` an account with `password` holding `roles`, when
    /// there is none yet (the boot account): the new account's id, or `None`
    /// when it existed already. A new account's password must keep the
    /// `[auth.password]` rules of `roles`. When the account exists, any of
    /// `roles` it lacks is given back (the boot account names its roles in
    /// the configuration, whatever its password is now).
    pub fn ensure_account(
        &self,
        identifier: &str,
        password: &str,
        roles: &[&str],
    ) -> Result<Option<UserId>, StoreError> {
        let ids = self.role_ids(roles)?;
        if let Some(user) = self.known(identifier)? {
            self.grant(account_of(user), &ids)?;
            return Ok(None);
        }
        let auth = self.auth()?;
        let verified = |auth: &nex_db::Auth<'_>| match auth.verify_password(identifier, password) {
            Ok(PasswordCheck::Verified(a) | PasswordCheck::NeedsSecondFactor { account: a }) => {
                Some(a)
            }
            _ => None,
        };
        let rules = self.policy().rules_for(roles.iter().copied());
        if let Some(why) = rules.refuse(password) {
            // An account another tool made with this password still joins.
            if verified(&auth).is_none() {
                return Err(StoreError::new(
                    StoreErrorKind::Invalid,
                    format!("the boot account's password: {why}"),
                ));
            }
        }
        match auth.sign_up(identifier, password) {
            Ok(account) => {
                auth.assign_roles(account, &ids).map_err(nex)?;
                self.record(identifier, account)?;
                Ok(Some(user_of(account)))
            }
            Err(nex_db::Error::AlreadyExists { .. }) => {
                if let Some(account) = verified(&auth) {
                    self.record(identifier, account)?;
                    self.grant(account, &ids)?;
                }
                Ok(None)
            }
            Err(e) => Err(nex(e)),
        }
    }

    /// Gives the account `identifier` names every role in `roles` it lacks;
    /// `false` when the directory does not know it.
    pub fn ensure_roles(&self, identifier: &str, roles: &[&str]) -> Result<bool, StoreError> {
        let Some(user) = self.known(identifier)? else {
            return Ok(false);
        };
        let ids = self.role_ids(roles)?;
        self.grant(account_of(user), &ids)?;
        Ok(true)
    }

    /// Puts `identifier`'s account in the directory, when it is not there.
    fn record(&self, identifier: &str, account: nex_db::AccountId) -> Result<(), StoreError> {
        let content = self.db.db().content();
        let path = format!("/{}", hex_of(account));
        if content
            .resolve(&self.directory, &path)
            .map_err(nex)?
            .is_some()
        {
            return Ok(());
        }
        let entity = Entity::new(DIRECTORY_KIND)
            .site(self.directory.as_ref())
            .path(path)
            .field("identifier", identifier.trim().to_lowercase());
        match content.put(entity) {
            // Two sign-ins of a new account at once: the other one wrote it.
            Ok(_) | Err(nex_db::Error::AlreadyExists { .. } | nex_db::Error::Conflict) => Ok(()),
            Err(e) => Err(nex(e)),
        }
    }

    /// Every account in the directory that still exists, with its
    /// identifier.
    pub fn accounts(&self) -> Result<Vec<(String, UserId)>, StoreError> {
        let content = self.db.db().content();
        let auth = self.auth()?;
        let mut out = Vec::new();
        let mut page = content
            .list(
                &Listing::latest(DIRECTORY_KIND)
                    .site(self.directory.as_ref())
                    .limit(1000),
            )
            .map_err(nex)?;
        loop {
            for e in page.items() {
                let Some(identifier) = e.field("identifier").and_then(nex_db::Value::as_text)
                else {
                    continue;
                };
                let Some(account) = e
                    .route()
                    .and_then(|(_, p)| account_of_hex(p.trim_start_matches('/')))
                else {
                    continue;
                };
                if auth.account(account).map_err(nex)?.is_some() {
                    out.push((identifier.to_owned(), user_of(account)));
                }
                if out.len() > MAX_ENTRIES {
                    return Err(StoreError::other(format!(
                        "more than {MAX_ENTRIES} accounts"
                    )));
                }
            }
            let next = match page.next() {
                Some(cursor) => content.next_page(cursor).map_err(nex)?,
                None => break,
            };
            page = next;
        }
        Ok(out)
    }

    /// The account `identifier` names, when the directory knows it and it
    /// still exists.
    pub fn known(&self, identifier: &str) -> Result<Option<UserId>, StoreError> {
        let want = identifier.trim().to_lowercase();
        Ok(self
            .accounts()?
            .into_iter()
            .find(|(i, _)| *i == want)
            .map(|(_, u)| u))
    }

    /// Bans the account: every session it holds ends in the same commit.
    pub fn ban(&self, user: UserId) -> Result<(), StoreError> {
        self.auth()?
            .set_standing(
                account_of(user),
                nex_db::Standing::Banned { reason: 1 },
                None,
            )
            .map_err(nex)?;
        self.revoker.account(user.0);
        Ok(())
    }

    /// The first step of a sign-in: `identifier` and `password`. Every
    /// refusal (wrong password, unknown account, locked out) is the same
    /// answer.
    pub fn check_password(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<PasswordStep, StoreError> {
        let auth = self.auth()?;
        match auth.verify_password(identifier, password).map_err(nex)? {
            PasswordCheck::Verified(account) => {
                // An account made before the directory, or by another tool,
                // joins it the first time it signs in.
                self.record(identifier, account)?;
                let user = user_of(account);
                if self.rules(user)?.mfa == MfaMode::Required && !self.totp_on(user)? {
                    return Ok(PasswordStep::Setup(user));
                }
                Ok(PasswordStep::Done(user))
            }
            PasswordCheck::NeedsSecondFactor { account } => {
                self.record(identifier, account)?;
                Ok(PasswordStep::Code(user_of(account)))
            }
            _ => Ok(PasswordStep::Refused),
        }
    }

    /// Opens a session for `user` (its password, and its code when it needs
    /// one, already checked), signed in `from` a device and address: the
    /// session cookie's value. Past the account's session cap, its oldest
    /// sessions end.
    ///
    /// The new session's id comes from nex-db itself (`Session::id`), so its
    /// device and address are kept with the right session whatever else signs
    /// in at the same moment.
    pub fn open_session(&self, user: UserId, from: &SignInFrom) -> Result<String, StoreError> {
        let account = account_of(user);
        let policy = self.policy();
        let (perms, names) = self.roles_of(account)?;
        let rules = policy.rules_for(names.iter().map(String::as_str));
        let spec = SessionSpec::new(rules.absolute)
            .map_err(nex)?
            .idle(rules.idle)
            .recheck_after(policy.recheck)
            .payload(&perms.0.to_le_bytes())
            .map_err(nex)?;
        let auth = self.auth()?;
        let token = auth.issue_session(account, spec).map_err(nex)?;
        if let Validation::Valid(s) = auth.validate(token.as_str()).map_err(nex)? {
            self.record_session(user, s.id(), session_id(token.as_str()), from)?;
        }
        if rules.max_sessions > 0 {
            let mut sessions = auth.sessions(account).map_err(nex)?;
            let cap = usize::try_from(rules.max_sessions).unwrap_or(usize::MAX);
            if sessions.len() > cap {
                // Oldest first; the one just issued is the newest.
                sessions.sort_by_key(nex_db::SessionInfo::created_at);
                let over = sessions.len() - cap;
                for s in sessions.iter().take(over) {
                    let _ = auth.revoke_session(account, s.id()).map_err(nex)?;
                }
            }
        }
        Ok(format!(
            "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
            token.as_str(),
            rules.absolute.as_secs()
        ))
    }

    /// Signs `identifier` in with `password`, when no second step is
    /// needed: the session cookie's value. `None` for any refusal, and for
    /// an account that needs a code or two-step set-up first.
    pub fn sign_in(&self, identifier: &str, password: &str) -> Result<Option<String>, StoreError> {
        match self.check_password(identifier, password)? {
            PasswordStep::Done(user) => self.open_session(user, &SignInFrom::default()).map(Some),
            _ => Ok(None),
        }
    }

    /// Ends the session `token` names; the cookie value that clears it.
    pub fn sign_out(&self, token: &str) -> Result<String, StoreError> {
        let _ = self.auth()?.revoke(token).map_err(nex)?;
        Ok(clear_cookie())
    }
}

fn clear_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// The value of the cookie `want` in a `Cookie` header, when it appears once.
pub fn cookie<'a>(header: &'a [u8], want: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(header).ok()?;
    let mut found = None;
    for pair in text.split(';') {
        // A cookie set without `=` (another script's flag) is not ours.
        let Some((name, value)) = pair.trim().split_once('=') else {
            continue;
        };
        if name == want {
            if found.is_some() {
                return None; // planted twice: never pick one
            }
            found = Some(value);
        }
    }
    found
}

/// An account id as 32 lowercase hex digits.
fn hex_of(account: nex_db::AccountId) -> String {
    format!("{:032x}", u128::from_be_bytes(*account.as_bytes()))
}

/// The account id 32 hex digits spell.
fn account_of_hex(hex: &str) -> Option<nex_db::AccountId> {
    if hex.len() != 32 {
        return None;
    }
    let n = u128::from_str_radix(hex, 16).ok()?;
    Some(nex_db::AccountId::from_bytes(n.to_be_bytes()))
}

fn account_of(user: UserId) -> nex_db::AccountId {
    nex_db::AccountId::from_bytes(user.0.to_be_bytes())
}

fn user_of(account: nex_db::AccountId) -> UserId {
    UserId(u128::from_be_bytes(*account.as_bytes()))
}

fn session_id(token: &str) -> SessionId {
    let digest = crypt_io::hash::blake3(token.as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    SessionId(u128::from_le_bytes(b))
}

fn unix(t: SystemTime) -> Option<u64> {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

impl Authenticator for NexAuth {
    fn authenticate(
        &self,
        request: RequestView<'_>,
        _profile: &Profile,
        out: &mut AuthOut,
    ) -> Authentication {
        let _client: Option<IpAddr> = request.trip().client;
        // A program: judged by its key alone, whatever cookie it sends.
        if let Some(key) = request.head().header("authorization").and_then(bearer) {
            return self.authenticate_key(key, out);
        }
        let header = request.head().header("cookie");
        let guest = |out: &mut AuthOut| {
            // A guest's binding is the pre-session cookie, when it is one.
            let pre = header
                .and_then(|h| cookie(h, PRE_COOKIE))
                .filter(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()));
            out.keep(NexToken::new(pre.map_or(&[][..], str::as_bytes)));
            Authentication::Identified(Identity::guest())
        };
        let Some(token) = header.and_then(|h| cookie(h, SESSION_COOKIE)) else {
            return guest(out);
        };
        let Ok(auth) = self.auth() else {
            return Authentication::Unavailable;
        };
        let session = match auth.validate(token) {
            Ok(Validation::Valid(s)) => s,
            Ok(_) => {
                let a = guest(out);
                out.set_cookie(clear_cookie().as_bytes());
                return a;
            }
            // The store cannot answer: neither a guest nor signed in (503),
            // nothing cleared.
            Err(_) => return Authentication::Unavailable,
        };
        let account = session.account();
        let id = session_id(token);
        // The permissions written at sign-in, until the first recheck; from
        // then on the account's roles and standing as read at most a minute
        // ago, so a removed role or a suspension reaches open sessions.
        let recheck = self.policy().recheck;
        let (perms, standing) = if session
            .recheck_at()
            .is_some_and(|at| SystemTime::now() >= at)
        {
            if let Some(known) = self.checked.get(id, recheck) {
                known
            } else {
                let standing = match auth.standing(account) {
                    Ok(Some(nex_db::Standing::Banned { .. })) => {
                        out.set_cookie(clear_cookie().as_bytes());
                        return Authentication::Refused(wasp_core::Refusal::status(403));
                    }
                    Ok(Some(nex_db::Standing::Suspended { until, .. })) => Standing::Suspended {
                        until: until.and_then(unix),
                    },
                    Ok(Some(_)) => Standing::Good,
                    Ok(None) => {
                        let a = guest(out);
                        out.set_cookie(clear_cookie().as_bytes());
                        return a;
                    }
                    // The store cannot answer: never let the request through
                    // on what it last said.
                    Err(_) => return Authentication::Unavailable,
                };
                let Ok((perms, names)) = self.roles_of(account) else {
                    return Authentication::Unavailable;
                };
                // Two-step sign-in now required of a role the account holds,
                // and not set up: signed out, to set it up at the next
                // sign-in.
                let rules = self.policy().rules_for(names.iter().map(String::as_str));
                if rules.mfa == MfaMode::Required {
                    match self.totp_on(user_of(account)) {
                        Ok(true) => {}
                        Ok(false) => {
                            let _ = auth.revoke(token);
                            let a = guest(out);
                            out.set_cookie(clear_cookie().as_bytes());
                            return a;
                        }
                        Err(_) => return Authentication::Unavailable,
                    }
                }
                self.checked.put(id, perms, standing, recheck);
                (perms, standing)
            }
        } else {
            let perms = session
                .payload()
                .get(..8)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map_or(PermSet::NONE, |b| PermSet(u64::from_le_bytes(b)));
            (perms, Standing::Good)
        };
        let user = user_of(account);
        let session = id;
        out.keep(NexToken::new(&session.0.to_le_bytes()));
        // Only a session cookie reaches the account and admin pages.
        let perms = PermSet(perms.0 | SESSION.0);
        Authentication::Identified(Identity::user(user, session, perms).with_standing(standing))
    }
}

/// The key in an `Authorization: Bearer <key>` field; `Some("")` for a
/// bearer field without a usable key (it counts as a bad key), `None` for
/// any other scheme.
fn bearer(field: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(field).ok()?.trim();
    let (scheme, rest) = text.split_once(' ').unwrap_or((text, ""));
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let key = rest.trim();
    let usable = !key.is_empty() && key.len() <= 512 && key.bytes().all(|b| b.is_ascii_graphic());
    Some(if usable { key } else { "" })
}

impl NexAuth {
    /// A request with an API key: its account, with the account's roles cut
    /// down to the key's scopes; a guest marked as such when the key does
    /// not count.
    fn authenticate_key(&self, key: &str, out: &mut AuthOut) -> Authentication {
        let refused = |out: &mut AuthOut, via: Via| {
            out.keep(NexToken::by_key(via));
            Authentication::Identified(Identity::guest())
        };
        let Ok(auth) = self.auth() else {
            return Authentication::Unavailable;
        };
        let (account, id, scopes) = match auth.validate_api_key(key) {
            Ok(nex_db::ApiKeyCheck::Valid {
                account,
                id,
                scopes,
            }) => (account, id, Scopes::of_stored(&scopes)),
            Ok(_) => return refused(out, Via::BadKey),
            Err(_) => return Authentication::Unavailable,
        };
        let session = keys::key_session(id);
        // The account's standing and roles, read on every request with a
        // key: a ban, a disable or a removed role stops its keys at once.
        match auth.standing(account) {
            Ok(Some(nex_db::Standing::Banned { .. })) => {
                return Authentication::Refused(wasp_core::Refusal::status(403));
            }
            // Disabled by an administrator.
            Ok(Some(nex_db::Standing::Suspended { .. })) => {
                return refused(out, Via::KeyRefused);
            }
            // Locked out by wrong passwords: the key still works, so no
            // one can stop an account's programs by failing to sign in.
            Ok(Some(_)) => {}
            Ok(None) => return refused(out, Via::BadKey),
            Err(_) => return Authentication::Unavailable,
        }
        let Ok((perms, _)) = self.roles_of(account) else {
            return Authentication::Unavailable;
        };
        out.keep(NexToken::by_key(Via::Key(scopes)));
        let perms = PermSet(perms.0 & scopes.perms().0);
        Authentication::Identified(Identity::user(user_of(account), session, perms))
    }
}

#[cfg(test)]
mod tests {
    use super::bearer;

    #[test]
    fn a_bearer_field_gives_its_key_and_other_schemes_nothing() {
        assert_eq!(bearer(b"Bearer abc.DEF-1"), Some("abc.DEF-1"));
        assert_eq!(bearer(b"  bearer   abc  "), Some("abc"));
        assert_eq!(bearer(b"BEARER abc"), Some("abc"));
        // A bearer field without a usable key counts as a bad key.
        assert_eq!(bearer(b"Bearer"), Some(""));
        assert_eq!(bearer(b"Bearer a b"), Some(""));
        assert_eq!(bearer("Bearer caf\u{e9}".as_bytes()), Some(""));
        assert_eq!(
            bearer(format!("Bearer {}", "k".repeat(513)).as_bytes()),
            Some("")
        );
        // Another scheme is not a key: the cookie decides.
        assert_eq!(bearer(b"Basic dTpw"), None);
        assert_eq!(bearer(b"Bearerabc"), None);
        assert_eq!(bearer(b"\xff"), None);
    }
}
