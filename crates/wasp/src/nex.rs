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

use crate::content::{ContentStore, StoreError, StoreErrorKind, Stored};

/// The site in nex-db's routes.
const SITE: &str = nex_db::DEFAULT_SITE;

/// The session cookie (`__Host-`: secure, whole site, no domain).
pub const SESSION_COOKIE: &str = "__Host-nex";

/// A guest's pre-session cookie: what the sign-in form's CSRF token is bound
/// to before there is a session.
pub const PRE_COOKIE: &str = "__Host-nexpre";

/// The role every account that may use the site holds.
pub const MEMBER_ROLE: &str = "member";

/// What the authenticator keeps for the web service: the value CSRF tokens
/// are bound to (the session's id, or a guest's pre-session cookie; empty
/// when there is neither).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NexToken {
    binding: [u8; 48],
    len: u8,
}

impl NexToken {
    fn new(bytes: &[u8]) -> NexToken {
        let mut binding = [0u8; 48];
        let len = bytes.len().min(48);
        binding[..len].copy_from_slice(&bytes[..len]);
        NexToken {
            binding,
            len: u8::try_from(len).unwrap_or(48),
        }
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

/// How often a session's account standing is read again.
const RECHECK: Duration = Duration::from_secs(60);

/// The most entries read from one listing at boot.
const MAX_ENTRIES: usize = 100_000;

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
    /// process holds it, or when it is not ready to serve.
    pub fn open(dir: &Path) -> Result<NexDb, StoreError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| StoreError::unavailable(format!("nex-db {}: {e}", dir.display())))?;
        let db = nex_db::open(dir).map_err(|e| match e {
            nex_db::Error::Locked => StoreError::unavailable(format!(
                "nex-db {} is open in another process: is another instance running on this data folder?",
                dir.display()
            )),
            other => StoreError::new(
                kind_of(&other),
                format!("nex-db {}: {other}", dir.display()),
            ),
        })?;
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
}

impl NexStore {
    /// The content store over `db`.
    #[must_use]
    pub fn new(db: NexDb) -> NexStore {
        NexStore { db }
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
    fn load(&self) -> Result<Vec<Stored>, StoreError> {
        let content = self.db.db().content();
        let mut out = Vec::new();
        for kind in ["post", "page"] {
            let mut page = content
                .list(&Listing::latest(kind).limit(1000))
                .map_err(nex)?;
            loop {
                for e in page.items() {
                    let text = |name: &str| {
                        e.field(name)
                            .and_then(nex_db::Value::as_text)
                            .unwrap_or("")
                            .to_owned()
                    };
                    out.push(Stored {
                        kind: kind.to_owned(),
                        slug: text("slug"),
                        title: text("title"),
                        summary: text("summary"),
                        body: text("body"),
                        date: text("date"),
                    });
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
        let fields = [
            ("slug", &entry.slug),
            ("title", &entry.title),
            ("summary", &entry.summary),
            ("body", &entry.body),
            ("date", &entry.date),
        ];
        match content.resolve(SITE, &path).map_err(nex)? {
            Some(route) => {
                let patch = fields
                    .iter()
                    .fold(Patch::new(), |p, (k, v)| p.set(*k, v.as_str()));
                content.save_draft(route.entity(), patch).map_err(nex)?;
                content.publish(route.entity()).map_err(nex)?;
            }
            None => {
                let entity = fields
                    .iter()
                    .fold(Entity::new(entry.kind.as_str()), |e, (k, v)| {
                        e.field(*k, v.as_str())
                    })
                    .path(path);
                content.put(entity).map_err(nex)?;
            }
        }
        Ok(())
    }

    fn remove(&self, slug: &str) -> Result<bool, StoreError> {
        let content = self.db.db().content();
        let mut any = false;
        for kind in ["post", "page"] {
            if let Some(route) = content.resolve(SITE, &path_of(kind, slug)).map_err(nex)? {
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
/// again once a minute (`recheck_at`): a ban refuses the request (403), a
/// suspension marks the identity. Any other token is a guest whose cookie is
/// cleared.
#[derive(Clone, Debug)]
pub struct NexAuth {
    db: NexDb,
    roles: Arc<[(Box<str>, u64)]>,
}

impl NexAuth {
    /// The authenticator over `db`, with `member` granting permission bit 0
    /// (the site's account page).
    #[must_use]
    pub fn new(db: NexDb) -> NexAuth {
        NexAuth::with_roles(db, &[(MEMBER_ROLE, 1)])
    }

    /// The authenticator over `db`, with a role-to-permission-bits table.
    #[must_use]
    pub fn with_roles(db: NexDb, roles: &[(&str, u64)]) -> NexAuth {
        NexAuth {
            db,
            roles: roles.iter().map(|(n, b)| (Box::from(*n), *b)).collect(),
        }
    }

    /// The permission bits the account's roles grant.
    fn perms_of(&self, account: nex_db::AccountId) -> Result<PermSet, StoreError> {
        let auth = self.db.db().auth();
        let mut bits = 0u64;
        for id in auth.roles(account).map_err(nex)? {
            if let Some(role) = auth.role(id) {
                for (name, b) in self.roles.iter() {
                    if role.name() == &**name {
                        bits |= *b;
                    }
                }
            }
        }
        Ok(PermSet(bits))
    }

    /// Makes `identifier` an account with `password` holding `roles`, when
    /// there is none yet (the boot account): the new account's id, or `None`
    /// when it existed already (it is left as it is).
    pub fn ensure_account(
        &self,
        identifier: &str,
        password: &str,
        roles: &[&str],
    ) -> Result<Option<UserId>, StoreError> {
        let auth = self.db.db().auth();
        let account = match auth.sign_up(identifier, password) {
            Ok(a) => a,
            Err(nex_db::Error::AlreadyExists { .. }) => return Ok(None),
            Err(e) => return Err(nex(e)),
        };
        let mut ids = Vec::with_capacity(roles.len());
        for role in roles {
            ids.push(match auth.role_named(role) {
                Some(id) => id,
                None => auth.define_role(nex_db::Role::new(*role)).map_err(nex)?,
            });
        }
        auth.assign_roles(account, &ids).map_err(nex)?;
        Ok(Some(user_of(account)))
    }

    /// Bans the account: every session it holds ends in the same commit.
    pub fn ban(&self, user: UserId) -> Result<(), StoreError> {
        let account = nex_db::AccountId::from_bytes(user.0.to_be_bytes());
        self.db
            .db()
            .auth()
            .set_standing(account, nex_db::Standing::Banned { reason: 1 }, None)
            .map_err(nex)
    }

    /// Signs `identifier` in with `password`: on success, the session
    /// cookie's value (`__Host-nex=<token>; ...`) holding `perms`. `None` for
    /// any refusal (wrong password, unknown account, locked out): the same
    /// answer for each.
    pub fn sign_in(&self, identifier: &str, password: &str) -> Result<Option<String>, StoreError> {
        let auth = self.db.db().auth();
        let PasswordCheck::Verified(account) =
            auth.verify_password(identifier, password).map_err(nex)?
        else {
            return Ok(None);
        };
        let perms = self.perms_of(account)?;
        let spec = SessionSpec::web()
            .recheck_after(RECHECK)
            .payload(&perms.0.to_le_bytes())
            .map_err(nex)?;
        let token = auth.issue_session(account, spec).map_err(nex)?;
        Ok(Some(format!(
            "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000",
            token.as_str()
        )))
    }

    /// Ends the session `token` names; the cookie value that clears it.
    pub fn sign_out(&self, token: &str) -> Result<String, StoreError> {
        let _ = self.db.db().auth().revoke(token).map_err(nex)?;
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
        let (name, value) = pair.trim().split_once('=')?;
        if name == want {
            if found.is_some() {
                return None; // planted twice: never pick one
            }
            found = Some(value);
        }
    }
    found
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
        let auth = self.db.db().auth();
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
        let mut standing = Standing::Good;
        if session
            .recheck_at()
            .is_some_and(|at| SystemTime::now() >= at)
        {
            match auth.standing(account) {
                Ok(Some(nex_db::Standing::Banned { .. })) => {
                    out.set_cookie(clear_cookie().as_bytes());
                    return Authentication::Refused(wasp_core::Refusal::status(403));
                }
                Ok(Some(nex_db::Standing::Suspended { until, .. })) => {
                    standing = Standing::Suspended {
                        until: until.and_then(unix),
                    };
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    let a = guest(out);
                    out.set_cookie(clear_cookie().as_bytes());
                    return a;
                }
                Err(_) => {}
            }
        }
        let perms = session
            .payload()
            .get(..8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map_or(PermSet::NONE, |b| PermSet(u64::from_le_bytes(b)));
        let user = user_of(account);
        let session = session_id(token);
        out.keep(NexToken::new(&session.0.to_le_bytes()));
        Authentication::Identified(Identity::user(user, session, perms).with_standing(standing))
    }
}
