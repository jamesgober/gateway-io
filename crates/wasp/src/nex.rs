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
//! nex-db refuses a second open of the same folder, keeps every commit that
//! returned, and stops writes after a failed write (its health is then
//! read-only: the provider reports unhealthy and the site's `/ready` answers
//! 503).

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use nex_db::{Entity, Health, Listing, Patch, SessionSpec, SignIn, Validation};
use wasp_core::{
    AuthOut, Authentication, Authenticator, Identity, PermSet, Profile, Provider, ProviderError,
    RequestView, SessionId, Standing, UserId,
};

use crate::content::{ContentStore, StoreError, Stored};

/// The site in nex-db's routes.
const SITE: &str = nex_db::DEFAULT_SITE;

/// The session cookie (`__Host-`: secure, whole site, no domain).
pub const SESSION_COOKIE: &str = "__Host-nex";

/// How often a session's account standing is read again.
const RECHECK: Duration = Duration::from_secs(60);

/// The most entries read from one listing at boot.
const MAX_ENTRIES: usize = 100_000;

fn nex(e: nex_db::Error) -> StoreError {
    StoreError(format!("nex-db: {e}"))
}

/// The shared database.
#[derive(Clone)]
pub struct NexDb {
    db: Arc<nex_db::Database>,
}

impl NexDb {
    /// Opens (or creates) the database in `dir`. Refused while another
    /// process holds it, or when it is not ready to serve.
    pub fn open(dir: &Path) -> Result<NexDb, StoreError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| StoreError(format!("nex-db {}: {e}", dir.display())))?;
        let db = nex_db::open(dir).map_err(|e| match e {
            nex_db::Error::Locked => StoreError(format!(
                "nex-db {} is open in another process: is another instance running on this data folder?",
                dir.display()
            )),
            other => StoreError(format!("nex-db {}: {other}", dir.display())),
        })?;
        match db.health() {
            Health::Ready => Ok(NexDb { db: Arc::new(db) }),
            other => Err(StoreError(format!(
                "nex-db {} is not ready: {other:?}",
                dir.display()
            ))),
        }
    }

    /// The database.
    #[must_use]
    pub fn db(&self) -> &nex_db::Database {
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
                        return Err(StoreError(format!("more than {MAX_ENTRIES} entries")));
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
}

impl NexAuth {
    /// The authenticator over `db`.
    #[must_use]
    pub fn new(db: NexDb) -> NexAuth {
        NexAuth { db }
    }

    /// Signs `identifier` in with `password`: on success, the session
    /// cookie's value (`__Host-nex=<token>; ...`) holding `perms`. `None` for
    /// any refusal (wrong password, unknown account, locked out): the same
    /// answer for each.
    pub fn sign_in(
        &self,
        identifier: &str,
        password: &str,
        perms: PermSet,
    ) -> Result<Option<String>, StoreError> {
        let spec = SessionSpec::web()
            .recheck_after(RECHECK)
            .payload(&perms.0.to_le_bytes())
            .map_err(nex)?;
        match self
            .db
            .db()
            .auth()
            .sign_in(identifier, password, spec)
            .map_err(nex)?
        {
            SignIn::Success { token, .. } => Ok(Some(format!(
                "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000",
                token.as_str()
            ))),
            _ => Ok(None),
        }
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

/// The session cookie's value in a `Cookie` header, when it appears once.
fn cookie(header: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(header).ok()?;
    let mut found = None;
    for pair in text.split(';') {
        let (name, value) = pair.trim().split_once('=')?;
        if name == SESSION_COOKIE {
            if found.is_some() {
                return None; // planted twice: never pick one
            }
            found = Some(value);
        }
    }
    found
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
        let Some(token) = request.head().header("cookie").and_then(cookie) else {
            return Authentication::Identified(Identity::guest());
        };
        let auth = self.db.db().auth();
        let session = match auth.validate(token) {
            Ok(Validation::Valid(s)) => s,
            Ok(_) => {
                out.set_cookie(clear_cookie().as_bytes());
                return Authentication::Identified(Identity::guest());
            }
            // The store cannot answer: a guest, nothing cleared.
            Err(_) => return Authentication::Identified(Identity::guest()),
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
                    out.set_cookie(clear_cookie().as_bytes());
                    return Authentication::Identified(Identity::guest());
                }
                Err(_) => {}
            }
        }
        let perms = session
            .payload()
            .get(..8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map_or(PermSet::NONE, |b| PermSet(u64::from_le_bytes(b)));
        let user = UserId(u128::from_be_bytes(*account.as_bytes()));
        Authentication::Identified(
            Identity::user(user, session_id(token), perms).with_standing(standing),
        )
    }
}
