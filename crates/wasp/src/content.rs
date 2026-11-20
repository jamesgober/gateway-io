//! The content manifest: entries prepared when they are saved, served from
//! memory, read by the templates through the `View` trait.
//!
//! The heavy work happens when content is saved ([`Manifest::save`]): the
//! body is turned into safe HTML once (every character escaped, paragraphs
//! split), the URL and the listing are computed. A request only borrows what
//! is already there: an entry is an `Arc<Entry>`, the post listing one shared
//! `Arc<Vec<Arc<Entry>>>`, so rendering a page copies no content.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use wasp_core::{Provider, ProviderError};

/// What kind of entry: it picks the default template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A standalone page (`/about`).
    Page,
    /// A dated post, listed on the home page (`/posts/:slug`).
    Post,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Page => "page",
            Kind::Post => "post",
        }
    }
}

/// One entry as the templates see it (`page.entry`, each of `page.posts`);
/// its view schema is declared with the theme (`theme.rs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// `page` or `post`.
    pub kind: String,
    /// The slug.
    pub slug: String,
    /// The title (plain text; the template escapes it).
    pub title: String,
    /// The site-relative URL.
    pub url: String,
    /// A one-line summary (plain text).
    pub summary: String,
    /// The body as safe HTML, prepared when the entry was saved.
    pub body: String,
    /// The date (`2026-11-09`), for posts.
    pub date: String,
    /// The body as the author wrote it (plain text), for the editor.
    pub text: String,
}

/// What an editor saves.
#[derive(Clone, Debug)]
pub struct Draft<'a> {
    /// Page or post.
    pub kind: Kind,
    /// The slug: lowercase letters, digits, and `-` only.
    pub slug: &'a str,
    /// The title.
    pub title: &'a str,
    /// A one-line summary.
    pub summary: &'a str,
    /// The body, plain text; blank lines separate paragraphs.
    pub body: &'a str,
    /// The date, for posts.
    pub date: &'a str,
}

/// Why a draft was refused (the editor sees it; nothing is saved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid(pub String);

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Invalid {}

/// Why a save failed: the draft was refused, or the store could not take it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SaveError {
    /// The draft breaks a rule; the editor fixes it.
    Invalid(Invalid),
    /// The store failed; its kind says whether to retry.
    Store(StoreError),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::Invalid(e) => e.fmt(f),
            SaveError::Store(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SaveError {}

impl From<Invalid> for SaveError {
    fn from(e: Invalid) -> SaveError {
        SaveError::Invalid(e)
    }
}

/// The content, in memory until a content store exists (build-path step 8).
#[derive(Clone, Debug, Default)]
pub struct Manifest {
    base: String,
    entries: BTreeMap<String, Arc<Entry>>,
    posts: Arc<Vec<Arc<Entry>>>,
    store: Option<Arc<dyn ContentStore>>,
}

impl std::fmt::Debug for dyn ContentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContentStore({})", self.name())
    }
}

/// An entry as stored: what was prepared when it was saved. The URL is not
/// stored; it depends on where the site is installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    /// `page` or `post`.
    pub kind: String,
    /// The slug (the store's key).
    pub slug: String,
    /// The title.
    pub title: String,
    /// The summary.
    pub summary: String,
    /// The body as the author wrote it (plain text); it is escaped and split
    /// into paragraphs again at every load.
    pub body: String,
    /// The date, for posts.
    pub date: String,
}

/// What kind of failure a store reports, whatever the backend: a file, an
/// embedded database, or one across the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StoreErrorKind {
    /// The store cannot answer now (down, unreachable, locked by another
    /// process, out of a bounded resource). Retry later.
    Unavailable,
    /// The store did not answer in time. The call may or may not have taken
    /// effect; retry later.
    Timeout,
    /// The write lost to another writer, or a unique value is taken. Read
    /// again and retry.
    Conflict,
    /// The input was refused. Retrying the same input fails the same way.
    Invalid,
    /// Anything else: damaged data, a bug. Needs a person.
    Other,
}

/// Why the store failed: its kind, and a message for the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreError {
    kind: StoreErrorKind,
    message: String,
}

impl StoreError {
    /// A failure of `kind`.
    pub fn new(kind: StoreErrorKind, message: impl Into<String>) -> StoreError {
        StoreError {
            kind,
            message: message.into(),
        }
    }

    /// The store cannot answer now.
    pub fn unavailable(message: impl Into<String>) -> StoreError {
        StoreError::new(StoreErrorKind::Unavailable, message)
    }

    /// The input was refused.
    pub fn invalid(message: impl Into<String>) -> StoreError {
        StoreError::new(StoreErrorKind::Invalid, message)
    }

    /// Any other failure.
    pub fn other(message: impl Into<String>) -> StoreError {
        StoreError::new(StoreErrorKind::Other, message)
    }

    /// What kind of failure.
    #[must_use]
    pub fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    /// The message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether the same call may succeed later (unavailable, timeout,
    /// conflict).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            StoreErrorKind::Unavailable | StoreErrorKind::Timeout | StoreErrorKind::Conflict
        )
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

/// Where the content lives between restarts: the provider seam for content.
/// Writes happen when content is saved, never per request; the site reads
/// everything at boot.
///
/// The seam fits any backend, local or remote:
///
/// - every call can fail, with a [`StoreErrorKind`] that says whether to
///   retry;
/// - values cross by copy: nothing returned borrows from the store, and
///   nothing is held between calls;
/// - an entry is found by its slug alone, an opaque key the store never
///   interprets;
/// - no handle to a shared database appears in the signatures, so one
///   process, several, or a cluster can sit behind it;
/// - health is the store's own ([`Provider::healthy`]), reported per
///   backend.
pub trait ContentStore: Provider {
    /// Every stored entry, in no particular order.
    fn load(&self) -> Result<Vec<Stored>, StoreError>;
    /// Stores an entry, replacing the one with the same slug.
    fn put(&self, entry: &Stored) -> Result<(), StoreError>;
    /// Removes the entry with this slug; `false` when there was none.
    fn remove(&self, slug: &str) -> Result<bool, StoreError>;
}

/// Content in memory: gone at a restart. For tests and a first run.
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: Mutex<BTreeMap<String, Stored>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }
}

impl Provider for MemoryStore {
    fn name(&self) -> &str {
        "content-memory"
    }
    fn flush(&self) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl ContentStore for MemoryStore {
    fn load(&self) -> Result<Vec<Stored>, StoreError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::other("store lock poisoned"))?;
        Ok(entries.values().cloned().collect())
    }
    fn put(&self, entry: &Stored) -> Result<(), StoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::other("store lock poisoned"))?;
        entries.insert(entry.slug.clone(), entry.clone());
        Ok(())
    }
    fn remove(&self, slug: &str) -> Result<bool, StoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::other("store lock poisoned"))?;
        Ok(entries.remove(slug).is_some())
    }
}

pub use crate::content::bison_store::{BisonStore, Recovery};

/// The bison-db store.
mod bison_store {
    use std::path::{Path, PathBuf};
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    use bison_db::{Db, DbOptions, Document, RecoveryMode, SyncPolicy, Value};
    use wasp_core::{Provider, ProviderError};

    use super::{ContentStore, StoreError, StoreErrorKind, Stored};

    /// Content in a bison-db file: one document per entry, keyed by slug. Every
    /// write is synced to disk (content is written rarely and must survive a
    /// crash); the slug index is declared at open (bison-db keeps indexes in
    /// memory).
    ///
    /// One process holds the file: a second open (another instance on the
    /// same data folder) is refused at boot. A file damaged anywhere but a
    /// torn last record is refused too, and left as it was; the operator
    /// backs it up and starts once with `content.recovery = "salvage"`,
    /// which keeps every record that still verifies (bison-db saves the
    /// damaged file beside it as `<path>.damaged` first).
    pub struct BisonStore {
        db: RwLock<Db>,
        path: PathBuf,
        discarded: u64,
        /// A write failed: bison-db refuses writes until the store is
        /// reopened, so the provider reports itself unhealthy.
        failed: AtomicBool,
    }

    /// How a damaged store file is opened.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum Recovery {
        /// Refuse a file damaged before its end (the default).
        #[default]
        Strict,
        /// Keep every record that still verifies; the damaged file is copied
        /// beside the store first.
        Salvage,
    }

    const FIELDS: [&str; 6] = ["kind", "slug", "title", "summary", "body", "date"];

    fn bison(e: bison_db::Error) -> StoreError {
        let kind = match e {
            bison_db::Error::Locked | bison_db::Error::Io(_) => StoreErrorKind::Unavailable,
            bison_db::Error::ValueTooLarge => StoreErrorKind::Invalid,
            _ => StoreErrorKind::Other,
        };
        StoreError::new(kind, format!("content store: {e}"))
    }

    impl BisonStore {
        /// Opens (or creates) the store at `path`, creating its folder.
        pub fn open(path: impl AsRef<Path>) -> Result<BisonStore, StoreError> {
            BisonStore::open_with(path, Recovery::Strict)
        }

        /// [`open`](Self::open), with the recovery mode for a damaged file.
        pub fn open_with(
            path: impl AsRef<Path>,
            recovery: Recovery,
        ) -> Result<BisonStore, StoreError> {
            let path = path.as_ref().to_path_buf();
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).map_err(|e| {
                    StoreError::other(format!("content store {}: {e}", dir.display()))
                })?;
            }
            let shown = path.display().to_string();
            let mut db = DbOptions::new()
                .sync(SyncPolicy::Always)
                .recovery(match recovery {
                    Recovery::Strict => RecoveryMode::Strict,
                    Recovery::Salvage => RecoveryMode::Salvage,
                })
                .open(&path)
                .map_err(|e| match e {
                    bison_db::Error::Locked => StoreError::unavailable(format!(
                        "content store {shown} is open in another process: is another instance running on this data folder?"
                    )),
                    bison_db::Error::Corrupt(what) => StoreError::other(format!(
                        "content store {shown} is damaged before its end ({what}); nothing was changed. Back the file up, then start once with content.recovery = \"salvage\" to keep every record that still verifies"
                    )),
                    other => StoreError::other(format!("content store {shown}: {other}")),
                })?;
            db.create_index("slug").map_err(bison)?;
            let discarded = db.discarded_bytes();
            Ok(BisonStore {
                db: RwLock::new(db),
                path,
                discarded,
                failed: AtomicBool::new(false),
            })
        }

        /// Bytes the open removed: a torn last record after a crash, or the
        /// damaged regions a salvage skipped. Logged at boot when not zero.
        #[must_use]
        pub fn discarded(&self) -> u64 {
            self.discarded
        }

        /// Notes a failed write: the provider is unhealthy until reopened.
        fn failing<T>(&self, r: Result<T, StoreError>) -> Result<T, StoreError> {
            if r.is_err() {
                self.failed.store(true, Ordering::Release);
            }
            r
        }

        /// The store's file.
        #[must_use]
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl std::fmt::Debug for BisonStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BisonStore")
                .field("path", &self.path)
                .finish()
        }
    }

    impl Provider for BisonStore {
        fn name(&self) -> &str {
            "content-bison"
        }
        fn healthy(&self) -> bool {
            !self.failed.load(Ordering::Acquire)
        }
        fn flush(&self) -> Result<(), ProviderError> {
            let mut db = self
                .db
                .write()
                .map_err(|_| ProviderError("content store lock poisoned".into()))?;
            db.flush()
                .map_err(|e| ProviderError(format!("content store: {e}")))
        }
    }

    impl ContentStore for BisonStore {
        fn load(&self) -> Result<Vec<Stored>, StoreError> {
            let db = self
                .db
                .read()
                .map_err(|_| StoreError::other("store lock poisoned"))?;
            let mut out = Vec::with_capacity(db.len());
            for id in db.ids() {
                let Some(doc) = db.get(id).map_err(bison)? else {
                    continue;
                };
                let text = |name: &str| {
                    doc.get(name)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                };
                out.push(Stored {
                    kind: text("kind"),
                    slug: text("slug"),
                    title: text("title"),
                    summary: text("summary"),
                    body: text("body"),
                    date: text("date"),
                });
            }
            Ok(out)
        }

        fn put(&self, entry: &Stored) -> Result<(), StoreError> {
            let mut doc = Document::new();
            let values = [
                &entry.kind,
                &entry.slug,
                &entry.title,
                &entry.summary,
                &entry.body,
                &entry.date,
            ];
            for (name, value) in FIELDS.iter().zip(values) {
                doc.set(*name, value.as_str());
            }
            self.failing((|| {
                let mut db = self
                    .db
                    .write()
                    .map_err(|_| StoreError::other("store lock poisoned"))?;
                let existing = db
                    .find("slug", &Value::from(entry.slug.as_str()))
                    .map_err(bison)?;
                match existing.first() {
                    Some(id) => {
                        db.update(*id, doc).map_err(bison)?;
                    }
                    None => {
                        db.insert(doc).map_err(bison)?;
                    }
                }
                Ok(())
            })())
        }

        fn remove(&self, slug: &str) -> Result<bool, StoreError> {
            self.failing((|| {
                let mut db = self
                    .db
                    .write()
                    .map_err(|_| StoreError::other("store lock poisoned"))?;
                let ids = db.find("slug", &Value::from(slug)).map_err(bison)?;
                let mut any = false;
                for id in ids {
                    any |= db.delete(id).map_err(bison)?;
                }
                Ok(any)
            })())
        }
    }
}

/// Escapes text for HTML, once, at save time.
fn escape_into(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

impl Manifest {
    /// An empty manifest.
    #[must_use]
    pub fn new() -> Manifest {
        Manifest::default()
    }

    /// An empty manifest for a site installed under `base` (`/blog`): entry
    /// URLs are prepared with it.
    #[must_use]
    pub fn with_base(base: &str) -> Manifest {
        Manifest {
            base: base.trim_end_matches('/').to_owned(),
            ..Manifest::default()
        }
    }

    /// Validates and prepares a draft, then stores it (replacing an entry with
    /// the same slug) and rebuilds the post listing, newest first.
    pub fn save(&mut self, draft: &Draft<'_>) -> Result<(), SaveError> {
        self.validate(draft)?;
        let entry = Arc::new(self.prepare(draft));
        if let Some(store) = &self.store {
            // The author's text is what is stored; the HTML is made again
            // from it at every load, never trusted from the store.
            store
                .put(&Stored {
                    kind: entry.kind.clone(),
                    slug: entry.slug.clone(),
                    title: entry.title.clone(),
                    summary: entry.summary.clone(),
                    body: draft.body.to_owned(),
                    date: entry.date.clone(),
                })
                .map_err(SaveError::Store)?;
        }
        self.entries.insert(entry.slug.clone(), entry);
        self.rebuild_posts();
        Ok(())
    }

    /// The rules a draft must meet, at save and at load.
    fn validate(&self, draft: &Draft<'_>) -> Result<(), Invalid> {
        let slug_ok = !draft.slug.is_empty()
            && draft
                .slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !slug_ok {
            return Err(Invalid(format!(
                "slug `{}`: lowercase letters, digits, and `-` only",
                draft.slug
            )));
        }
        if draft.title.trim().is_empty() {
            return Err(Invalid(format!("`{}` has no title", draft.slug)));
        }
        if draft.kind == Kind::Post && draft.date.len() != 10 {
            return Err(Invalid(format!(
                "post `{}` needs a date (YYYY-MM-DD)",
                draft.slug
            )));
        }
        Ok(())
    }

    /// A draft that passed validation, prepared: the body escaped and split
    /// into paragraphs, the URL made for this site's base.
    fn prepare(&self, draft: &Draft<'_>) -> Entry {
        // A browser sends a textarea's line breaks as CRLF.
        let text = unix_newlines(draft.body);
        let mut body = String::with_capacity(text.len() + 32);
        for para in text.split("\n\n").map(str::trim).filter(|p| !p.is_empty()) {
            body.push_str("<p>");
            escape_into(&mut body, para);
            body.push_str("</p>");
        }
        let url = match draft.kind {
            Kind::Page => format!("{}/{}", self.base, draft.slug),
            Kind::Post => format!("{}/posts/{}", self.base, draft.slug),
        };
        Entry {
            kind: draft.kind.as_str().to_owned(),
            slug: draft.slug.to_owned(),
            title: draft.title.to_owned(),
            url,
            summary: draft.summary.to_owned(),
            body,
            date: draft.date.to_owned(),
            text: text.into_owned(),
        }
    }

    /// Rebuilds the post listing, newest first.
    fn rebuild_posts(&mut self) {
        let mut posts: Vec<Arc<Entry>> = self
            .entries
            .values()
            .filter(|e| e.kind == "post")
            .cloned()
            .collect();
        posts.sort_by(|a, b| b.date.cmp(&a.date).then_with(|| a.slug.cmp(&b.slug)));
        self.posts = Arc::new(posts);
    }

    /// The manifest of everything in `store`, for a site under `base`; saves
    /// go through the store. An empty store is given the sample content
    /// (`seed`), so a first run has a site.
    pub fn open(
        store: Arc<dyn ContentStore>,
        base: &str,
        seed: bool,
    ) -> Result<Manifest, StoreError> {
        let mut m = Manifest::with_base(base);
        let stored = store.load()?;
        for s in &stored {
            // The same rules and preparation as a save: what any writer put
            // in the store is checked and escaped like an author's draft,
            // never trusted as HTML.
            let kind = match s.kind.as_str() {
                "post" => Kind::Post,
                "page" => Kind::Page,
                other => {
                    return Err(StoreError::other(format!(
                        "`{}`: unknown kind `{other}`",
                        s.slug
                    )));
                }
            };
            let draft = Draft {
                kind,
                slug: &s.slug,
                title: &s.title,
                summary: &s.summary,
                body: &s.body,
                date: &s.date,
            };
            m.validate(&draft).map_err(|e| StoreError::invalid(e.0))?;
            let entry = Arc::new(m.prepare(&draft));
            m.entries.insert(entry.slug.clone(), entry);
        }
        // One listing for everything loaded, not one per entry.
        m.rebuild_posts();
        m.store = Some(store);
        if stored.is_empty() && seed {
            for d in &sample_drafts() {
                m.save(d).map_err(|e| match e {
                    SaveError::Store(e) => e,
                    SaveError::Invalid(e) => StoreError::invalid(e.0),
                })?;
            }
        }
        Ok(m)
    }

    /// Removes an entry (from the store too).
    pub fn remove(&mut self, slug: &str) -> Result<bool, StoreError> {
        if let Some(store) = &self.store {
            store.remove(slug)?;
        }
        let gone = self.entries.remove(slug).is_some();
        if gone {
            let posts: Vec<Arc<Entry>> = self
                .posts
                .iter()
                .filter(|p| p.slug != slug)
                .cloned()
                .collect();
            self.posts = Arc::new(posts);
        }
        Ok(gone)
    }

    /// The entry with this slug and kind.
    #[must_use]
    pub fn get(&self, kind: Kind, slug: &str) -> Option<Arc<Entry>> {
        self.entries
            .get(slug)
            .filter(|e| e.kind == kind.as_str())
            .cloned()
    }

    /// The entry with this slug, of either kind.
    #[must_use]
    pub fn find(&self, slug: &str) -> Option<Arc<Entry>> {
        self.entries.get(slug).cloned()
    }

    /// Whether an entry of either kind has this slug (one slug, one entry).
    #[must_use]
    pub fn contains(&self, slug: &str) -> bool {
        self.entries.contains_key(slug)
    }

    /// Every entry: posts newest first, then pages by slug.
    #[must_use]
    pub fn all(&self) -> Vec<Arc<Entry>> {
        let mut all: Vec<Arc<Entry>> = self.posts.iter().cloned().collect();
        all.extend(self.entries.values().filter(|e| e.kind == "page").cloned());
        all
    }

    /// The posts, newest first (shared, not copied).
    #[must_use]
    pub fn posts(&self) -> Arc<Vec<Arc<Entry>>> {
        self.posts.clone()
    }

    /// The sample content.
    #[must_use]
    pub fn sample() -> Manifest {
        Manifest::sample_at("")
    }

    /// The sample content for a site under `base`.
    #[must_use]
    pub fn sample_at(base: &str) -> Manifest {
        let mut m = Manifest::with_base(base);
        let drafts = sample_drafts();
        for d in &drafts {
            // The sample is fixed and valid.
            let _ = m.save(d);
        }
        m
    }
}

/// Today's date in UTC (`YYYY-MM-DD`), the default for a new post.
#[must_use]
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    date_of(i64::try_from(secs / 86_400).unwrap_or(0))
}

/// The civil date `days` after 1970-01-01.
fn date_of(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The content the site serves, shared by every request and the editor.
///
/// A request takes a snapshot (one `Arc`, no lock held while it renders). A
/// save prepares the next manifest beside the live one, writes through the
/// store, and swaps it in; saves run one at a time, and readers only ever
/// wait for the swap of a pointer, never for the store.
pub struct Content {
    live: RwLock<Arc<Manifest>>,
    writer: Mutex<()>,
    changed: Vec<Box<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Content")
            .field("live", &self.snapshot())
            .field("listeners", &self.changed.len())
            .finish()
    }
}

impl Content {
    /// The content of `manifest`.
    #[must_use]
    pub fn new(manifest: Manifest) -> Content {
        Content {
            live: RwLock::new(Arc::new(manifest)),
            writer: Mutex::new(()),
            changed: Vec::new(),
        }
    }

    /// The same content, calling `f` after every change is live (to drop
    /// cached pages).
    #[must_use]
    pub fn on_change(mut self, f: impl Fn() + Send + Sync + 'static) -> Content {
        self.changed.push(Box::new(f));
        self
    }

    /// The content as it is now.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Manifest> {
        self.live
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn publish(&self, next: Manifest) {
        *self.live.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
        for f in &self.changed {
            f();
        }
    }

    /// Saves `draft`. `replaces` is the slug the editor opened (`None` for
    /// a new entry): a slug that another entry already has is refused, and
    /// a renamed entry's old slug is removed.
    pub fn save(&self, draft: &Draft<'_>, replaces: Option<&str>) -> Result<(), SaveError> {
        let _one = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = (*self.snapshot()).clone();
        let renamed = replaces.filter(|old| *old != draft.slug && next.contains(old));
        if replaces != Some(draft.slug) && next.contains(draft.slug) {
            return Err(SaveError::Invalid(Invalid(format!(
                "slug `{}` is taken: another page or post has it",
                draft.slug
            ))));
        }
        next.save(draft)?;
        let removed = match renamed {
            Some(old) => next.remove(old).map(|_| ()),
            None => Ok(()),
        };
        // What the store took is live, even when removing the old slug
        // failed (both entries are then in the store and in memory).
        self.publish(next);
        removed.map_err(SaveError::Store)
    }

    /// Removes the entry with this slug; `false` when there was none.
    pub fn remove(&self, slug: &str) -> Result<bool, StoreError> {
        let _one = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = (*self.snapshot()).clone();
        let gone = next.remove(slug)?;
        if gone {
            self.publish(next);
        }
        Ok(gone)
    }
}

fn sample_drafts() -> [Draft<'static>; 4] {
    [
        Draft {
            kind: Kind::Post,
            slug: "hello-world",
            title: "Hello, world",
            summary: "The first page through the gateway, the core, and the web service.",
            body: "This page came in through the gateway, was identified by the core, routed by the web service, and rendered by the theme.\n\nEvery value on it was read through a view, never through JSON.",
            date: "2026-11-08",
        },
        Draft {
            kind: Kind::Post,
            slug: "the-passport",
            title: "The passport",
            summary: "One per request, from the pool to the reply and back.",
            body: "Every request carries one from the pool to the reply, and back, wiped.",
            date: "2026-11-09",
        },
        Draft {
            kind: Kind::Post,
            slug: "escaping",
            title: "Tom & Jerry <script>alert(1)</script>",
            summary: "A title with markup in it, written as text.",
            body: "<b>Not bold.</b> & not a tag either.",
            date: "2026-11-10",
        },
        Draft {
            kind: Kind::Page,
            slug: "about",
            title: "About",
            summary: "What this site is.",
            body: "A site in memory, themed from a folder, on the platform's walking skeleton.",
            date: "",
        },
    ]
}

/// `text` with every CRLF and lone CR as LF.
fn unix_newlines(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains('\r') {
        std::borrow::Cow::Owned(text.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_breaks_from_a_browser_make_paragraphs() {
        let mut m = Manifest::sample();
        m.save(&Draft {
            kind: Kind::Post,
            slug: "crlf",
            title: "From a browser",
            summary: "",
            body: "First line\r\nstill first.\r\n\r\nSecond.\r\rThird, from an old Mac.",
            date: "2026-11-19",
        })
        .expect("save");
        let e = m.get(Kind::Post, "crlf").expect("entry");
        assert_eq!(
            e.body,
            "<p>First line\nstill first.</p><p>Second.</p><p>Third, from an old Mac.</p>"
        );
        assert!(
            !e.text.contains('\r'),
            "the text kept for editing has no CR"
        );
    }

    #[test]
    fn save_prepares_escaped_paragraphs_and_lists_posts_newest_first() {
        let m = Manifest::sample();
        let e = m.get(Kind::Post, "escaping").expect("entry");
        assert_eq!(
            e.body,
            "<p>&lt;b&gt;Not bold.&lt;/b&gt; &amp; not a tag either.</p>"
        );
        assert_eq!(e.url, "/posts/escaping");
        let slugs: Vec<_> = m.posts().iter().map(|p| p.slug.clone()).collect();
        assert_eq!(slugs, ["escaping", "the-passport", "hello-world"]);
        assert!(m.get(Kind::Post, "about").is_none(), "a page is not a post");
    }

    #[test]
    fn content_survives_a_restart_in_bison_db() {
        let dir = std::env::temp_dir().join(format!("wasp-content-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("content.bison");
        {
            let store: Arc<dyn ContentStore> = Arc::new(BisonStore::open(&path).expect("open"));
            let mut m = Manifest::open(store.clone(), "", true).expect("manifest");
            assert_eq!(m.posts().len(), 3, "seeded on first open");
            m.save(&Draft {
                kind: Kind::Post,
                slug: "after-restart",
                title: "Still here",
                summary: "Saved before the restart.",
                body: "A <b>body</b>.",
                date: "2026-11-11",
            })
            .expect("save");
            assert!(m.remove("hello-world").expect("remove"));
            store.flush().expect("flush");
        }
        // A new process: nothing in memory, the file is all there is.
        let store: Arc<dyn ContentStore> = Arc::new(BisonStore::open(&path).expect("reopen"));
        let m = Manifest::open(store, "/blog", true).expect("manifest");
        let e = m.get(Kind::Post, "after-restart").expect("survived");
        assert_eq!(e.title, "Still here");
        assert_eq!(
            e.body, "<p>A &lt;b&gt;body&lt;/b&gt;.</p>",
            "stored prepared, not re-parsed"
        );
        assert_eq!(
            e.url, "/blog/posts/after-restart",
            "URL from where the site is now"
        );
        assert!(
            m.get(Kind::Post, "hello-world").is_none(),
            "the removal survived too"
        );
        assert_eq!(m.posts().len(), 3, "not seeded again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dates_are_civil_dates() {
        assert_eq!(super::date_of(0), "1970-01-01");
        assert_eq!(super::date_of(11_016), "2000-02-29");
        assert_eq!(super::date_of(19_723), "2024-01-01");
        assert_eq!(super::today().len(), 10);
    }

    #[test]
    fn content_saves_renames_and_refuses_a_taken_slug() {
        let changes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = changes.clone();
        let content = Content::new(Manifest::sample()).on_change(move || {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let before = content.snapshot();
        let draft = Draft {
            kind: Kind::Page,
            slug: "contact",
            title: "Contact",
            summary: "",
            body: "Write to us.",
            date: "",
        };
        content.save(&draft, None).expect("new");
        assert!(before.find("contact").is_none(), "a snapshot never changes");
        assert_eq!(
            content.snapshot().find("contact").map(|e| e.text.clone()),
            Some("Write to us.".to_owned())
        );
        let taken = content.save(
            &Draft {
                slug: "about",
                ..draft.clone()
            },
            None,
        );
        assert!(matches!(taken, Err(SaveError::Invalid(_))), "{taken:?}");
        let renamed = Draft {
            slug: "write-to-us",
            ..draft.clone()
        };
        content.save(&renamed, Some("contact")).expect("renamed");
        let now = content.snapshot();
        assert!(now.find("contact").is_none() && now.find("write-to-us").is_some());
        assert!(content.remove("write-to-us").expect("removed"));
        assert!(!content.remove("write-to-us").expect("gone"));
        // A save, a rename, a removal: each told the listeners (the refused
        // save and the removal of nothing did not).
        assert_eq!(changes.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn invalid_drafts_are_refused() {
        let mut m = Manifest::new();
        let bad = Draft {
            kind: Kind::Post,
            slug: "Bad Slug",
            title: "x",
            summary: "",
            body: "",
            date: "2026-11-10",
        };
        assert!(m.save(&bad).is_err());
        assert!(
            m.save(&Draft {
                slug: "ok",
                date: "",
                ..bad.clone()
            })
            .is_err(),
            "a post needs a date"
        );
        assert!(
            m.save(&Draft {
                slug: "ok",
                title: " ",
                ..bad
            })
            .is_err()
        );
    }

    #[test]
    fn what_the_store_holds_is_escaped_and_checked_at_load() {
        // Review F-7: anything that writes the store (an import, a restore,
        // another process) is treated like an author's draft.
        let store = Arc::new(MemoryStore::new());
        let put = |kind: &str, slug: &str, body: &str| {
            store
                .put(&Stored {
                    kind: kind.into(),
                    slug: slug.into(),
                    title: "Imported".into(),
                    summary: String::new(),
                    body: body.into(),
                    date: "2026-11-11".into(),
                })
                .expect("put");
        };
        put(
            "post",
            "x",
            "hi<script>alert(1)</script><meta http-equiv=refresh content=\"0;url=https://evil.example/\">",
        );
        let m = Manifest::open(store.clone(), "", false).expect("open");
        let body = &m.get(Kind::Post, "x").expect("entry").body;
        assert!(!body.contains("<script"), "{body}");
        assert!(!body.contains("<meta"), "{body}");
        assert!(body.starts_with("<p>hi&lt;script&gt;"), "{body}");

        put("post", "Bad Slug", "x");
        assert!(
            Manifest::open(store.clone(), "", false).is_err(),
            "slug rule at load"
        );
        let _ = store.remove("Bad Slug");
        put("script", "y", "x");
        assert!(
            Manifest::open(store.clone(), "", false).is_err(),
            "unknown kind at load"
        );
    }
}
