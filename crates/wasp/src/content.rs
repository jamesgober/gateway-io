//! The content manifest: entries prepared when they are saved, served from
//! memory, read by the templates through the `View` trait.
//!
//! The heavy work happens when content is saved ([`Manifest::save`]): the
//! body is turned into safe HTML once (every character escaped, paragraphs
//! split), the URL and the listing are computed. A request only borrows what
//! is already there: an entry is an `Arc<Entry>`, the post listing one shared
//! `Arc<Vec<Arc<Entry>>>`, so rendering a page copies no content.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use bison_db::{Db, DbOptions, Document, SyncPolicy, Value};
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
    /// The body, safe HTML prepared at save time.
    pub body: String,
    /// The date, for posts.
    pub date: String,
}

/// Why the store failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

/// Where the content lives between restarts: the provider seam for content.
/// Writes happen when content is saved, never per request; the site reads
/// everything at boot.
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
            .map_err(|_| StoreError("store lock poisoned".into()))?;
        Ok(entries.values().cloned().collect())
    }
    fn put(&self, entry: &Stored) -> Result<(), StoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError("store lock poisoned".into()))?;
        entries.insert(entry.slug.clone(), entry.clone());
        Ok(())
    }
    fn remove(&self, slug: &str) -> Result<bool, StoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError("store lock poisoned".into()))?;
        Ok(entries.remove(slug).is_some())
    }
}

/// Content in a bison-db file: one document per entry, keyed by slug. Every
/// write is synced to disk (content is written rarely and must survive a
/// crash); the slug index is declared at open (bison-db keeps indexes in
/// memory).
pub struct BisonStore {
    db: RwLock<Db>,
    path: PathBuf,
}

const FIELDS: [&str; 6] = ["kind", "slug", "title", "summary", "body", "date"];

fn bison(e: bison_db::Error) -> StoreError {
    StoreError(format!("content store: {e}"))
}

impl BisonStore {
    /// Opens (or creates) the store at `path`, creating its folder.
    pub fn open(path: impl AsRef<Path>) -> Result<BisonStore, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)
                .map_err(|e| StoreError(format!("content store {}: {e}", dir.display())))?;
        }
        let mut db = DbOptions::new()
            .sync(SyncPolicy::Always)
            .open(&path)
            .map_err(bison)?;
        db.create_index("slug").map_err(bison)?;
        Ok(BisonStore {
            db: RwLock::new(db),
            path,
        })
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
            .map_err(|_| StoreError("store lock poisoned".into()))?;
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
        let mut db = self
            .db
            .write()
            .map_err(|_| StoreError("store lock poisoned".into()))?;
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
    }

    fn remove(&self, slug: &str) -> Result<bool, StoreError> {
        let mut db = self
            .db
            .write()
            .map_err(|_| StoreError("store lock poisoned".into()))?;
        let ids = db.find("slug", &Value::from(slug)).map_err(bison)?;
        let mut any = false;
        for id in ids {
            any |= db.delete(id).map_err(bison)?;
        }
        Ok(any)
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
    pub fn save(&mut self, draft: &Draft<'_>) -> Result<(), Invalid> {
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
        let mut body = String::with_capacity(draft.body.len() + 32);
        for para in draft
            .body
            .split("\n\n")
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            body.push_str("<p>");
            escape_into(&mut body, para);
            body.push_str("</p>");
        }
        let url = match draft.kind {
            Kind::Page => format!("{}/{}", self.base, draft.slug),
            Kind::Post => format!("{}/posts/{}", self.base, draft.slug),
        };
        let entry = Arc::new(Entry {
            kind: draft.kind.as_str().to_owned(),
            slug: draft.slug.to_owned(),
            title: draft.title.to_owned(),
            url,
            summary: draft.summary.to_owned(),
            body,
            date: draft.date.to_owned(),
        });
        if let Some(store) = &self.store {
            store
                .put(&Stored {
                    kind: entry.kind.clone(),
                    slug: entry.slug.clone(),
                    title: entry.title.clone(),
                    summary: entry.summary.clone(),
                    body: entry.body.clone(),
                    date: entry.date.clone(),
                })
                .map_err(|e| Invalid(e.0))?;
        }
        self.insert(entry);
        Ok(())
    }

    fn insert(&mut self, entry: Arc<Entry>) {
        self.entries.insert(entry.slug.clone(), entry);
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
            let url = match s.kind.as_str() {
                "post" => format!("{}/posts/{}", m.base, s.slug),
                _ => format!("{}/{}", m.base, s.slug),
            };
            m.insert(Arc::new(Entry {
                kind: s.kind.clone(),
                slug: s.slug.clone(),
                title: s.title.clone(),
                summary: s.summary.clone(),
                body: s.body.clone(),
                date: s.date.clone(),
                url,
            }));
        }
        m.store = Some(store);
        if stored.is_empty() && seed {
            for d in &sample_drafts() {
                m.save(d).map_err(|e| StoreError(e.0))?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
