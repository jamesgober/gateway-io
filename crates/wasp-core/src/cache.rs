//! The guest output cache seam: the core answers a guest's cacheable page
//! without waking the service.
//!
//! Implementations live in this crate: answering from the cache writes a reply
//! on an identified passport, which nothing outside the core may do.
//!
//! ```text
//!  core, after authentication:
//!    a guest?  GET or HEAD?  no body?  no query?        any "no" ─▶ the service
//!    key = (profile, host, target)
//!    a fresh entry?                                     no ─▶ the service
//!    yes ─▶ the stored status, fields, and body ─▶ the response pipeline
//!  core, after a passport service answered:
//!    the service marked the reply (Reply::cache_for_guests), a guest's GET,
//!    status 200, no Set-Cookie, no Content-Encoding,
//!    within the limits                                  ─▶ kept under the key
//!  gateway, after a web service answered (Core::finish_for_guests):
//!    the same offer, with the web reply copied in
//! ```
//!
//! The door, authentication, and the response pipeline still run on a hit:
//! a banned address reads nothing, and the authentication cookie still goes
//! out. A query string never hits or is kept, so random queries cannot push
//! real pages out. [`GuestPages::purge`] drops everything (the site calls it
//! when content changes).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::passport::{Exit, Passport};
use crate::slot::{Head, ReplyKind, Trip};
use crate::stage::Identified;

/// The core's guest output cache. Only guests, only `GET` and `HEAD`, only
/// requests without a body; the service decides what is stored.
pub trait GuestCache: Send + Sync + 'static {
    /// A hit answers the request (`Ok`); a miss hands the passport back (`Err`).
    #[allow(clippy::result_large_err)]
    fn guest_hit(&self, p: Passport<Identified>) -> Result<Exit, Passport<Identified>>;

    /// A passport service's answer that it marked for guests
    /// ([`Reply::cache_for_guests`](crate::Reply::cache_for_guests)): the
    /// cache decides whether to keep it. The default keeps nothing.
    fn offer(&self, exit: &Exit) {
        let _ = exit;
    }
}

impl<T: GuestCache> GuestCache for Arc<T> {
    #[inline]
    fn guest_hit(&self, p: Passport<Identified>) -> Result<Exit, Passport<Identified>> {
        (**self).guest_hit(p)
    }

    #[inline]
    fn offer(&self, exit: &Exit) {
        (**self).offer(exit);
    }
}

/// No cache: every request goes to its service. Correct, only minimal.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCache;

impl GuestCache for NoCache {
    #[inline]
    fn guest_hit(&self, p: Passport<Identified>) -> Result<Exit, Passport<Identified>> {
        Err(p)
    }
}

/// What [`GuestPages`] may hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheLimits {
    /// Pages at most (default 1,024).
    pub entries: usize,
    /// Bytes at most, every page's fields and body together (default 32 MiB).
    pub bytes: usize,
    /// The largest page kept (default 1 MiB).
    pub entry_bytes: usize,
    /// The longest a page is kept, whatever the service asked (default one
    /// hour).
    pub max_ttl: Duration,
}

impl Default for CacheLimits {
    fn default() -> CacheLimits {
        CacheLimits {
            entries: 1024,
            bytes: 32 << 20,
            entry_bytes: 1 << 20,
            max_ttl: Duration::from_secs(3600),
        }
    }
}

/// What [`GuestPages`] has done so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Requests answered from the cache.
    pub hits: u64,
    /// Guest requests that could have been answered and were not.
    pub misses: u64,
    /// Pages kept.
    pub stored: u64,
    /// Pages held now (fresh or not yet replaced).
    pub entries: u64,
    /// Bytes held now.
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    profile: u8,
    host: Box<[u8]>,
    target: Box<str>,
}

/// A kept field: its name and value.
type Field = (Box<str>, Box<[u8]>);

struct Page {
    status: u16,
    fields: Box<[Field]>,
    body: Box<[u8]>,
    expires: Instant,
    size: usize,
}

#[derive(Default)]
struct Inner {
    pages: HashMap<Key, Arc<Page>>,
    /// Keys in the order they were first kept: the oldest goes first.
    order: VecDeque<Key>,
    bytes: usize,
}

/// The guest output cache: whole replies in memory, bounded by
/// [`CacheLimits`], oldest first out, each kept for the time its service
/// asked for (at most `max_ttl`).
pub struct GuestPages {
    inner: RwLock<Inner>,
    limits: CacheLimits,
    hits: AtomicU64,
    misses: AtomicU64,
    stored: AtomicU64,
}

impl Default for GuestPages {
    fn default() -> GuestPages {
        GuestPages::new(CacheLimits::default())
    }
}

impl std::fmt::Debug for GuestPages {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestPages")
            .field("limits", &self.limits)
            .field("stats", &self.stats())
            .finish()
    }
}

/// The key of a request the cache may answer or keep: no query, no body.
fn key_of(trip: &Trip, head: &Head) -> Option<Key> {
    if !head.is_get_or_head() || head.query().is_some() {
        return None;
    }
    let no_body = head.header("transfer-encoding").is_none()
        && head
            .header("content-length")
            .is_none_or(|v| v.iter().all(|b| *b == b'0'));
    if !no_body {
        return None;
    }
    Some(Key {
        profile: trip.profile.0,
        host: head
            .header("host")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .into_boxed_slice(),
        target: head.target().into(),
    })
}

impl GuestPages {
    /// An empty cache with these limits.
    #[must_use]
    pub fn new(limits: CacheLimits) -> GuestPages {
        GuestPages {
            inner: RwLock::new(Inner::default()),
            limits,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            stored: AtomicU64::new(0),
        }
    }

    /// Drops every page (the content changed).
    pub fn purge(&self) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        inner.pages.clear();
        inner.order.clear();
        inner.bytes = 0;
    }

    /// The counters and what is held.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let inner = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stored: self.stored.load(Ordering::Relaxed),
            entries: inner.pages.len() as u64,
            bytes: inner.bytes as u64,
        }
    }

    fn keep(&self, key: Key, page: Page) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let size = page.size;
        match inner.pages.insert(key.clone(), Arc::new(page)) {
            Some(old) => inner.bytes -= old.size,
            None => inner.order.push_back(key),
        }
        inner.bytes += size;
        while inner.pages.len() > self.limits.entries || inner.bytes > self.limits.bytes {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            if let Some(gone) = inner.pages.remove(&oldest) {
                inner.bytes -= gone.size;
            }
        }
        self.stored.fetch_add(1, Ordering::Relaxed);
    }
}

impl GuestCache for GuestPages {
    fn guest_hit(&self, p: Passport<Identified>) -> Result<Exit, Passport<Identified>> {
        if !p.identity().is_guest() {
            return Err(p);
        }
        let Some(key) = key_of(p.trip(), p.head()) else {
            return Err(p);
        };
        let page = self
            .inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .pages
            .get(&key)
            .cloned();
        let Some(page) = page.filter(|page| Instant::now() < page.expires) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return Err(p);
        };
        self.hits.fetch_add(1, Ordering::Relaxed);
        Ok(p.answer_cached(|reply| {
            reply.status(page.status);
            for (name, value) in &page.fields {
                reply.header(name, value);
            }
            reply.body(&page.body);
        }))
    }

    fn offer(&self, exit: &Exit) {
        let reply = exit.reply();
        let Some(ttl) = reply.guest_ttl().map(|t| t.min(self.limits.max_ttl)) else {
            return;
        };
        // Only a guest's GET (a HEAD reply has no body to keep), a full 200
        // answer, nothing personal in it, and a body every client can read
        // (an encoded one was chosen for this visitor's Accept-Encoding).
        if ttl.is_zero()
            || !exit.identity().is_some_and(|i| i.is_guest())
            || exit.head().method() != "GET"
            || reply.status_code() != 200
            || reply.kind() != ReplyKind::Answer
            || reply.fields().any(|(n, _)| {
                n.eq_ignore_ascii_case(b"set-cookie") || n.eq_ignore_ascii_case(b"content-encoding")
            })
        {
            return;
        }
        let Some(key) = key_of(exit.trip(), exit.head()) else {
            return;
        };
        let mut fields = Vec::with_capacity(reply.fields().len());
        let mut size = reply.body_bytes().len();
        for (name, value) in reply.fields() {
            let Ok(name) = std::str::from_utf8(name) else {
                return;
            };
            size += name.len() + value.len();
            fields.push((Box::<str>::from(name), Box::<[u8]>::from(value)));
        }
        if size > self.limits.entry_bytes {
            return;
        }
        self.keep(
            key,
            Page {
                status: 200,
                fields: fields.into_boxed_slice(),
                body: reply.body_bytes().into(),
                expires: Instant::now() + ttl,
                size,
            },
        );
    }
}
