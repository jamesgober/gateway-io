//! The core's guest output cache through the whole gateway: a guest's page
//! is answered without the service, and nothing else ever is.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use gateway_io::{Door, Settings, WebServices};
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{
    AuthOut, Authentication, Authenticator, CacheLimits, Core, Exit, GuestPages, Identified,
    Identity, Passport, PermSet, Profile, RequestView, Rule, Service, ServiceCtx, SessionId,
    UserId,
};

/// `Cookie: who=user` is a signed-in visitor; anyone else is a guest.
struct Who;

impl Authenticator for Who {
    fn authenticate(
        &self,
        request: RequestView<'_>,
        _profile: &Profile,
        _out: &mut AuthOut,
    ) -> Authentication {
        let user = request.head().header("cookie") == Some(&b"who=user"[..]);
        Authentication::Identified(if user {
            Identity::user(UserId(7), SessionId(9), PermSet::NONE)
        } else {
            Identity::guest()
        })
    }
}

/// Counts its calls; marks `/page` and `/short` for the guest cache, and
/// `/cookie` too (which sets a cookie, so it is never kept).
struct Counting {
    ctx: ServiceCtx,
    calls: Arc<AtomicUsize>,
}

impl Service for Counting {
    fn name(&self) -> &str {
        "counting"
    }

    fn handle(&self, p: Passport<Identified>) -> Exit {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let path = p.head().path().to_owned();
        let mut p = match self.ctx.access().authorize(p, &Rule::public(1)) {
            Ok(p) => p,
            Err(refused) => return refused,
        };
        let reply = p.reply();
        reply
            .status(200)
            .header("content-type", "text/plain; charset=utf-8")
            .body(format!("call {n}").as_bytes());
        match path.as_str() {
            "/page" => {
                reply.cache_for_guests(Duration::from_secs(60));
            }
            "/short" => {
                reply.cache_for_guests(Duration::from_millis(50));
            }
            "/gzip" => {
                reply
                    .header("content-encoding", "gzip")
                    .cache_for_guests(Duration::from_secs(60));
            }
            "/vary-language" => {
                reply
                    .header("vary", "Accept-Language")
                    .cache_for_guests(Duration::from_secs(60));
            }
            "/vary-cookie" => {
                reply
                    .header("vary", "accept-encoding, Cookie")
                    .cache_for_guests(Duration::from_secs(60));
            }
            "/vary-encoding" => {
                reply
                    .header("vary", "accept-encoding")
                    .cache_for_guests(Duration::from_secs(60));
            }
            "/cookie" => {
                reply
                    .header("set-cookie", "a=b; Path=/")
                    .cache_for_guests(Duration::from_secs(60));
            }
            _ => {}
        }
        p.answer()
    }
}

fn open() -> (Door, SocketAddr, Arc<AtomicUsize>, Arc<GuestPages>) {
    open_with(CacheLimits::default())
}

fn open_with(limits: CacheLimits) -> (Door, SocketAddr, Arc<AtomicUsize>, Arc<GuestPages>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let pages = Arc::new(GuestPages::new(limits));
    let c = calls.clone();
    let core = Arc::new(
        Core::builder()
            .authenticator(Who)
            .guest_cache(pages.clone())
            .service("counting", move |ctx| Counting {
                ctx,
                calls: c.clone(),
            })
            .profile("site", "counting", |_| {})
            .load()
            .expect("core"),
    );
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 8,
        ..Settings::default()
    };
    let door =
        Door::open(core, &settings, UrgentLine::detached(), WebServices::new()).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr, calls, pages)
}

/// The status and the body of one exchange.
fn send(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    s.write_all(request.as_bytes()).expect("write");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

fn get(addr: SocketAddr, target: &str, extra: &str) -> (u16, String) {
    send(
        addr,
        &format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n"),
    )
}

#[test]
fn a_guest_page_is_answered_without_the_service() {
    let (door, addr, calls, pages) = open();
    assert_eq!(get(addr, "/page", ""), (200, "call 1".to_owned()));
    assert_eq!(get(addr, "/page", ""), (200, "call 1".to_owned()), "cached");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let (status, body) = send(
        addr,
        "HEAD /page HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!((status, body.as_str()), (200, ""), "HEAD from the cache");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let stats = pages.stats();
    assert_eq!((stats.hits, stats.stored, stats.entries), (2, 1, 1));

    // Content changed: the next guest gets a fresh page.
    pages.purge();
    assert_eq!(get(addr, "/page", ""), (200, "call 2".to_owned()));
    assert_eq!(get(addr, "/page", ""), (200, "call 2".to_owned()));
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn only_guests_get_cached_pages_and_only_plain_ones_are_kept() {
    let (door, addr, calls, pages) = open();
    assert_eq!(get(addr, "/page", "").1, "call 1");

    // A signed-in visitor, a query, a POST, another host: the service.
    assert_eq!(get(addr, "/page", "Cookie: who=user\r\n").1, "call 2");
    assert_eq!(get(addr, "/page?x=1", "").1, "call 3");
    assert_eq!(
        get(addr, "/page?x=1", "").1,
        "call 4",
        "a query is never kept"
    );
    let (_, body) = send(
        addr,
        "POST /page HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body, "call 5");
    let (_, body) = send(
        addr,
        "GET /page HTTP/1.1\r\nHost: other.example\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(body, "call 6", "keyed by host");

    // A reply that sets a cookie, or one the service did not mark: not kept.
    assert_eq!(get(addr, "/cookie", "").1, "call 7");
    assert_eq!(get(addr, "/cookie", "").1, "call 8");
    assert_eq!(get(addr, "/plain", "").1, "call 9");
    assert_eq!(get(addr, "/plain", "").1, "call 10");
    // An encoded body was chosen for one visitor's Accept-Encoding.
    assert_eq!(get(addr, "/gzip", "").1, "call 11");
    assert_eq!(get(addr, "/gzip", "").1, "call 12");

    // A page kept briefly runs out.
    assert_eq!(get(addr, "/short", "").1, "call 13");
    assert_eq!(get(addr, "/short", "").1, "call 13");
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(get(addr, "/short", "").1, "call 14", "expired");

    // The guest copy of /page is still the first call's.
    assert_eq!(get(addr, "/page", "").1, "call 1");
    assert_eq!(calls.load(Ordering::SeqCst), 14);
    assert!(pages.stats().entries >= 2);
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn the_cache_keeps_to_its_limits() {
    let (door, addr, calls, pages) = open_with(CacheLimits {
        entries: 1,
        ..CacheLimits::default()
    });
    assert_eq!(get(addr, "/page", "").1, "call 1");
    assert_eq!(get(addr, "/short", "").1, "call 2");
    assert_eq!(pages.stats().entries, 1, "the oldest page made room");
    assert_eq!(get(addr, "/page", "").1, "call 3", "evicted");
    let (door2, addr2, _, small) = open_with(CacheLimits {
        entry_bytes: 4,
        ..CacheLimits::default()
    });
    assert_eq!(get(addr2, "/page", "").1, "call 1");
    assert_eq!(
        small.stats().stored,
        0,
        "a page over entry_bytes is not kept"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let _ = door.close(Duration::from_secs(1));
    let _ = door2.close(Duration::from_secs(1));
}

#[test]
fn a_reply_that_varies_on_more_than_encoding_is_not_kept() {
    let (door, addr, calls, _) = open();
    // The key is the path: a page chosen by language or by cookie would be
    // handed to the next guest whatever they asked for.
    let fr = "Accept-Language: fr\r\n";
    let de = "Accept-Language: de\r\n";
    assert_eq!(get(addr, "/vary-language", fr).1, "call 1");
    assert_eq!(get(addr, "/vary-language", de).1, "call 2");
    assert_eq!(get(addr, "/vary-cookie", "").1, "call 3");
    assert_eq!(get(addr, "/vary-cookie", "").1, "call 4");
    // Varying on Accept-Encoding alone is fine: an encoded body is never kept.
    assert_eq!(get(addr, "/vary-encoding", "").1, "call 5");
    assert_eq!(get(addr, "/vary-encoding", "").1, "call 5", "kept");
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    let _ = door.close(Duration::from_secs(1));
}
