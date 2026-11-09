//! The web site through the whole path over loopback: gateway, core, web-net.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WaspGate, WebServices, Who};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{Core, Rule};
use web_net::{App, Cx, Route, get};

fn settings() -> Settings {
    Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        drain: Duration::from_secs(5),
        ..Settings::default()
    }
}

/// Opens the process's own wiring from configuration text.
fn open_site(conf: &str) -> (Door, SocketAddr) {
    let config = Config::from_text(conf).expect("config");
    let wiring = wasp::wire(&config).expect("wiring");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let door = Door::open(wiring.core, &settings(), UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

#[derive(Debug)]
struct Got {
    status: u16,
    head: String,
    body: String,
}

impl Got {
    fn field(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
    fn count(&self, name: &str) -> usize {
        self.head
            .lines()
            .filter(|l| {
                l.split_once(':')
                    .is_some_and(|(n, _)| n.eq_ignore_ascii_case(name))
            })
            .count()
    }
}

fn read_response(s: &mut TcpStream) -> Option<Got> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let status = head.get(9..12)?.parse().ok()?;
    let len: usize = head
        .lines()
        .find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())?
        })
        .unwrap_or(0);
    while buf.len() < end + len {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    Some(Got {
        status,
        head,
        body: String::from_utf8_lossy(&buf[end..]).into_owned(),
    })
}

fn send(addr: SocketAddr, request: &str) -> Option<Got> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    s.write_all(request.as_bytes()).ok()?;
    read_response(&mut s)
}

fn get_on(addr: SocketAddr, host: &str, target: &str) -> Option<Got> {
    send(
        addr,
        &format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
}

fn get_path(addr: SocketAddr, target: &str) -> Option<Got> {
    get_on(addr, "localhost", target)
}

fn settle(door: &Door) {
    let until = Instant::now() + Duration::from_secs(2);
    while (door.pool().stats().in_use != 0 || door.tickets_held() != 0) && Instant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(door.tickets_held(), 0, "every request ticket released");
}

#[test]
fn pages_routes_methods_and_canonical_urls() {
    let (door, addr) = open_site("");
    let home = get_path(addr, "/").expect("home");
    assert_eq!(home.status, 200);
    assert!(home.body.contains("/posts/hello-world"), "{}", home.body);
    assert_eq!(home.field("x-content-type-options"), Some("nosniff"));

    let post = get_path(addr, "/posts/the-passport").expect("post");
    assert_eq!(post.status, 200);
    assert!(post.body.contains("<h1>The passport</h1>"));

    assert_eq!(get_path(addr, "/posts/nope").map(|g| g.status), Some(404));
    assert_eq!(get_path(addr, "/nowhere").map(|g| g.status), Some(404));

    let moved = get_path(addr, "/posts/hello-world/").expect("slash");
    assert_eq!(moved.status, 301);
    assert!(
        moved
            .field("location")
            .is_some_and(|l| l.ends_with("/posts/hello-world"))
    );
    let dots = get_path(addr, "/posts/../about").expect("dots");
    assert_eq!(dots.status, 301);
    assert_eq!(get_path(addr, "/a%2Fb").map(|g| g.status), Some(400));

    let wrong = send(
        addr,
        "DELETE / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .expect("delete");
    assert_eq!(wrong.status, 405);
    assert!(
        wrong.field("allow").is_some_and(|a| a.contains("GET")),
        "{}",
        wrong.head
    );

    assert_eq!(get_path(addr, "/health").map(|g| g.status), Some(200));
    settle(&door);
    assert_eq!(door.pool().stats().in_use, 0, "every passport returned");
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn authorization_is_the_cores_access_gate() {
    let (door, addr) = open_site("");
    // A guest: the account page's rule needs a signed-in account, so web-net
    // sends a GET to sign-in (303) and refuses anything else (401).
    let got = get_path(addr, "/account").expect("account");
    assert_eq!(got.status, 303);
    assert!(
        got.field("location")
            .is_some_and(|l| l.contains("/sign-in")),
        "{}",
        got.head
    );
    assert!(!got.body.contains("Signed in."));
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn a_site_in_a_folder() {
    let (door, addr) = open_site("[site]\nbase = \"/blog\"\n");
    let home = get_path(addr, "/blog/").expect("home");
    assert_eq!(home.status, 200);
    assert!(
        home.body.contains("href=\"/blog/posts/hello-world\""),
        "{}",
        home.body
    );
    assert_eq!(get_path(addr, "/blog/about").map(|g| g.status), Some(200));
    assert_ne!(
        get_path(addr, "/about").map(|g| g.status),
        Some(200),
        "outside the folder"
    );
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn a_domain_site_and_localhost() {
    let (door, addr) = open_site("[site]\nhosts = [\"example.com\"]\n");
    assert_eq!(
        get_on(addr, "example.com", "/").map(|g| g.status),
        Some(200)
    );
    let other = get_on(addr, "localhost", "/").expect("a response");
    assert_ne!(
        other.status, 200,
        "a host the site does not answer: {}",
        other.head
    );
    // The development site (no hosts) answers localhost.
    let (dev, dev_addr) = open_site("");
    assert_eq!(
        get_on(dev_addr, "localhost", "/").map(|g| g.status),
        Some(200)
    );
    let _ = door.close(Duration::from_secs(1));
    let _ = dev.close(Duration::from_secs(1));
}

#[test]
fn the_hello_passport_service_still_serves_when_chosen() {
    let (door, addr) = open_site("[site]\nservice = \"hello\"\n");
    let got = get_path(addr, "/anything").expect("hello");
    assert_eq!(got.status, 200);
    assert!(got.body.contains("Hello from WASP"));
    let _ = door.close(Duration::from_secs(1));
}

/// A web app with a slow page that also sets a cookie, to prove a revocation
/// replaces the whole reply (no field of it leaves).
fn slow_app(core: &Core) -> App<WaspGate> {
    let slow: Route<Who, Rule> = get("/slow", |cx: &mut Cx<'_, Who>| {
        thread::sleep(Duration::from_millis(600));
        cx.set_header("x-secret", "leaked");
        cx.html(200, "<p>content</p>");
        Ok(())
    })
    .public();
    App::with_gate(WaspGate::new(core.access().clone()))
        .development()
        .route(slow)
        .build()
        .expect("app")
}

fn web_core(authenticator: impl wasp_core::Authenticator) -> Arc<Core> {
    Arc::new(
        Core::builder()
            .authenticator(authenticator)
            .external("web")
            .profile("site", "web", |_| {})
            .load()
            .expect("core"),
    )
}

#[test]
fn a_revocation_during_a_web_request_replaces_the_whole_reply() {
    let core = web_core(wasp_core::EveryoneGuest);
    let mut web = WebServices::new();
    web.attach(core.service_tag("web").expect("tag"), slow_app(&core));
    let door = Door::open(core, &settings(), UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    let slow = thread::spawn(move || get_path(addr, "/slow"));
    let until = Instant::now() + Duration::from_secs(5);
    while door.pool().stats().in_use == 0 && Instant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(door.pool().stats().in_use, 1, "in flight");
    door.bouncer()
        .revoke(
            "127.0.0.1".parse::<IpAddr>().expect("ip"),
            bouncer_io::Reason::ADMIN,
        )
        .expect("revoke");
    let got = slow.join().expect("thread");
    // serve-net's last checkpoint replaced the reply whole: the denial's
    // status and nothing of what the handler wrote.
    let got = got.expect("a denial, not a closed connection");
    assert_eq!(got.status, 403, "{got:?}");
    assert!(
        !got.head.contains("leaked") && !got.body.contains("content"),
        "{got:?}"
    );
    assert!(got.field("content-security-policy").is_none(), "{got:?}");
    settle(&door);
    assert_eq!(door.pool().stats().in_use, 0);
    let _ = door.close(Duration::from_secs(1));
}

/// Clears a dead session cookie, as the auth gate does.
struct DeadSession;
impl wasp_core::Authenticator for DeadSession {
    fn authenticate(
        &self,
        request: wasp_core::RequestView<'_>,
        _profile: &wasp_core::Profile,
        cookie: &mut wasp_core::AuthCookie,
    ) -> wasp_core::Authentication {
        if request.head().header("cookie").is_some() {
            cookie.set(b"__Host-sid=; Max-Age=0; Path=/; Secure; HttpOnly");
        }
        wasp_core::Authentication::Identified(wasp_core::Identity::guest())
    }
}

#[test]
fn the_authentication_cookie_goes_out_once_on_web_replies() {
    let core = web_core(DeadSession);
    let site = wasp::site::build(
        core.access().clone(),
        wasp::site::Content::sample(),
        &wasp::site::SiteSettings::default(),
    )
    .expect("site");
    let mut web = WebServices::new();
    web.attach(core.service_tag("web").expect("tag"), site);
    let door = Door::open(core, &settings(), UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    let got = send(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nCookie: __Host-sid=dead\r\nConnection: close\r\n\r\n",
    )
    .expect("home");
    assert_eq!(got.status, 200);
    assert_eq!(got.count("set-cookie"), 1, "{}", got.head);
    assert!(
        got.field("set-cookie")
            .is_some_and(|c| c.starts_with("__Host-sid=;"))
    );
    // And on a page web-net refuses (404), the same.
    let got = send(
        addr,
        "GET /nope HTTP/1.1\r\nHost: localhost\r\nCookie: __Host-sid=dead\r\nConnection: close\r\n\r\n",
    )
    .expect("404");
    assert_eq!(got.status, 404);
    assert_eq!(got.count("set-cookie"), 1, "{}", got.head);
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn a_missing_web_service_refuses_to_open() {
    let core = web_core(wasp_core::EveryoneGuest);
    let err = Door::open(
        core,
        &settings(),
        UrgentLine::detached(),
        WebServices::new(),
    )
    .err()
    .expect("refused");
    assert!(err.0.contains("web"), "{err}");
}

#[test]
fn static_files_from_a_folder() {
    let dir = std::env::temp_dir().join(format!("wasp-site-assets-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(dir.join("hello.txt"), b"static hello").expect("file");
    std::fs::write(dir.join(".env"), b"SECRET=1").expect("hidden");
    let conf = format!(
        "[site]\nassets = \"{}\"\n",
        dir.display()
            .to_string()
            .replace(std::path::MAIN_SEPARATOR, "/")
    );
    let (door, addr) = open_site(&conf);
    let got = get_path(addr, "/static/hello.txt").expect("file");
    assert_eq!(got.status, 200, "{}", got.head);
    assert_eq!(got.body, "static hello");
    assert!(
        got.field("content-type")
            .is_some_and(|t| t.starts_with("text/plain")),
        "{}",
        got.head
    );
    assert_eq!(
        get_path(addr, "/static/.env").map(|g| g.status),
        Some(404),
        "hidden files"
    );
    let up = get_path(addr, "/static/%2e%2e/Cargo.toml").expect("traversal");
    assert_ne!(up.status, 200, "{}", up.head);
    assert_eq!(
        get_path(addr, "/static/missing.txt").map(|g| g.status),
        Some(404)
    );
    settle(&door);
    let _ = door.close(Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
}
