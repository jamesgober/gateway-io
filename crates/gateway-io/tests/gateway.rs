//! The gateway end to end over loopback TCP: admission, customs, the door,
//! revocation, the urgent line, and the drain.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings};
use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::kernel::{Level, UrgentLine};

fn core() -> Arc<Core> {
    Arc::new(
        Core::builder()
            .service("hello", Hello::with_slow_route)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core loads"),
    )
}

fn settings(workers: u16, passports: u32) -> Settings {
    Settings {
        listen: "127.0.0.1:0".into(),
        workers,
        passports,
        drain: Duration::from_secs(5),
        ..Settings::default()
    }
}

fn open(settings: &Settings) -> (Door, SocketAddr, UrgentLine) {
    let line = UrgentLine::detached();
    let open = Door::open(core(), settings, line.clone()).expect("gateway opens");
    let addr = open.local_addr().expect("a TCP listener");
    (open, addr, line)
}

/// What a request got back: the status, the head, the body; `None` when the
/// connection was closed or reset without a response.
#[derive(Debug)]
struct Got {
    status: u16,
    head: String,
    body: Vec<u8>,
}

fn exchange(addr: SocketAddr, request: &[u8]) -> Option<Got> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    s.write_all(request).ok()?;
    read_response(&mut s)
}

fn read_response(s: &mut TcpStream) -> Option<Got> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let status = head.get(9..12)?.parse().ok()?;
    let len: usize = head
        .lines()
        .find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())?
        })
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    Some(Got {
        status,
        head,
        body: buf[head_end..].to_vec(),
    })
}

fn get(addr: SocketAddr, target: &str) -> Option<Got> {
    exchange(
        addr,
        format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
}

fn has_field(got: &Got, name: &str, value: &str) -> bool {
    got.head.lines().any(|l| {
        l.split_once(':').is_some_and(|(n, v)| {
            n.eq_ignore_ascii_case(name) && v.trim().eq_ignore_ascii_case(value)
        })
    })
}

#[test]
fn hello_end_to_end_and_every_passport_returns() {
    let (open, addr, _line) = open(&settings(2, 8));
    let got = get(addr, "/a%3Cb%3E").expect("a response");
    assert_eq!(got.status, 200);
    let body = String::from_utf8_lossy(&got.body);
    assert!(
        body.contains("Hello from WASP") && body.contains("/a%3Cb%3E"),
        "{body}"
    );

    let got = exchange(
        addr,
        b"POST /form HTTP/1.1\r\nHost: a\r\nContent-Length: 8\r\nConnection: close\r\n\r\nname=ada",
    )
    .expect("a response");
    assert_eq!(got.status, 200);
    assert!(String::from_utf8_lossy(&got.body).contains("body: 8 bytes"));

    assert_eq!(get(addr, "/x").map(|g| g.status), Some(200));
    let got = exchange(
        addr,
        b"PUT /x HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .expect("a response");
    assert_eq!(got.status, 405);

    // Keep-alive: three requests on one connection, each with its own passport.
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    for i in 0..3 {
        s.write_all(format!("GET /{i} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes())
            .expect("write");
        assert_eq!(read_response(&mut s).map(|g| g.status), Some(200));
    }
    drop(s);
    thread::sleep(Duration::from_millis(100));
    assert_eq!(open.pool().stats().in_use, 0, "every passport went back");
    let report = open.close(Duration::from_secs(2));
    assert_eq!(report.killed, 0);
}

#[test]
fn customs_refuses_before_any_gate() {
    let (open, addr, _line) = open(&settings(1, 4));
    let long_target = format!("/{}", "a".repeat(5000));
    assert_eq!(get(addr, &long_target).map(|g| g.status), Some(414));
    let many: String = (0..70).map(|i| format!("X-{i}: v\r\n")).collect();
    let got = exchange(
        addr,
        format!("GET / HTTP/1.1\r\nHost: a\r\n{many}\r\n").as_bytes(),
    );
    assert_eq!(got.map(|g| g.status), Some(431));
    let got = exchange(addr, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
    assert_eq!(got.map(|g| g.status), Some(400), "HTTP/1.1 without Host");
    let got = exchange(addr, b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n");
    assert_eq!(got.map(|g| g.status), Some(400), "two Host fields");
    let big = "x".repeat(20_000);
    let got = exchange(
        addr,
        format!("GET / HTTP/1.1\r\nHost: a\r\nX-Big: {big}\r\n\r\n").as_bytes(),
    );
    assert_eq!(
        got.map(|g| g.status),
        Some(431),
        "oversized header (parser limit)"
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(open.pool().stats().in_use, 0);
    let _ = open.close(Duration::from_secs(1));
}

#[test]
fn a_full_worker_answers_503_without_a_passport() {
    // One worker with one passport. With inline dispatch a worker runs one
    // call at a time, so its shelf fills only when passports are held
    // elsewhere (deferred or offloaded work): hold the only one here.
    let (open, addr, _line) = open(&settings(1, 1));
    let held = open
        .pool()
        .admit_and_take(0)
        .expect("the worker's passport");
    let started = Instant::now();
    let got = get(addr, "/").expect("a response");
    assert_eq!(got.status, 503);
    assert!(has_field(&got, "retry-after", "1"), "{}", got.head);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "refused at once"
    );
    assert!(open.pool().stats().refused >= 1);
    open.pool().give_back_and_release(held.refuse(500));
    assert_eq!(get(addr, "/").map(|g| g.status), Some(200), "free again");
    let _ = open.close(Duration::from_secs(1));
}

#[test]
fn a_banned_address_is_closed_before_a_byte_is_read() {
    let mut s = settings(1, 4);
    s.ban = vec!["127.0.0.1".parse::<IpAddr>().expect("address")];
    let (open, addr, _line) = open(&s);
    assert!(get(addr, "/").is_none(), "no response for a banned address");
    open.bouncer()
        .lift("127.0.0.1".parse::<IpAddr>().expect("address"))
        .expect("lift");
    assert_eq!(get(addr, "/").map(|g| g.status), Some(200));
    let _ = open.close(Duration::from_secs(1));
}

#[test]
fn a_revocation_during_a_request_denies_its_reply() {
    let (open, addr, _line) = open(&settings(2, 4));
    let slow = thread::spawn(move || get(addr, "/slow?ms=600"));
    // Revoke only once the request is in flight (it holds a passport): a
    // revocation is not a ban, so a request that starts after it is served.
    let until = Instant::now() + Duration::from_secs(5);
    while open.pool().stats().in_use == 0 && Instant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(open.pool().stats().in_use, 1, "the request is in flight");
    open.bouncer()
        .revoke(
            "127.0.0.1".parse::<IpAddr>().expect("address"),
            bouncer_io::Reason::ADMIN,
        )
        .expect("revoke");
    // The reply was built, then the last checkpoint denied it: the content
    // never leaves (a denial or a closed connection, never a 200).
    let got = slow.join().expect("thread");
    assert!(
        got.as_ref()
            .is_none_or(|g| g.status == 403 || g.status == 503),
        "{got:?}"
    );
    assert!(
        got.as_ref()
            .is_none_or(|g| !String::from_utf8_lossy(&g.body).contains("Hello")),
        "content leaked after revocation"
    );
    thread::sleep(Duration::from_millis(100));
    assert_eq!(open.pool().stats().in_use, 0);
    let _ = open.close(Duration::from_secs(1));
}

#[test]
fn shed_on_the_urgent_line_refuses_the_default_lane() {
    let (open, addr, line) = open(&settings(1, 4));
    assert_eq!(get(addr, "/").map(|g| g.status), Some(200));
    line.set(Level::Shed, "test").expect("shed");
    open.running().server_handle().wake_all();
    thread::sleep(Duration::from_millis(50));
    let got = get(addr, "/");
    assert!(got.as_ref().is_none_or(|g| g.status == 503), "{got:?}");
    line.shift(Level::Shed, Level::Normal, "test over")
        .expect("normal");
    open.running().server_handle().wake_all();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(get(addr, "/").map(|g| g.status), Some(200));
    let _ = open.close(Duration::from_secs(1));
}

#[test]
fn drain_finishes_in_flight_work_and_refuses_new_connections() {
    let (open, addr, _line) = open(&settings(2, 4));
    let slow = thread::spawn(move || get(addr, "/slow?ms=700"));
    let until = Instant::now() + Duration::from_secs(5);
    while open.pool().stats().in_use == 0 && Instant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(open.pool().stats().in_use, 1, "the request is in flight");
    let started = Instant::now();
    // Shutdown step 1 on this thread, so the probe below cannot race it; the
    // drain (step 2, which closes the door again: idempotent) runs alongside.
    open.running().close_door();
    let closer = thread::spawn(move || open.close(Duration::from_secs(5)));
    // The door is closed: a new connection gets nothing.
    assert!(get(addr, "/").is_none(), "accepted after the door closed");
    let got = slow
        .join()
        .expect("thread")
        .expect("the in-flight request finished");
    assert_eq!(got.status, 200);
    assert!(has_field(&got, "connection", "close"), "{}", got.head);
    let report = closer.join().expect("thread");
    assert_eq!(report.killed, 0, "{report:?}");
    assert!(report.requests_finished >= 1, "{report:?}");
    assert!(!report.deadline_hit);
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn drain_deadline_kills_what_is_left() {
    // A request still sending its body when the drain starts: it never
    // completes, so the deadline closes it.
    let (open, addr, _line) = open(&settings(2, 4));
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    s.write_all(b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\n\r\nfirst bytes")
        .expect("write");
    thread::sleep(Duration::from_millis(200));
    let started = Instant::now();
    let report = open.close(Duration::from_millis(300));
    assert!(report.deadline_hit, "{report:?}");
    assert!(report.killed >= 1, "{report:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the deadline held"
    );
    let got = read_response(&mut s);
    assert!(got.as_ref().is_none_or(|g| g.status != 200), "{got:?}");
}

/// An authenticator that clears a dead session cookie and refuses a request
/// carrying `x-banned`, as a real auth gate would.
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
        if request.head().header("x-banned").is_some() {
            wasp_core::Authentication::Refused(wasp_core::Refusal::status(403))
        } else {
            wasp_core::Authentication::Identified(wasp_core::Identity::guest())
        }
    }
}

#[test]
fn authentication_cookie_rides_on_answers_and_refusals() {
    let core = Arc::new(
        Core::builder()
            .authenticator(DeadSession)
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core loads"),
    );
    let open = Door::open(core, &settings(1, 4), UrgentLine::detached()).expect("opens");
    let addr = open.local_addr().expect("addr");
    let cleared = "__Host-sid=; Max-Age=0; Path=/; Secure; HttpOnly";

    let got = exchange(
        addr,
        b"GET / HTTP/1.1\r\nHost: a\r\nCookie: __Host-sid=dead\r\nConnection: close\r\n\r\n",
    )
    .expect("a response");
    assert_eq!(got.status, 200);
    assert!(has_field(&got, "set-cookie", cleared), "{}", got.head);

    let got = exchange(
        addr,
        b"GET / HTTP/1.1\r\nHost: a\r\nCookie: __Host-sid=dead\r\nX-Banned: 1\r\nConnection: close\r\n\r\n",
    )
    .expect("a response");
    assert_eq!(got.status, 403);
    assert!(has_field(&got, "set-cookie", cleared), "{}", got.head);

    // A request without a cookie gets none: the buffer was wiped with the passport.
    let got = get(addr, "/").expect("a response");
    assert_eq!(got.status, 200);
    assert!(
        !got.head.to_ascii_lowercase().contains("set-cookie"),
        "{}",
        got.head
    );
    let _ = open.close(Duration::from_secs(1));
}
