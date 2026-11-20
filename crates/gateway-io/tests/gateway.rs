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
            .profile("site", "hello", |p| {
                p.lanes = vec![wasp_core::LaneRule::exact(
                    "/health",
                    wasp_core::Lane::CRITICAL,
                )];
            })
            .load()
            .expect("core loads"),
    )
}

/// The `Retry-After` of a refusal: one to three seconds.
fn retry_after_spread(got: &Got) -> bool {
    ["1", "2", "3"]
        .iter()
        .any(|s| has_field(got, "retry-after", s))
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
    let open = Door::open(
        core(),
        settings,
        line.clone(),
        gateway_io::WebServices::new(),
    )
    .expect("gateway opens");
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
    assert_eq!(open.tickets_held(), 0, "every request ticket released");
    let report = open.close(Duration::from_secs(2));
    assert_eq!(report.killed, 0);
}

#[test]
fn customs_refuses_before_any_gate() {
    let (open, addr, _line) = open(&settings(1, 4));
    let long_target = format!("/{}", "a".repeat(5000));
    let got = get(addr, &long_target).expect("reply");
    assert_eq!(got.status, 414);
    // Review N-4: the gateway's own refusals are never sniffed or cached.
    assert!(
        has_field(&got, "x-content-type-options", "nosniff"),
        "{}",
        got.head
    );
    assert!(has_field(&got, "cache-control", "no-store"), "{}", got.head);
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
    // The passport is given back only after the answer arrives: had the
    // request waited for it, no answer would come at all. So a 503 here,
    // with the passport still out, is a refusal that did not wait.
    let got = get(addr, "/").expect("a response");
    assert_eq!(got.status, 503);
    assert!(retry_after_spread(&got), "{}", got.head);
    assert_eq!(
        open.pool().stats().in_use,
        1,
        "answered while the only passport was still held"
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
fn browsing_cannot_take_the_reserved_passports() {
    // Four passports, one held back: three in use by browsing fill what
    // browsing may take, and a health check still gets the fourth.
    let (open, addr, _line) = open(&Settings {
        reserve: Some(1),
        ..settings(1, 4)
    });
    let held: Vec<_> = (0..3)
        .map(|_| open.pool().admit_and_take(0).expect("a browsing passport"))
        .collect();
    assert!(open.pool().admit_and_take(0).is_none(), "browsing is full");
    let got = get(addr, "/").expect("a response");
    assert_eq!(got.status, 503, "{}", got.head);
    assert!(retry_after_spread(&got), "{}", got.head);
    assert_eq!(get(addr, "/health").map(|g| g.status), Some(200));
    for p in held {
        open.pool().give_back_and_release(p.refuse(500));
    }
    assert_eq!(get(addr, "/").map(|g| g.status), Some(200), "free again");
    let _ = open.close(Duration::from_secs(1));
}

#[test]
fn shed_keeps_the_reserved_lanes() {
    let (open, addr, line) = open(&settings(1, 4));
    line.set(Level::Shed, "test").expect("shed");
    open.running().server_handle().wake_all();
    thread::sleep(Duration::from_millis(50));
    let got = get(addr, "/");
    assert!(got.as_ref().is_none_or(|g| g.status == 503), "{got:?}");
    assert_eq!(
        get(addr, "/health").map(|g| g.status),
        Some(200),
        "health checks pass under shed"
    );
    line.shift(Level::Shed, Level::Normal, "test over")
        .expect("normal");
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
    // Admitted (a passport reserved once the head was complete), body pending.
    let until = Instant::now() + Duration::from_secs(5);
    while open.pool().stats().in_use == 0 && Instant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(open.pool().stats().in_use, 1, "the request is in flight");
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

/// An authenticator that clears a dead session cookie, refuses a request
/// carrying `x-banned`, and cannot reach its store for one carrying
/// `x-store-down`, as a real auth gate would.
struct DeadSession;

impl wasp_core::Authenticator for DeadSession {
    fn authenticate(
        &self,
        request: wasp_core::RequestView<'_>,
        _profile: &wasp_core::Profile,
        out: &mut wasp_core::AuthOut,
    ) -> wasp_core::Authentication {
        if request.head().header("cookie").is_some() {
            out.set_cookie(b"__Host-sid=; Max-Age=0; Path=/; Secure; HttpOnly");
        }
        if request.head().header("x-banned").is_some() {
            wasp_core::Authentication::Refused(wasp_core::Refusal::status(403))
        } else if request.head().header("x-store-down").is_some() {
            wasp_core::Authentication::Unavailable
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
    let open = Door::open(
        core,
        &settings(1, 4),
        UrgentLine::detached(),
        gateway_io::WebServices::new(),
    )
    .expect("opens");
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

    // The credential store cannot answer: 503 with Retry-After, never a guest.
    let got = exchange(
        addr,
        b"GET / HTTP/1.1\r\nHost: a\r\nX-Store-Down: 1\r\nConnection: close\r\n\r\n",
    )
    .expect("a response");
    assert_eq!(got.status, 503, "{}", got.head);
    assert!(has_field(&got, "retry-after", "5"), "{}", got.head);

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

#[test]
fn the_blocking_driver_serves_every_connection_it_admits() {
    // Review F-4: serve-net's blocking driver runs more threads than
    // `workers`; every one of them needs a shelf.
    let s = Settings {
        driver: gateway_io::Driver::Blocking,
        ..settings(4, 1)
    };
    let (door, addr, _line) = open(&s);
    let mut conns: Vec<TcpStream> = (0..4)
        .map(|_| {
            let c = TcpStream::connect(addr).expect("connect");
            c.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("timeout");
            c
        })
        .collect();
    for round in 0..3 {
        for (i, c) in conns.iter_mut().enumerate() {
            c.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .expect("send");
            let got = read_response(c).expect("reply");
            assert_eq!(
                got.status, 200,
                "connection {i}, round {round}: {}",
                got.head
            );
        }
    }
    drop(conns);
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_closed_door_lets_go_of_the_core() {
    // The bouncer's ejector held the transport, whose service held the core:
    // nothing was ever freed, and a store's file lock stayed taken.
    let core = core();
    let weak = Arc::downgrade(&core);
    let door = Door::open(
        core,
        &settings(1, 4),
        UrgentLine::detached(),
        gateway_io::WebServices::new(),
    )
    .expect("opens");
    let addr = door.local_addr().expect("addr");
    assert_eq!(get(addr, "/").map(|g| g.status), Some(200));
    let _ = door.close(Duration::from_secs(2));
    let until = Instant::now() + Duration::from_secs(5);
    while weak.upgrade().is_some() && Instant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(weak.upgrade().is_none(), "the core is freed after close");
}

#[test]
fn slow_browsing_sheds_on_its_own_and_recovers() {
    let mut s = settings(1, 4);
    s.shed_passports = 0;
    s.shed_slow = Duration::from_millis(20);
    s.shed_check = Duration::from_millis(10);
    let (open, addr, line) = open(&s);
    // Quick replies: nothing happens.
    for _ in 0..5 {
        assert_eq!(get(addr, "/").map(|g| g.status), Some(200));
    }
    thread::sleep(Duration::from_millis(50));
    assert_eq!(line.level(), Level::Normal);

    // Slow browsing: the watch sheds.
    let until = Instant::now() + Duration::from_secs(5);
    while line.level() == Level::Normal && Instant::now() < until {
        let _ = get(addr, "/slow?ms=150");
    }
    assert_eq!(line.level(), Level::Shed, "the load watch shed");
    open.running().server_handle().wake_all();
    thread::sleep(Duration::from_millis(20));
    assert_eq!(
        get(addr, "/health").map(|g| g.status),
        Some(200),
        "health checks pass under shed"
    );

    // Quiet again: back to normal on its own.
    let until = Instant::now() + Duration::from_secs(5);
    while line.level() == Level::Shed && Instant::now() < until {
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(line.level(), Level::Normal, "the load passed");
    open.running().server_handle().wake_all();
    thread::sleep(Duration::from_millis(20));
    assert_eq!(get(addr, "/").map(|g| g.status), Some(200));
    let _ = open.close(Duration::from_secs(1));
}

#[test]
fn closing_the_door_lowers_a_shed_the_watch_raised() {
    let mut s = settings(1, 4);
    s.shed_passports = 0;
    s.shed_slow = Duration::from_millis(20);
    s.shed_check = Duration::from_millis(10);
    let (open, addr, line) = open(&s);
    let until = Instant::now() + Duration::from_secs(5);
    while line.level() == Level::Normal && Instant::now() < until {
        let _ = get(addr, "/slow?ms=150");
    }
    assert_eq!(line.level(), Level::Shed);
    let _ = open.close(Duration::from_secs(1));
    assert_eq!(line.level(), Level::Normal);
}

#[test]
fn the_access_log_writes_a_line_per_request_without_the_query() {
    let (tx, rx) = std::sync::mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    let access = gateway_io::AccessLog::with_writer(move |e| {
        let _ = tx.lock().expect("lock").send(e.clone());
    })
    .expect("access log");
    let line = UrgentLine::detached();
    let open = Door::open_with(
        core(),
        &settings(1, 4),
        line.clone(),
        gateway_io::WebServices::new(),
        gateway_io::Extras {
            access: Some(access),
            ..gateway_io::Extras::default()
        },
    )
    .expect("gateway opens");
    let addr = open.local_addr().expect("addr");
    assert_eq!(get(addr, "/?token=secret").map(|g| g.status), Some(200));
    let e = rx.recv_timeout(Duration::from_secs(5)).expect("a line");
    assert_eq!((&*e.method, &*e.path), ("GET", "/"));
    assert_eq!((e.status, e.end), (Some(200), "replied"));
    assert!(e.bytes_out > 0 && e.server_time.is_some(), "{e:?}");
    assert_eq!(e.client, Some(IpAddr::from([127, 0, 0, 1])));
    assert!(!format!("{e:?}").contains("secret"), "no query in the log");

    // A shed request is written too.
    line.set(Level::Shed, "test").expect("shed");
    open.running().server_handle().wake_all();
    thread::sleep(Duration::from_millis(50));
    let _ = get(addr, "/");
    let e = rx.recv_timeout(Duration::from_secs(5)).expect("a line");
    assert_eq!((&*e.path, e.status), ("/", Some(503)), "{e:?}");
    line.shift(Level::Shed, Level::Normal, "test over")
        .expect("normal");
    let _ = open.close(Duration::from_secs(1));
}

/// Counts the bouncer's strikes.
#[derive(Default)]
struct Strikes(std::sync::atomic::AtomicUsize);

impl bouncer_io::EventSink for Strikes {
    fn event(&self, e: &bouncer_io::Event<'_>) {
        if e.signal == bouncer_io::signals::STRIKE {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

fn open_counting_strikes() -> (Door, SocketAddr, Arc<Strikes>) {
    let strikes = Arc::new(Strikes::default());
    let open = Door::open_with(
        core(),
        &settings(1, 4),
        UrgentLine::detached(),
        gateway_io::WebServices::new(),
        gateway_io::Extras {
            events: Some(strikes.clone()),
            ..gateway_io::Extras::default()
        },
    )
    .expect("gateway opens");
    let addr = open.local_addr().expect("addr");
    (open, addr, strikes)
}

/// Past net-io's 5 s grace for the inbound rate.
const PAST_GRACE: Duration = Duration::from_secs(7);

#[test]
fn a_keep_alive_connection_idle_after_a_full_exchange_is_no_strike() {
    let (open, addr, strikes) = open_counting_strikes();
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write");
    let mut buf = [0u8; 4096];
    let n = s.read(&mut buf).expect("reply");
    assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "a full exchange");
    thread::sleep(PAST_GRACE);
    assert_eq!(strikes.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(s);
    let _ = open.close(Duration::from_secs(1));
}

/// A browser opens a spare connection ahead of need and may never use it:
/// it closes at the head deadline, never as a slow peer the bouncer strikes.
#[test]
fn a_connection_that_never_sends_a_byte_is_no_strike() {
    let (open, addr, strikes) = open_counting_strikes();
    let s = TcpStream::connect(addr).expect("connect");
    thread::sleep(PAST_GRACE);
    assert_eq!(strikes.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    drop(s);
    let _ = open.close(Duration::from_secs(1));
}
