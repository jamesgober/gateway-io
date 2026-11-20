//! A route marked `WorkClass::Cpu` (password hashing) runs on the gateway's
//! CPU pool: while it works, the reactor worker that holds its connection
//! answers other connections at once (G-80).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WaspGate, WebServices, Who};
use serve_net::WorkClass;
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{Core, Rule};
use web_net::{App, Context, Route, get, post};

/// How long the slow route works: far longer than a page view takes.
const SLOW: Duration = Duration::from_millis(800);

fn open(cpu_threads: u16) -> (Door, SocketAddr) {
    let core = Arc::new(
        Core::builder()
            .external("web")
            .profile("site", "web", |_| {})
            .load()
            .expect("core"),
    );
    let slow: Route<Who, Rule> = post("/sign-in", |cx: &mut Context<'_, Who>| {
        // Stands in for Argon2id: the thread is busy, not waiting on I/O.
        let until = Instant::now() + SLOW;
        let mut n = 0u64;
        while Instant::now() < until {
            n = std::hint::black_box(n.wrapping_add(1));
        }
        cx.text(
            200,
            &format!("hashed on {}", std::thread::current().name().unwrap_or("?")),
        )
    })
    .public()
    .csrf_exempt("a test route")
    .work(WorkClass::Cpu);
    let page: Route<Who, Rule> =
        get("/", |cx: &mut Context<'_, Who>| cx.text(200, "page")).public();
    let app: App<WaspGate> = App::with_gate(WaspGate::new(core.access().clone()))
        .development()
        .route(slow)
        .route(page)
        .build()
        .expect("app");
    let mut web = WebServices::new();
    web.attach(core.service_tag("web").expect("tag"), app);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        // One worker: every connection shares it.
        workers: 1,
        passports: 8,
        cpu_threads,
        ..Settings::default()
    };
    let door = Door::open(core, &settings, UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

/// The status and body of one request on its own connection.
fn send(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    s.write_all(request.as_bytes()).expect("write");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map_or("", |(_, b)| b)
        .to_owned();
    (status, body)
}

const SIGN_IN: &str =
    "POST /sign-in HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const PAGE: &str = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

/// How long a page view takes while a sign-in works on another connection
/// of the same worker, and the sign-in's answer.
fn page_during_sign_in(addr: SocketAddr) -> (Duration, (u16, String)) {
    let slow = std::thread::spawn(move || send(addr, SIGN_IN));
    // Let the sign-in reach its handler first.
    std::thread::sleep(Duration::from_millis(150));
    let t = Instant::now();
    let (status, body) = send(addr, PAGE);
    let took = t.elapsed();
    assert_eq!((status, body.as_str()), (200, "page"));
    (took, slow.join().expect("sign-in"))
}

#[test]
fn a_page_view_is_answered_while_a_sign_in_hashes() {
    let (door, addr) = open(2);
    let (took, (status, body)) = page_during_sign_in(addr);
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("hashed on gateway-cpu-"), "{body}");
    // The worker was free: the page did not wait for the hashing (which
    // has well over half of its time still to go when the page is asked).
    assert!(took < SLOW / 2, "the page waited {took:?}");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn with_no_cpu_threads_the_worker_does_the_work_as_before() {
    let (door, addr) = open(0);
    let (took, (status, body)) = page_during_sign_in(addr);
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("gateway-cpu-"), "{body}");
    // The one worker was busy hashing: the page waited for it.
    assert!(took >= SLOW / 2, "the page did not wait: {took:?}");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn the_pool_answers_as_the_worker_would() {
    let (door, addr) = open(1);
    // Several at once: each answered whole, one at a time on the pool.
    let all: Vec<_> = (0..3)
        .map(|_| std::thread::spawn(move || send(addr, SIGN_IN)))
        .collect();
    for h in all {
        let (status, body) = h.join().expect("sign-in");
        assert_eq!(status, 200, "{body}");
    }
    // HTTP/1.0: the connection closes after the reply, which still arrives
    // whole from the pool.
    let (status, body) = send(
        addr,
        "POST /sign-in HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("hashed on gateway-cpu-"), "{body}");
    let _ = door.close(Duration::from_secs(2));
}
