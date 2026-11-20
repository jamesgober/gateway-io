//! A route marked `WorkClass::Cpu` (password hashing) runs on the gateway's
//! CPU pool: while it works, the reactor worker that holds its connection
//! answers other connections at once (G-80).
//!
//! No clock decides these tests: the slow route holds its thread until the
//! test releases it, and each test checks what was answered while it was
//! still held.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use gateway_io::{Door, Settings, WaspGate, WebServices, Who};
use serve_net::WorkClass;
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{Core, Rule};
use web_net::{App, Context, Route, get, post};

/// What the slow route waits on: it says when it has started, then holds its
/// thread until the test opens the gate.
#[derive(Default)]
struct Gate {
    started: Mutex<u32>,
    started_cv: Condvar,
    open: Mutex<bool>,
    open_cv: Condvar,
    /// Set just before the gate opens, so a reply can tell whether it came
    /// before.
    opened: AtomicBool,
}

/// Long enough for any machine; only a broken test waits this long.
const LIMIT: Duration = Duration::from_secs(20);

impl Gate {
    /// The slow route's side: counts itself in, then waits for the gate.
    fn hold(&self) {
        if let Ok(mut n) = self.started.lock() {
            *n += 1;
            self.started_cv.notify_all();
        }
        let open = self.open.lock().expect("gate");
        let _ = self.open_cv.wait_timeout_while(open, LIMIT, |o| !*o);
    }

    /// Waits until `n` slow requests are being held.
    fn wait_started(&self, n: u32) {
        let started = self.started.lock().expect("gate");
        let (started, _) = self
            .started_cv
            .wait_timeout_while(started, LIMIT, |s| *s < n)
            .expect("gate");
        assert!(*started >= n, "the slow route never started");
    }

    /// Lets every held request go.
    fn release(&self) {
        self.opened.store(true, Ordering::SeqCst);
        *self.open.lock().expect("gate") = true;
        self.open_cv.notify_all();
    }

    fn is_open(&self) -> bool {
        self.opened.load(Ordering::SeqCst)
    }
}

fn open(cpu_threads: u16, gate: &Arc<Gate>) -> (Door, SocketAddr) {
    let core = Arc::new(
        Core::builder()
            .external("web")
            .profile("site", "web", |_| {})
            .load()
            .expect("core"),
    );
    let g = Arc::clone(gate);
    let slow: Route<Who, Rule> = post("/sign-in", move |cx: &mut Context<'_, Who>| {
        // Stands in for Argon2id: the thread is held, not free.
        g.hold();
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
    s.set_read_timeout(Some(LIMIT)).expect("timeout");
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

#[test]
fn a_page_view_is_answered_while_a_sign_in_hashes() {
    let gate = Arc::new(Gate::default());
    let (door, addr) = open(2, &gate);
    let slow = std::thread::spawn(move || send(addr, SIGN_IN));
    gate.wait_started(1);
    // The sign-in holds its thread; the worker answers the page anyway.
    let page = send(addr, PAGE);
    assert_eq!(page, (200, "page".to_owned()));
    assert!(!gate.is_open(), "answered while the sign-in was still held");
    gate.release();
    let (status, body) = slow.join().expect("sign-in");
    assert_eq!(status, 200, "{body}");
    assert!(body.starts_with("hashed on gateway-cpu-"), "{body}");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn with_no_cpu_threads_the_worker_does_the_work_as_before() {
    let gate = Arc::new(Gate::default());
    let (door, addr) = open(0, &gate);
    let slow = std::thread::spawn(move || send(addr, SIGN_IN));
    gate.wait_started(1);
    // The one worker is held by the sign-in: the page cannot be answered
    // until the gate opens, however long that takes.
    let g = Arc::clone(&gate);
    let page = std::thread::spawn(move || {
        let got = send(addr, PAGE);
        (got, g.is_open())
    });
    // A moment for a wrong answer to show; the check below does not depend
    // on how long it is.
    std::thread::sleep(Duration::from_millis(200));
    gate.release();
    let (got, opened_first) = page.join().expect("page");
    assert_eq!(got, (200, "page".to_owned()));
    assert!(
        opened_first,
        "the page did not answer before the gate opened"
    );
    let (status, body) = slow.join().expect("sign-in");
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("gateway-cpu-"), "{body}");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn the_pool_answers_as_the_worker_would() {
    let gate = Arc::new(Gate::default());
    gate.release();
    let (door, addr) = open(1, &gate);
    // Several at once: each answered whole, one at a time on the pool.
    let all: Vec<_> = (0..3)
        .map(|_| std::thread::spawn(move || send(addr, SIGN_IN)))
        .collect();
    for h in all {
        let (status, body) = h.join().expect("sign-in");
        assert_eq!(status, 200, "{body}");
        assert!(body.starts_with("hashed on gateway-cpu-"), "{body}");
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
