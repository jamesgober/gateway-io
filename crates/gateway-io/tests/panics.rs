//! A panic anywhere in a request never costs a worker its capacity: the
//! passport's slot wipes itself as it unwinds and the pool replaces it
//! (review F-1).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_io::{Door, Driver, Settings, WebServices};
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{
    AuthOut, Authentication, Authenticator, Core, Exit, Identified, Identity, Passport, Profile,
    RequestView, Rule, Service, ServiceCtx,
};

/// A passport service with a bug on one path.
struct Boom(ServiceCtx);

impl Service for Boom {
    fn name(&self) -> &str {
        "boom"
    }

    fn handle(&self, p: Passport<Identified>) -> Exit {
        if p.head().path() == "/boom" {
            panic!("a bug in a service");
        }
        let mut p = match self.0.access().authorize(p, &Rule::public(1)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        p.reply().text(200, "ok");
        p.answer()
    }
}

/// An authenticator with a bug on one path (before any service runs).
struct BoomAuth;

impl Authenticator for BoomAuth {
    fn authenticate(
        &self,
        request: RequestView<'_>,
        _profile: &Profile,
        out: &mut AuthOut,
    ) -> Authentication {
        out.set_cookie(b"sid=; Max-Age=0");
        if request.head().path() == "/auth-boom" {
            panic!("a bug in the authenticator");
        }
        Authentication::Identified(Identity::guest())
    }
}

fn open(workers: u16, passports: u32, driver: Driver) -> (Door, SocketAddr) {
    let core = Arc::new(
        Core::builder()
            .authenticator(BoomAuth)
            .service("boom", Boom)
            .profile("site", "boom", |_| {})
            .load()
            .expect("core"),
    );
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers,
        passports,
        driver,
        drain: Duration::from_secs(2),
        ..Settings::default()
    };
    let door =
        Door::open(core, &settings, UrgentLine::detached(), WebServices::new()).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

fn get(addr: SocketAddr, path: &str) -> Option<u16> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .ok()?;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).get(9..12)?.parse().ok()
}

/// `get`, retrying a 503 for a moment: the blocking driver admits
/// `workers` connections, and the one before may still be closing. A worker
/// that lost its passport for good answers 503 every time.
fn get_admitted(addr: SocketAddr, path: &str) -> Option<u16> {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        let got = get(addr, path);
        if got != Some(503) || Instant::now() >= until {
            return got;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn settle(door: &Door) {
    let until = Instant::now() + Duration::from_secs(5);
    while door.pool().stats().in_use != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn panics_then_served(driver: Driver, passports: u32) {
    let (door, addr) = open(1, passports, driver);
    let capacity = door.pool().stats().capacity;
    assert_eq!(get_admitted(addr, "/ok"), Some(200), "healthy at first");
    let panics = passports + 1;
    for i in 0..panics {
        let path = if i % 2 == 0 { "/boom" } else { "/auth-boom" };
        assert_eq!(get_admitted(addr, path), Some(500), "{path}");
    }
    settle(&door);
    let after: Vec<_> = (0..3).map(|_| get_admitted(addr, "/ok")).collect();
    assert_eq!(after, vec![Some(200); 3], "the worker keeps serving");
    settle(&door);
    let stats = door.pool().stats();
    assert_eq!(stats.lost, u64::from(panics), "{stats:?}");
    assert_eq!(stats.in_use, 0, "{stats:?}");
    assert_eq!(stats.capacity, capacity, "{stats:?}");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn panics_in_services_and_gates_never_cost_capacity() {
    panics_then_served(Driver::Reactor, 2);
}

#[test]
fn one_panic_does_not_disable_a_blocking_worker() {
    panics_then_served(Driver::Blocking, 1);
}
