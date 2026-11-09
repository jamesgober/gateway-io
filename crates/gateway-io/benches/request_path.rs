//! The whole request path over loopback TCP: the gateway (bouncer door,
//! admission, passport, customs, core, hello service, encode, egress) against
//! bare serve-net answering the same page on the same workers. The difference
//! is what the platform adds on top of the transport.
//!
//! ```text
//! cargo bench -p gateway-io --bench request_path
//! ```
//!
//! std only. Keep-alive connections, one request in flight per connection,
//! client and server on the same machine (so the client's own cost is in
//! every figure, equally for both servers). Numbers from a laptop compare
//! builds with each other; they are not the published figures.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use gateway_io::{Door, ServerTime, Settings, TimeObserver, WaspGate, WebServices};
use serve_net::{KeepAlive, ListenerSpec, Server, Workers};
use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::kernel::UrgentLine;

const WORKERS: u16 = 4;
const REQUEST: &[u8] =
    b"GET /bench HTTP/1.1\r\nHost: localhost\r\nUser-Agent: bench\r\nAccept: text/html\r\n\r\n";

/// The same page the hello service renders for `/bench`.
const PAGE: &str = "<!doctype html><meta charset=utf-8><title>hello</title><h1>Hello from WASP</h1><p>path: <code>/bench</code></p>";

fn read_one(s: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    buf.clear();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = &buf[..end];
            let len = std::str::from_utf8(head)
                .ok()
                .and_then(|h| {
                    h.lines().find_map(|l| {
                        let (n, v) = l.split_once(':')?;
                        n.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    })
                })
                .unwrap_or(0);
            if buf.len() >= end + 4 + len {
                return buf.starts_with(b"HTTP/1.1 200");
            }
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return false,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

struct Run {
    requests: u64,
    elapsed: Duration,
    p50: Duration,
    p99: Duration,
    p999: Duration,
    failed: u64,
}

/// `conns` keep-alive connections, `per_conn` requests each.
fn drive(addr: SocketAddr, conns: usize, per_conn: usize) -> Run {
    let start = Arc::new(Barrier::new(conns + 1));
    let handles: Vec<_> = (0..conns)
        .map(|_| {
            let start = start.clone();
            thread::spawn(move || {
                let mut s = TcpStream::connect(addr).expect("connect");
                s.set_nodelay(true).expect("nodelay");
                s.set_read_timeout(Some(Duration::from_secs(10)))
                    .expect("timeout");
                let mut buf = Vec::with_capacity(4096);
                // Warm the connection.
                for _ in 0..200 {
                    s.write_all(REQUEST).expect("write");
                    read_one(&mut s, &mut buf);
                }
                start.wait();
                let mut lat = Vec::with_capacity(per_conn);
                let mut failed = 0;
                for _ in 0..per_conn {
                    let t = Instant::now();
                    if s.write_all(REQUEST).is_err() || !read_one(&mut s, &mut buf) {
                        failed += 1;
                        break;
                    }
                    lat.push(t.elapsed());
                }
                (lat, failed)
            })
        })
        .collect();
    start.wait();
    let t = Instant::now();
    let mut all = Vec::new();
    let mut failed = 0;
    for h in handles {
        let (lat, f) = h.join().expect("client");
        all.extend(lat);
        failed += f;
    }
    let elapsed = t.elapsed();
    all.sort();
    let pick = |q: f64| all[((all.len() as f64 * q) as usize).min(all.len() - 1)];
    Run {
        requests: all.len() as u64,
        elapsed,
        p50: pick(0.50),
        p99: pick(0.99),
        p999: pick(0.999),
        failed,
    }
}

fn print(name: &str, conns: usize, r: &Run) {
    let rps = r.requests as f64 / r.elapsed.as_secs_f64();
    println!(
        "| {name} | {conns} | {:.0} | {:.1} | {:.1} | {:.1} | {} |",
        rps,
        r.p50.as_nanos() as f64 / 1000.0,
        r.p99.as_nanos() as f64 / 1000.0,
        r.p999.as_nanos() as f64 / 1000.0,
        r.failed
    );
}

/// One server under test: its name, address, and server-time histogram.
struct Under<'a> {
    name: &'a str,
    addr: SocketAddr,
    time: &'a ServerTime,
}

/// Runs `a` and `b` alternately for each case and prints both tables.
fn compare(title: &str, a: &Under<'_>, b: &Under<'_>, cases: &[(usize, usize)]) {
    println!("### {title}");
    println!();
    println!("| server | connections | requests/s | p50 us | p99 us | p99.9 us | failed |");
    println!("|---|---|---|---|---|---|---|");
    let mut server_rows = Vec::new();
    for &(conns, per) in cases {
        // Alternate, and keep the better of two runs each, so neither server
        // gets the quieter moment of a shared machine.
        let mut best_a: Option<Run> = None;
        let mut best_b: Option<Run> = None;
        a.time.reset();
        b.time.reset();
        for _ in 0..2 {
            let r = drive(a.addr, conns, per);
            if best_a.as_ref().is_none_or(|x| r.p50 < x.p50) {
                best_a = Some(r);
            }
            let r = drive(b.addr, conns, per);
            if best_b.as_ref().is_none_or(|x| r.p50 < x.p50) {
                best_b = Some(r);
            }
        }
        if let (Some(ra), Some(rb)) = (best_a, best_b) {
            print(a.name, conns, &ra);
            print(b.name, conns, &rb);
            println!(
                "| difference at p50 | {conns} | | {:+.1} | | | |",
                (rb.p50.as_nanos() as f64 - ra.p50.as_nanos() as f64) / 1000.0
            );
        }
        server_rows.push((conns, a.time.summary(), b.time.summary()));
    }
    println!();
    println!(
        "Server time per request (head complete to reply handed to net-io), measured inside each server:"
    );
    println!();
    println!(
        "| connections | {} mean ns | {} mean ns | added, mean ns | {} p50 below | {} p99 below |",
        a.name, b.name, b.name, b.name
    );
    println!("|---|---|---|---|---|---|");
    for (conns, sa, sb) in server_rows {
        println!(
            "| {conns} | {} | {} | {:+} | {:?} | {:?} |",
            sa.mean.as_nanos(),
            sb.mean.as_nanos(),
            sb.mean.as_nanos() as i128 - sa.mean.as_nanos() as i128,
            sb.p50,
            sb.p99
        );
    }
    println!();
}

fn bench_route<I: web_net::Identity, R: Send + Sync + 'static>() -> web_net::Route<I, R> {
    web_net::get("/bench", |cx: &mut web_net::Cx<'_, I>| {
        cx.html(200, PAGE);
        Ok(())
    })
    .public()
}

fn main() {
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: WORKERS,
        passports: 256,
        keep_alive_requests: 10_000_000,
        exempt: vec!["127.0.0.1".parse().expect("address")],
        ..Settings::default()
    };

    // 1. The passport path (hello service) against serve-net alone.
    let core = Arc::new(
        Core::builder()
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core"),
    );
    let door =
        Door::open(core, &settings, UrgentLine::detached(), WebServices::new()).expect("gateway");
    let bare_time = Arc::new(ServerTime::default());
    let bare = Server::builder()
        .observer(TimeObserver::new(bare_time.clone()))
        .listener(ListenerSpec::tcp("bare", "127.0.0.1:0"))
        .workers(Workers::reactor(WORKERS))
        .keep_alive(KeepAlive::new().max_requests(10_000_000))
        .serve(serve_net::handler(|_req, reply| {
            reply.html(200, PAGE);
        }))
        .expect("bare serve-net");

    // 2. The web path (core, then web-net) against web-net alone on serve-net.
    let web_core = Arc::new(
        Core::builder()
            .external("web")
            .profile("site", "web", |_| {})
            .load()
            .expect("core"),
    );
    let site = web_net::App::with_gate(WaspGate::new(web_core.access().clone()))
        .development()
        .route(bench_route())
        .build()
        .expect("site");
    let mut web = WebServices::new();
    web.attach(web_core.service_tag("web").expect("tag"), site);
    let web_door =
        Door::open(web_core, &settings, UrgentLine::detached(), web).expect("web gateway");
    let alone_time = Arc::new(ServerTime::default());
    let alone_app = web_net::App::builder()
        .development()
        .route(bench_route())
        .build()
        .expect("web-net alone");
    let alone = Server::builder()
        .observer(TimeObserver::new(alone_time.clone()))
        .listener(ListenerSpec::tcp("alone", "127.0.0.1:0"))
        .workers(Workers::reactor(WORKERS))
        .keep_alive(KeepAlive::new().max_requests(10_000_000))
        .serve(alone_app)
        .expect("web-net on serve-net");

    println!(
        "request path over loopback, {WORKERS} reactor workers, keep-alive, 1 request in flight per connection"
    );
    println!();
    compare(
        "passport path: hello service",
        &Under {
            name: "serve-net alone",
            addr: bare.local_addr().expect("a"),
            time: &bare_time,
        },
        &Under {
            name: "gateway + hello",
            addr: door.local_addr().expect("a"),
            time: door.server_time(),
        },
        &[(1, 20_000), (8, 10_000), (32, 4_000)],
    );
    compare(
        "web path: web-net",
        &Under {
            name: "web-net alone",
            addr: alone.local_addr().expect("a"),
            time: &alone_time,
        },
        &Under {
            name: "gateway + web-net",
            addr: web_door.local_addr().expect("a"),
            time: web_door.server_time(),
        },
        &[(1, 20_000), (8, 10_000)],
    );

    for (name, d) in [("hello", &door), ("web", &web_door)] {
        let stats = d.pool().stats();
        println!(
            "{name}: passports after the run: {} of {} in use, {} refused; request tickets held: {}",
            stats.in_use,
            stats.capacity,
            stats.refused,
            d.tickets_held()
        );
    }
    let _ = door.close(Duration::from_secs(2));
    let _ = web_door.close(Duration::from_secs(2));
    let _ = bare.drain(Duration::from_secs(2));
    let _ = alone.drain(Duration::from_secs(2));
}
