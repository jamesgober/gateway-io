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

use gateway_io::{Door, ServerTime, Settings, TimeObserver};
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

fn main() {
    let core = Arc::new(
        Core::builder()
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core"),
    );
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: WORKERS,
        passports: 256,
        keep_alive_requests: 10_000_000,
        exempt: vec!["127.0.0.1".parse().expect("address")],
        ..Settings::default()
    };
    let door = Door::open(core, &settings, UrgentLine::detached()).expect("gateway");
    let wasp = door.local_addr().expect("address");

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
    let bare_addr = bare.local_addr().expect("address");

    println!(
        "request path over loopback, {WORKERS} reactor workers, keep-alive, 1 request in flight per connection"
    );
    println!();
    println!("| server | connections | requests/s | p50 us | p99 us | p99.9 us | failed |");
    println!("|---|---|---|---|---|---|---|");
    let mut server_rows = Vec::new();
    for &(conns, per) in &[(1usize, 20_000usize), (8, 10_000), (32, 4_000)] {
        // Alternate, and keep the better of two runs each, so neither server
        // gets the quieter moment of a shared machine.
        let mut best_bare: Option<Run> = None;
        let mut best_wasp: Option<Run> = None;
        bare_time.reset();
        door.server_time().reset();
        for _ in 0..2 {
            let b = drive(bare_addr, conns, per);
            if best_bare.as_ref().is_none_or(|x| b.p50 < x.p50) {
                best_bare = Some(b);
            }
            let w = drive(wasp, conns, per);
            if best_wasp.as_ref().is_none_or(|x| w.p50 < x.p50) {
                best_wasp = Some(w);
            }
        }
        if let (Some(b), Some(w)) = (best_bare, best_wasp) {
            print("serve-net alone", conns, &b);
            print("gateway (WASP path)", conns, &w);
            println!(
                "| difference at p50 | {conns} | | {:+.1} | | | |",
                (w.p50.as_nanos() as f64 - b.p50.as_nanos() as f64) / 1000.0
            );
        }
        server_rows.push((conns, bare_time.summary(), door.server_time().summary()));
    }
    println!();
    println!(
        "server time per request (head complete to reply handed to net-io), measured inside each server:"
    );
    println!();
    println!(
        "| connections | serve-net alone mean ns | gateway mean ns | added by the WASP path, mean ns | gateway p50 below | gateway p99 below |"
    );
    println!("|---|---|---|---|---|---|");
    for (conns, b, w) in server_rows {
        println!(
            "| {conns} | {} | {} | {:+} | {:?} | {:?} |",
            b.mean.as_nanos(),
            w.mean.as_nanos(),
            w.mean.as_nanos() as i128 - b.mean.as_nanos() as i128,
            w.p50,
            w.p99
        );
    }
    let stats = door.pool().stats();
    println!();
    println!(
        "passports after the run: {} of {} in use, {} refused",
        stats.in_use, stats.capacity, stats.refused
    );
    let _ = door.close(Duration::from_secs(2));
    let _ = bare.drain(Duration::from_secs(2));
}
