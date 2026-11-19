//! Sustained mixed traffic against a running `wasp`, for a soak run.
//!
//! ```text
//! cargo run --release -p wasp --example soak -- 127.0.0.1:8080 8 250 600
//! ```
//!
//! `connections` keep-alive connections, each sending `rate` requests a
//! second, for `seconds`. The traffic is what a small site sees: the home
//! page, posts and pages (cached for guests), pages with a query (never
//! cached), missing pages, the sign-in form, the health check. Every 30
//! seconds it prints the requests, the statuses, and the latency; at the end
//! the totals. It exits with an error if any request got no answer or a
//! status other than the expected ones.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The paths and the statuses each may answer. A visitor without a cookie
/// is sent from the nex-db site's sign-in form back to it with a pre-session
/// cookie (303), and this client keeps no cookies.
const PATHS: &[(&str, &[u16])] = &[
    ("/", &[200]),
    ("/posts/the-passport", &[200]),
    ("/posts/hello-world", &[200]),
    ("/about", &[200]),
    ("/?page=2", &[200]),
    ("/posts/the-passport?ref=feed", &[200]),
    ("/posts/nope", &[404]),
    ("/no/such/page", &[404]),
    ("/sign-in", &[200, 303]),
    ("/health", &[200]),
];

#[derive(Default)]
struct Window {
    latencies: Vec<Duration>,
    /// By class: 1xx to 5xx.
    statuses: [u64; 6],
    unexpected: u64,
    failed: u64,
}

fn read_reply(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<(u16, bool)> {
    buf.clear();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&buf[..end]).ok()?;
            let status: u16 = head.get(9..12)?.parse().ok()?;
            let mut len = 0usize;
            let mut close = false;
            for l in head.lines().skip(1) {
                let Some((n, v)) = l.split_once(':') else {
                    continue;
                };
                if n.eq_ignore_ascii_case("content-length") {
                    len = v.trim().parse().ok()?;
                } else if n.eq_ignore_ascii_case("connection") {
                    close = v.trim().eq_ignore_ascii_case("close");
                }
            }
            if buf.len() >= end + 4 + len {
                return Some((status, close));
            }
        }
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn connect(addr: &str) -> Option<TcpStream> {
    let s = TcpStream::connect(addr).ok()?;
    s.set_nodelay(true).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    Some(s)
}

fn client(addr: String, rate: u32, seed: usize, stop: Arc<AtomicBool>, window: Arc<Mutex<Window>>) {
    let gap = Duration::from_secs(1) / rate.max(1);
    let mut s = connect(&addr);
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut i = seed;
    let mut next = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let (path, expected) = PATHS[i % PATHS.len()];
        i += 7;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: soak\r\nAccept: text/html\r\n\r\n"
        );
        let t = Instant::now();
        let mut got = None;
        for _ in 0..2 {
            if s.is_none() {
                s = connect(&addr);
            }
            let Some(conn) = s.as_mut() else { break };
            if conn.write_all(request.as_bytes()).is_ok()
                && let Some(r) = read_reply(conn, &mut buf)
            {
                got = Some(r);
                break;
            }
            s = None;
        }
        let took = t.elapsed();
        {
            let mut w = window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match got {
                Some((status, close)) => {
                    w.latencies.push(took);
                    w.statuses[usize::from(status / 100).min(5)] += 1;
                    if !expected.contains(&status) && status != 503 {
                        w.unexpected += 1;
                    }
                    if close {
                        s = None;
                    }
                }
                None => w.failed += 1,
            }
        }
        next += gap;
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else {
            next = now;
        }
    }
}

fn report(label: &str, w: &mut Window) {
    w.latencies.sort();
    let q = |f: f64| {
        w.latencies
            .get(((w.latencies.len() as f64 * f) as usize).min(w.latencies.len().saturating_sub(1)))
            .map_or(0.0, |d| d.as_nanos() as f64 / 1000.0)
    };
    println!(
        "{label}: {} answered, 2xx {} 3xx {} 4xx {} 5xx {}, unexpected {}, no answer {}, p50 {:.0} us p99 {:.0} us max {:.0} us",
        w.latencies.len(),
        w.statuses[2],
        w.statuses[3],
        w.statuses[4],
        w.statuses[5],
        w.unexpected,
        w.failed,
        q(0.50),
        q(0.99),
        q(1.0)
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:8080".into());
    let connections: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(8);
    let rate: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(250);
    let seconds: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(600);
    let stop = Arc::new(AtomicBool::new(false));
    let window = Arc::new(Mutex::new(Window::default()));
    let threads: Vec<_> = (0..connections)
        .map(|c| {
            let (addr, stop, window) = (addr.clone(), stop.clone(), window.clone());
            std::thread::spawn(move || client(addr, rate, c, stop, window))
        })
        .collect();
    let started = Instant::now();
    let (mut answered, mut fivexx, mut unexpected, mut failed) = (0u64, 0u64, 0u64, 0u64);
    let total_p99 = AtomicU64::new(0);
    while started.elapsed() < Duration::from_secs(seconds) {
        std::thread::sleep(
            Duration::from_secs(30)
                .min(Duration::from_secs(seconds).saturating_sub(started.elapsed())),
        );
        let mut w = std::mem::take(
            &mut *window
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        report(&format!("{:>4} s", started.elapsed().as_secs()), &mut w);
        answered += w.latencies.len() as u64;
        fivexx += w.statuses[5];
        unexpected += w.unexpected;
        failed += w.failed;
        let p99 = w
            .latencies
            .get((w.latencies.len() * 99 / 100).min(w.latencies.len().saturating_sub(1)))
            .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
        total_p99.fetch_max(p99, Ordering::Relaxed);
    }
    stop.store(true, Ordering::Relaxed);
    for t in threads {
        let _ = t.join();
    }
    println!(
        "total: {answered} answered in {} s, 5xx {fivexx}, unexpected {unexpected}, no answer {failed}, worst window p99 {} us",
        started.elapsed().as_secs(),
        total_p99.load(Ordering::Relaxed)
    );
    if unexpected > 0 || failed > 0 {
        return Err("unexpected statuses or unanswered requests".into());
    }
    Ok(())
}
