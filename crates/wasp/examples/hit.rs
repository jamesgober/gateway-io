//! Measures one page, request in to page out, against a running `wasp`.
//!
//! ```text
//! cargo run --release -p wasp --example hit -- 127.0.0.1:8080 /posts/the-passport 20000
//! ```
//!
//! One keep-alive connection, one request at a time: each figure is the time
//! from writing the request to having the whole page, as a browser on the
//! same machine would see it. The first 1,000 requests warm the path and are
//! not counted.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn read_reply(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<usize> {
    buf.clear();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&buf[..end]).ok()?;
            let len: usize = head.lines().find_map(|l| {
                let (n, v) = l.split_once(':')?;
                n.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().ok())?
            })?;
            if buf.len() >= end + 4 + len {
                return head.starts_with("HTTP/1.1 200").then_some(len);
            }
        }
        let n = s.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:8080".into());
    let path = args.next().unwrap_or_else(|| "/posts/the-passport".into());
    let n: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(20_000);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: hit\r\nAccept: text/html\r\nAccept-Encoding: identity\r\n\r\n"
    );

    let connect = || -> std::io::Result<TcpStream> {
        let s = TcpStream::connect(&addr)?;
        s.set_nodelay(true)?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        Ok(s)
    };
    let mut s = connect()?;
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut page = 0;
    let mut reconnects = 0;
    // One request; when the server ended the connection (keep-alive limit),
    // reconnect once and send again, as a browser would.
    let mut one =
        |s: &mut TcpStream, buf: &mut Vec<u8>| -> Result<usize, Box<dyn std::error::Error>> {
            if s.write_all(request.as_bytes()).is_ok()
                && let Some(len) = read_reply(s, buf)
            {
                return Ok(len);
            }
            reconnects += 1;
            *s = connect()?;
            s.write_all(request.as_bytes())?;
            match read_reply(s, buf) {
                Some(len) => Ok(len),
                None => Err(format!(
                    "no 200 page: {:?}",
                    String::from_utf8_lossy(&buf[..buf.len().min(300)])
                )
                .into()),
            }
        };
    for _ in 0..1_000 {
        page = one(&mut s, &mut buf)?;
    }
    let mut lat = Vec::with_capacity(n);
    let started = Instant::now();
    for _ in 0..n {
        let t = Instant::now();
        one(&mut s, &mut buf)?;
        lat.push(t.elapsed());
    }
    let wall = started.elapsed();
    lat.sort();
    let us = |d: Duration| d.as_nanos() as f64 / 1000.0;
    let q = |f: f64| lat[((lat.len() as f64 * f) as usize).min(lat.len() - 1)];
    let mean = lat.iter().sum::<Duration>() / u32::try_from(lat.len()).unwrap_or(u32::MAX);
    println!(
        "GET {path} on {addr}: {n} requests, one keep-alive connection ({reconnects} reconnects), page {page} bytes"
    );
    println!(
        "  min {:.1} us  p50 {:.1} us  p90 {:.1} us  p99 {:.1} us  mean {:.1} us  ({:.0} pages/s)",
        us(lat[0]),
        us(q(0.50)),
        us(q(0.90)),
        us(q(0.99)),
        us(mean),
        n as f64 / wall.as_secs_f64()
    );
    Ok(())
}
