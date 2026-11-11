//! The binary's own wiring, opened in this process with stage timing on, and
//! driven like `examples/hit.rs` drives the binary: one keep-alive
//! connection, one request at a time. Prints where the server time goes.
//!
//! ```text
//! cargo bench -p wasp --bench stages -- [workers] [requests] [reactor|blocking] [path]
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use gateway_io::{Door, Extras, Settings, WebServices};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

fn read_reply(s: &mut TcpStream, buf: &mut Vec<u8>) -> bool {
    buf.clear();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let len = std::str::from_utf8(&buf[..end])
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

fn main() {
    let mut args = std::env::args().skip(1).filter(|a| !a.starts_with("--"));
    let workers: u16 = args.next().and_then(|a| a.parse().ok()).unwrap_or(4);
    let n: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(20_000);
    let driver = match args.next().as_deref() {
        Some("blocking") => gateway_io::Driver::Blocking,
        _ => gateway_io::Driver::Reactor,
    };
    let path = args.next().unwrap_or_else(|| "/posts/the-passport".into());
    let theme = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../themes/default")
        .display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let conf = format!(
        "[gateway]\nstage_timing = true\n\n[site]\ntheme = \"{theme}\"\ntheme_poll = \"0s\"\n"
    );
    let wiring = wasp::wire(&Config::from_text(&conf).expect("config")).expect("wiring");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("tag"), wiring.site);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers,
        driver,
        keep_alive_requests: 10_000_000,
        exempt: vec!["127.0.0.1".parse().expect("ip")],
        ..Settings::default()
    };
    let door = Door::open_with(
        wiring.core,
        &settings,
        UrgentLine::detached(),
        web,
        Extras {
            stages: Some(wiring.stages.clone()),
            ..Extras::default()
        },
    )
    .expect("door");
    let addr = door.local_addr().expect("addr");

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nUser-Agent: hit\r\nAccept: text/html\r\nAccept-Encoding: identity\r\n\r\n"
    );
    let connect = || {
        let s = TcpStream::connect(addr).expect("connect");
        s.set_nodelay(true).expect("nodelay");
        s.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        s
    };
    let mut s = connect();
    let mut buf = Vec::with_capacity(16 * 1024);
    let mut reconnects = 0_u32;
    // One request; a connection the server ended is reopened, as a browser does.
    let mut one = |s: &mut TcpStream, buf: &mut Vec<u8>| {
        if s.write_all(request.as_bytes()).is_ok() && read_reply(s, buf) {
            return;
        }
        reconnects += 1;
        *s = connect();
        s.write_all(request.as_bytes()).expect("write");
        assert!(read_reply(s, buf), "a 200 page after reconnecting");
    };
    for _ in 0..1_000 {
        one(&mut s, &mut buf);
    }
    wiring.stages.reset();
    let mut lat = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        one(&mut s, &mut buf);
        lat.push(t.elapsed());
    }
    drop(s);
    std::thread::sleep(Duration::from_millis(200));
    lat.sort();
    let us = |d: Duration| d.as_nanos() as f64 / 1000.0;
    println!(
        "in process, {driver:?} driver, {workers} workers, GET {path}: client p50 {:.1} us, min {:.1} us, {reconnects} reconnects",
        us(lat[lat.len() / 2]),
        us(lat[0])
    );
    print!("{}", wiring.stages.table());
    let _ = door.close(Duration::from_secs(1));
}
