//! Web replies in parts (files over 1 MiB): the passport pipeline runs once
//! per request, never once per part, and nothing it decides can be written
//! into a body already on the wire (review F-3).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WaspGate, WebServices};
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{AuthOut, Authentication, Authenticator, Core, Identity, Profile, RequestView};
use web_net::{App, Assets};

/// Counts its calls; refuses (a ban) from call `refuse_from` on.
struct Gate {
    calls: Arc<AtomicUsize>,
    refuse_from: usize,
}

impl Authenticator for Gate {
    fn authenticate(
        &self,
        _request: RequestView<'_>,
        _profile: &Profile,
        out: &mut AuthOut,
    ) -> Authentication {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        out.set_cookie(b"__Host-pre=visitor-A; Path=/; Secure; HttpOnly");
        if n >= self.refuse_from {
            Authentication::Refused(wasp_core::Refusal::status(403))
        } else {
            Authentication::Identified(Identity::guest())
        }
    }
}

struct Site {
    door: Door,
    addr: SocketAddr,
    calls: Arc<AtomicUsize>,
    file: Vec<u8>,
    dir: std::path::PathBuf,
}

impl Drop for Site {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn site(name: &str, refuse_from: usize, mib: u32) -> Site {
    let calls = Arc::new(AtomicUsize::new(0));
    let core = Arc::new(
        Core::builder()
            .authenticator(Gate {
                calls: calls.clone(),
                refuse_from,
            })
            .external("web")
            .profile("site", "web", |_| {})
            .load()
            .expect("core"),
    );
    let dir = std::env::temp_dir().join(format!("gateway-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let file: Vec<u8> = (0..mib * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("big.bin"), &file).expect("file");
    let app: App<WaspGate> = App::with_gate(WaspGate::new(core.access().clone()))
        .development()
        .assets(Assets::new("/static", dir.clone()))
        .build()
        .expect("app");
    let mut web = WebServices::new();
    web.attach(core.service_tag("web").expect("tag"), app);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 8,
        drain: Duration::from_secs(2),
        ..Settings::default()
    };
    let door = Door::open(core, &settings, UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    Site {
        door,
        addr,
        calls,
        file,
        dir,
    }
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = b.windows(2).position(|w| w == b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&b[..line_end]).ok()?.trim(), 16).ok()?;
        b = &b[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..size)?);
        b = b.get(size + 2..)?;
    }
}

fn download(addr: SocketAddr) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(20)))
        .expect("timeout");
    s.write_all(b"GET /static/big.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("head") + 4;
    (
        String::from_utf8_lossy(&buf[..end]).into_owned(),
        buf[end..].to_vec(),
    )
}

fn settle(door: &Door) {
    let until = Instant::now() + Duration::from_secs(5);
    while (door.pool().stats().in_use != 0 || door.tickets_held() != 0) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_reply_in_parts_is_authenticated_once() {
    let s = site("once", usize::MAX, 3);
    let (head, raw) = download(s.addr);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        dechunk(&raw).as_deref(),
        Some(&s.file[..]),
        "the file arrives whole"
    );
    assert_eq!(s.calls.load(Ordering::SeqCst), 1, "one authentication");
    assert_eq!(
        head.to_ascii_lowercase().matches("set-cookie").count(),
        1,
        "{head}"
    );
    settle(&s.door);
    let stats = s.door.pool().stats();
    assert_eq!((stats.in_use, stats.lost), (0, 0), "{stats:?}");
    assert_eq!(s.door.tickets_held(), 0);
}

#[test]
fn a_gate_that_would_refuse_later_never_writes_into_the_file() {
    // The reviewer's case: an authenticator that refuses from its second
    // call. Later parts never reach it, so the file is whole.
    let s = site("mid", 1, 3);
    let (head, raw) = download(s.addr);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(!raw.windows(14).any(|w| w == b"403 Forbidden\n"));
    assert_eq!(dechunk(&raw).as_deref(), Some(&s.file[..]));
    assert_eq!(s.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn a_client_that_leaves_mid_file_gives_its_passport_back() {
    let s = site("leave", usize::MAX, 8);
    let mut c = TcpStream::connect(s.addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    c.write_all(b"GET /static/big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write");
    let mut part = vec![0u8; 256 * 1024];
    let mut got = 0;
    while got < part.len() {
        match c.read(&mut part[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    drop(c);
    settle(&s.door);
    let stats = s.door.pool().stats();
    assert_eq!((stats.in_use, stats.lost), (0, 0), "{stats:?}");
    assert_eq!(s.door.tickets_held(), 0, "the parked part was released");
    // The worker still serves.
    let (head, raw) = download(s.addr);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(dechunk(&raw).as_deref(), Some(&s.file[..]));
}

#[test]
fn a_revocation_mid_file_cuts_the_connection() {
    let s = site("revoke", usize::MAX, 48);
    let mut c = TcpStream::connect(s.addr).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    c.write_all(b"GET /static/big.bin HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write");
    let mut buf = vec![0u8; 256 * 1024];
    let mut got = 0;
    while got < buf.len() {
        match c.read(&mut buf[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    s.door
        .bouncer()
        .revoke(
            "127.0.0.1".parse::<std::net::IpAddr>().expect("ip"),
            bouncer_io::Reason::ADMIN,
        )
        .expect("revoke");
    buf.truncate(got);
    let _ = c.read_to_end(&mut buf);
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("head") + 4;
    let raw = &buf[end..];
    assert!(!raw.ends_with(b"0\r\n\r\n"), "never a clean end");
    assert!(!raw.windows(14).any(|w| w == b"403 Forbidden\n"));
    assert!(raw.len() < s.file.len());
    settle(&s.door);
    assert_eq!(s.door.pool().stats().in_use, 0);
}
