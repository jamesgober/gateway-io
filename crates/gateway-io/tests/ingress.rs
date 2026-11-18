//! Behind a reverse proxy the gateway sees each visitor, not the proxy: the
//! client named by a trusted proxy's `X-Forwarded-For` is the one the door
//! bans and charges (review F-14).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use gateway_io::{Door, IngressMode, Settings, WebServices};
use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

const BANNED: &str = "203.0.113.9";

fn open(ingress: IngressMode) -> (Door, SocketAddr) {
    let core = Arc::new(
        Core::builder()
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core"),
    );
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 8,
        ban: vec![BANNED.parse().expect("ip")],
        ingress,
        ..Settings::default()
    };
    let door =
        Door::open(core, &settings, UrgentLine::detached(), WebServices::new()).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

/// The status of `GET /` with these extra fields; 0 when the connection
/// closed without one.
fn status(addr: SocketAddr, fields: &str) -> u16 {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let _ = s.write_all(
        format!("GET / HTTP/1.1\r\nHost: localhost\r\n{fields}Connection: close\r\n\r\n")
            .as_bytes(),
    );
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf)
        .get(9..12)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[test]
fn behind_a_proxy_the_door_judges_each_visitor() {
    let (door, addr) = open(IngressMode::Proxy {
        trusted: vec!["127.0.0.1".into()],
        forwarded_proto: true,
    });
    assert_eq!(
        status(addr, "X-Forwarded-For: 203.0.113.10\r\n"),
        200,
        "a visitor"
    );
    let banned = status(addr, &format!("X-Forwarded-For: {BANNED}\r\n"));
    assert_ne!(banned, 200, "the banned visitor, behind the same proxy");
    assert_eq!(
        status(addr, "X-Forwarded-For: 203.0.113.11\r\n"),
        200,
        "the proxy itself is never banned for one visitor"
    );
    assert_ne!(
        status(addr, ""),
        200,
        "a trusted proxy must name the client"
    );
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn direct_ingress_ignores_forwarded_headers() {
    let (door, addr) = open(IngressMode::Direct);
    assert_eq!(
        status(addr, &format!("X-Forwarded-For: {BANNED}\r\n")),
        200,
        "a client cannot name itself someone else"
    );
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn proxy_ingress_needs_a_trust_list() {
    let refused = |text: &str| Settings::from_config(&Config::from_text(text).expect("config"));
    assert!(refused("[gateway]\ningress = \"proxy\"\n").is_err());
    assert!(
        refused("[gateway]\ningress = \"proxy\"\ntrusted_proxies = [\"not an address\"]\n")
            .is_err()
    );
    assert!(refused("[gateway]\ningress = \"sideways\"\n").is_err());
    let ok = refused(
        "[gateway]\ningress = \"proxy\"\ntrusted_proxies = [\"127.0.0.1\", \"10.0.0.0/8\"]\n",
    )
    .expect("valid");
    assert_eq!(ok.ingress.trusted().len(), 2);
}
