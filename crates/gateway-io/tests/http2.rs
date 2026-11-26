//! Cleartext HTTP/2 (G-87): with prior knowledge, from a trusted proxy only.
//! On a direct listener the preface is not HTTP/2, whatever the client
//! wants, so no one on the open internet skips TLS.

mod h2c;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use gateway_io::{Door, H2c, IngressMode, Settings, WebServices};
use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

fn core() -> Arc<Core> {
    Arc::new(
        Core::builder()
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core"),
    )
}

fn settings(ingress: IngressMode, h2c: H2c) -> Settings {
    Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 8,
        ingress,
        h2c,
        ..Settings::default()
    }
}

fn open(ingress: IngressMode, h2c: H2c) -> (Door, SocketAddr) {
    let door = Door::open(
        core(),
        &settings(ingress, h2c),
        UrgentLine::detached(),
        WebServices::new(),
    )
    .expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

fn proxy() -> IngressMode {
    IngressMode::Proxy {
        trusted: vec!["127.0.0.1".into()],
        forwarded_proto: true,
    }
}

const VISITOR: (&str, &str) = ("x-forwarded-for", "203.0.113.10");

#[test]
fn behind_a_trusted_proxy_a_connection_may_speak_http2() {
    let (door, addr) = open(proxy(), H2c::Auto);
    let answer = h2c::request(addr, "GET", "/", &[VISITOR]);
    assert_eq!(answer.status, Some(200), "{answer:?}");
    assert!(!answer.body.is_empty(), "the page came over HTTP/2");
    // The same listener still takes HTTP/1.1.
    assert_eq!(
        h2c::http1_status(addr, "/", "X-Forwarded-For: 203.0.113.10\r\n"),
        200
    );
    // Over HTTP/2 the proxy must still name the client.
    let unnamed = h2c::request(addr, "GET", "/", &[]);
    assert_ne!(unnamed.status, Some(200), "{unnamed:?}");
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn a_direct_listener_never_speaks_cleartext_http2() {
    let (door, addr) = open(IngressMode::Direct, H2c::Auto);
    let answer = h2c::request(addr, "GET", "/", &[]);
    assert!(
        !answer.spoke_h2,
        "no HTTP/2 frame on an open port: {answer:?}"
    );
    assert_eq!(answer.status, None);
    assert_eq!(h2c::http1_status(addr, "/", ""), 200);
    let _ = door.close(Duration::from_secs(1));
    // Asking for it there is refused at the start.
    let refused = Door::open(
        core(),
        &settings(IngressMode::Direct, H2c::On),
        UrgentLine::detached(),
        WebServices::new(),
    );
    assert!(refused.is_err(), "gateway.h2c = true needs a trusted proxy");
}

#[test]
fn it_can_be_turned_off_behind_a_proxy() {
    let (door, addr) = open(proxy(), H2c::Off);
    let answer = h2c::request(addr, "GET", "/", &[VISITOR]);
    assert!(!answer.spoke_h2, "{answer:?}");
    assert_eq!(
        h2c::http1_status(addr, "/", "X-Forwarded-For: 203.0.113.10\r\n"),
        200
    );
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn the_setting_is_read() {
    let read = |text: &str| {
        Settings::from_config(&Config::from_text(text).expect("config"))
            .expect("settings")
            .h2c
    };
    assert_eq!(read(""), H2c::Auto);
    assert_eq!(read("[gateway]\nh2c = true\n"), H2c::On);
    assert_eq!(read("[gateway]\nh2c = false\n"), H2c::Off);
}
