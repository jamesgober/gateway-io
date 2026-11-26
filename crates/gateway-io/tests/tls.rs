//! TLS termination (G-90): HTTP/1.1 or HTTP/2 by ALPN, HSTS when asked
//! for, the plain listener that sends everyone to HTTPS, the certificate
//! loaded again when its files change, and a key others may read refused.

#![cfg(feature = "tls")]

mod h2c;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gateway_io::tls::TlsNote;
use gateway_io::{Door, Extras, IngressMode, Settings, TlsSettings, WebServices};
use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

const CA: &[u8] = include_bytes!("data/ca.pem");
const CERT: &[u8] = include_bytes!("data/site.pem");
const KEY: &[u8] = include_bytes!("data/site.key");
const CERT_2: &[u8] = include_bytes!("data/site-rsa.pem");
const KEY_2: &[u8] = include_bytes!("data/site-rsa.key");

fn core() -> Arc<Core> {
    Arc::new(
        Core::builder()
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core"),
    )
}

/// A folder of its own with the certificate and a key only this account
/// may read.
fn files(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("gateway-tls-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    put(&dir, CERT, KEY);
    dir
}

/// Writes a pair into `dir`: the key first, so a reload sees both.
fn put(dir: &Path, cert: &[u8], key: &[u8]) {
    wasp_core::suite::path::write_atomic_private(dir.join("site.key"), key).expect("key");
    wasp_core::suite::path::write_atomic(dir.join("site.pem"), cert).expect("cert");
}

fn tls(dir: &Path) -> TlsSettings {
    TlsSettings {
        cert: dir.join("site.pem"),
        key: dir.join("site.key"),
        reload: Duration::ZERO,
        hsts: None,
        redirect_from: None,
        redirect_hosts: Vec::new(),
    }
}

fn settings(tls: TlsSettings) -> Settings {
    Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 8,
        tls: Some(tls),
        ..Settings::default()
    }
}

/// The door, and what it told about its certificate.
fn open(tls: TlsSettings) -> (Door, Arc<Mutex<Vec<TlsNote>>>) {
    let notes = Arc::new(Mutex::new(Vec::new()));
    let told = notes.clone();
    let door = Door::open_with(
        core(),
        &settings(tls),
        UrgentLine::detached(),
        WebServices::new(),
        Extras {
            tls_notes: Some(Arc::new(move |n| told.lock().expect("notes").push(n))),
            ..Extras::default()
        },
    )
    .expect("opens");
    (door, notes)
}

/// A TLS connection that trusts the test CA and offers these protocols.
fn connect(addr: SocketAddr, alpn: &[tls_net::Alpn]) -> tls_net::TlsStream<TcpStream> {
    let client = tls_net::TlsClient::builder()
        .trust(tls_net::TrustAnchors::from_pem(CA).expect("ca"))
        .alpn(alpn)
        .build()
        .expect("client");
    let tcp = TcpStream::connect(addr).expect("connect");
    tcp.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");
    client.connect_stream("localhost", tcp).expect("handshake")
}

/// The serial of the certificate the server shows.
fn serial(addr: SocketAddr) -> Vec<u8> {
    let s = connect(addr, &[tls_net::Alpn::HTTP_1_1]);
    s.info()
        .and_then(|i| i.peer.map(|p| p.serial.clone()))
        .expect("a certificate")
}

/// An HTTP/1.1 exchange on `s`: the whole answer as text.
fn http1<S: Read + Write>(mut s: S, head: &str) -> String {
    s.write_all(head.as_bytes()).expect("write");
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A field of an HTTP/1.1 answer, by lower-case name.
fn field<'a>(answer: &'a str, name: &str) -> Option<&'a str> {
    answer.split("\r\n\r\n").next()?.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn status(answer: &str) -> u16 {
    answer.get(9..12).and_then(|t| t.parse().ok()).unwrap_or(0)
}

fn get(host: &str, target: &str) -> String {
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

#[test]
fn a_browser_gets_http2_or_http1_by_alpn() {
    let dir = files("alpn");
    let (door, notes) = open(tls(&dir));
    let addr = door.local_addr().expect("addr");

    let s = connect(addr, &[tls_net::Alpn::H2, tls_net::Alpn::HTTP_1_1]);
    let info = s.info().expect("handshake");
    assert_eq!(info.alpn, Some(&b"h2"[..]));
    assert_eq!(info.version, tls_net::Version::Tls13, "1.3 is preferred");
    let answer = h2c::request_over(s, "https", "GET", "/", &[]);
    assert_eq!(answer.status, Some(200), "{answer:?}");
    assert!(!answer.body.is_empty());

    let s = connect(addr, &[tls_net::Alpn::HTTP_1_1]);
    assert_eq!(s.info().expect("handshake").alpn, Some(&b"http/1.1"[..]));
    assert_eq!(status(&http1(s, &get("localhost", "/"))), 200);

    // Plain HTTP on the TLS port gets nothing served.
    let plain = TcpStream::connect(addr).expect("connect");
    plain
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");
    assert_ne!(status(&http1(plain, &get("localhost", "/"))), 200);

    // The load was told, with the certificate's last day.
    let told = notes.lock().expect("notes").clone();
    assert!(
        matches!(told.as_slice(), [TlsNote::Loaded { reload: false, days_left, .. }] if *days_left > 365),
        "{told:?}"
    );
    let _ = door.close(Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hsts_is_sent_only_when_asked_for() {
    let dir = files("hsts");
    let (door, _) = open(tls(&dir));
    let addr = door.local_addr().expect("addr");
    let answer = http1(
        connect(addr, &[tls_net::Alpn::HTTP_1_1]),
        &get("localhost", "/"),
    );
    assert_eq!(status(&answer), 200);
    assert_eq!(field(&answer, "strict-transport-security"), None);
    let _ = door.close(Duration::from_secs(1));

    let (door, _) = open(TlsSettings {
        hsts: Some("max-age=31536000; includeSubDomains".into()),
        ..tls(&dir)
    });
    let addr = door.local_addr().expect("addr");
    let answer = http1(
        connect(addr, &[tls_net::Alpn::HTTP_1_1]),
        &get("localhost", "/"),
    );
    assert_eq!(
        field(&answer, "strict-transport-security"),
        Some("max-age=31536000; includeSubDomains")
    );
    let answer = h2c::request_over(
        connect(addr, &[tls_net::Alpn::H2]),
        "https",
        "GET",
        "/",
        &[],
    );
    assert!(
        answer
            .fields
            .iter()
            .any(|(n, v)| n == "strict-transport-security" && v.starts_with("max-age=")),
        "{answer:?}"
    );
    let _ = door.close(Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_plain_listener_sends_everyone_to_https() {
    let dir = files("redirect");
    let (door, _) = open(TlsSettings {
        hsts: Some("max-age=600".into()),
        redirect_from: Some("127.0.0.1:0".parse().expect("addr")),
        redirect_hosts: vec!["example.test".into(), "www.example.test".into()],
        ..tls(&dir)
    });
    let https = door.local_addr().expect("addr").port();
    let plain = door.redirect_addr().expect("redirect listener");
    let ask = |host: &str, target: &str| {
        let s = TcpStream::connect(plain).expect("connect");
        s.set_read_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        http1(s, &get(host, target))
    };

    // The site's own host, path and query kept, port dropped.
    let answer = ask("WWW.Example.Test:80", "/a/b?c=d");
    assert_eq!(status(&answer), 308, "{answer}");
    assert_eq!(
        field(&answer, "location"),
        Some(format!("https://www.example.test:{https}/a/b?c=d").as_str())
    );
    assert_eq!(field(&answer, "cache-control"), Some("no-store"));
    // HSTS is never sent over plain HTTP.
    assert_eq!(field(&answer, "strict-transport-security"), None);

    // Another host goes to the site's first, never to itself.
    let answer = ask("evil.test", "/x");
    assert_eq!(status(&answer), 308);
    assert_eq!(
        field(&answer, "location"),
        Some(format!("https://example.test:{https}/x").as_str())
    );
    let _ = door.close(Duration::from_secs(1));

    // With no site hosts (a local run), only a development host.
    let (door, _) = open(TlsSettings {
        redirect_from: Some("127.0.0.1:0".parse().expect("addr")),
        ..tls(&dir)
    });
    let https = door.local_addr().expect("addr").port();
    let plain = door.redirect_addr().expect("redirect listener");
    let ask = |host: &str| {
        let s = TcpStream::connect(plain).expect("connect");
        s.set_read_timeout(Some(Duration::from_millis(200)))
            .expect("timeout");
        http1(s, &get(host, "/"))
    };
    let answer = ask("localhost:8080");
    assert_eq!(
        field(&answer, "location"),
        Some(format!("https://localhost:{https}/").as_str())
    );
    assert_eq!(status(&ask("evil.test")), 421);
    let _ = door.close(Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_changed_certificate_is_loaded_and_a_bad_one_is_not() {
    let dir = files("watch");
    let (door, notes) = open(TlsSettings {
        reload: Duration::from_secs(1),
        ..tls(&dir)
    });
    let addr = door.local_addr().expect("addr");
    let first = serial(addr);

    put(&dir, CERT_2, KEY_2);
    let until = Instant::now() + Duration::from_secs(20);
    while serial(addr) == first {
        assert!(Instant::now() < until, "the new certificate was not loaded");
        std::thread::sleep(Duration::from_millis(100));
    }
    let second = serial(addr);
    assert!(
        notes
            .lock()
            .expect("notes")
            .iter()
            .any(|n| matches!(n, TlsNote::Loaded { reload: true, .. })),
        "the reload was told"
    );

    // A broken pair: told, and the one serving stays.
    put(&dir, b"not a certificate", KEY_2);
    let until = Instant::now() + Duration::from_secs(20);
    while !notes
        .lock()
        .expect("notes")
        .iter()
        .any(|n| matches!(n, TlsNote::Refused(_)))
    {
        assert!(Instant::now() < until, "the refusal was not told");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(serial(addr), second);
    let _ = door.close(Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_configuration_reload_loads_the_files_again() {
    let dir = files("reload");
    let (door, _) = open(tls(&dir));
    let addr = door.local_addr().expect("addr");
    let first = serial(addr);
    put(&dir, CERT_2, KEY_2);
    // No checks (`tls.reload = 0s`): nothing changes until asked.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(serial(addr), first);
    assert!(matches!(
        door.reload_tls(),
        Some(TlsNote::Loaded { reload: true, .. })
    ));
    assert_ne!(serial(addr), first);
    let _ = door.close(Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Lets every account read `path`.
fn share(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    }
    #[cfg(windows)]
    {
        // Everyone (S-1-1-0) may read.
        let done = std::process::Command::new("icacls")
            .arg(path)
            .args(["/grant", "*S-1-1-0:(R)"])
            .output()
            .expect("icacls");
        assert!(done.status.success(), "{done:?}");
    }
}

#[test]
fn a_key_others_may_read_is_refused() {
    let dir = files("shared-key");
    share(&dir.join("site.key"));
    let refused = Door::open(
        core(),
        &settings(tls(&dir)),
        UrgentLine::detached(),
        WebServices::new(),
    );
    let Err(e) = refused else {
        panic!("a key others may read must refuse to open");
    };
    assert!(e.to_string().contains("tls.key"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tls_is_refused_where_it_cannot_work() {
    let dir = files("refused");
    // A proxy in front already terminates TLS.
    let behind = Settings {
        ingress: IngressMode::Proxy {
            trusted: vec!["127.0.0.1".into()],
            forwarded_proto: true,
        },
        ..settings(tls(&dir))
    };
    let refused = Door::open(core(), &behind, UrgentLine::detached(), WebServices::new());
    assert!(refused.is_err());
    // A Unix socket has no TLS here.
    let unix = Settings {
        listen: "unix:/tmp/gateway-tls.sock".into(),
        ..settings(tls(&dir))
    };
    let refused = Door::open(core(), &unix, UrgentLine::detached(), WebServices::new());
    assert!(refused.is_err());
    // A certificate that is not there.
    let missing = TlsSettings {
        cert: dir.join("missing.pem"),
        ..tls(&dir)
    };
    let refused = Door::open(
        core(),
        &settings(missing),
        UrgentLine::detached(),
        WebServices::new(),
    );
    assert!(refused.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_settings_are_read() {
    let read = |text: &str| Settings::from_config(&Config::from_text(text).expect("config"));
    assert_eq!(read("").expect("settings").tls, None);
    assert_eq!(
        read("[tls]\nenabled = false\ncert = \"a.pem\"\n")
            .expect("settings")
            .tls,
        None
    );
    let t = read(concat!(
        "[site]\nhosts = [\"Example.Test\"]\n",
        "[host.blog]\nhosts = [\"blog.example.test\", \"*.example.test\"]\n",
        "[tls]\nenabled = true\ncert = \"/etc/wasp/site.pem\"\nkey = \"/etc/wasp/site.key\"\n",
        "hsts = \"max-age=600\"\nredirect_from = \"0.0.0.0:80\"\nreload = \"0s\"\n",
    ))
    .expect("settings")
    .tls
    .expect("tls");
    assert_eq!(t.cert, PathBuf::from("/etc/wasp/site.pem"));
    assert_eq!(t.key, PathBuf::from("/etc/wasp/site.key"));
    assert_eq!(t.hsts.as_deref(), Some("max-age=600"));
    assert_eq!(t.redirect_from, Some("0.0.0.0:80".parse().expect("addr")));
    assert_eq!(t.reload, Duration::ZERO);
    assert_eq!(t.redirect_hosts, ["example.test", "blog.example.test"]);
    let defaults = read("[tls]\nenabled = true\ncert = \"a.pem\"\nkey = \"a.key\"\n")
        .expect("settings")
        .tls
        .expect("tls");
    assert_eq!(defaults.reload, Duration::from_secs(60));
    assert_eq!(defaults.hsts, None);
    assert_eq!(defaults.redirect_from, None);

    for bad in [
        "[tls]\nenabled = true\nkey = \"a.key\"\n",
        "[tls]\nenabled = true\ncert = \"a.pem\"\n",
        "[tls]\nenabled = true\ncert = \"a.pem\"\nkey = \"a.key\"\nreload = \"500ms\"\n",
        "[tls]\nenabled = true\ncert = \"a.pem\"\nkey = \"a.key\"\nhsts = \"31536000\"\n",
        "[tls]\nenabled = true\ncert = \"a.pem\"\nkey = \"a.key\"\nredirect_from = \"port 80\"\n",
        "[tls]\nenabled = true\ncert = \"a.pem\"\nkey = \"a.key\"\nsurprise = 1\n",
    ] {
        assert!(read(bad).is_err(), "{bad}");
    }
}
