//! Log rules end to end: the client in a line is the address the door
//! judges (never a spoofed `X-Forwarded-For`), the query only with its
//! switch, the headers a rule asks for, and the rate cap.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_io::{AccessLog, Door, Extras, IngressMode, LogRules, Settings, WebServices};
use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

const SPOOFED: &str = "198.51.100.7";

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("gateway-log-rules-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    TempDir(dir)
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn open(ingress: IngressMode, rules: &str) -> (Door, SocketAddr) {
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
        ingress,
        ..Settings::default()
    };
    let rules = LogRules::from_config(&Config::from_text(rules).expect("toml")).expect("rules");
    let access = AccessLog::with_writer_and_rules(|_| {}, rules).expect("log");
    let door = Door::open_with(
        core,
        &settings,
        UrgentLine::detached(),
        WebServices::new(),
        Extras {
            access: Some(access),
            ..Extras::default()
        },
    )
    .expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

/// The status of `GET target` with these extra fields.
fn status(addr: SocketAddr, target: &str, fields: &str) -> u16 {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let _ = s.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n{fields}Connection: close\r\n\r\n")
            .as_bytes(),
    );
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf)
        .get(9..12)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// The file's lines once it has at least `n` (the writer runs on its own
/// thread).
fn lines(path: &Path, n: usize) -> Vec<String> {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let got: Vec<String> = text.lines().map(str::to_owned).collect();
        if got.len() >= n || Instant::now() > until {
            return got;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_rule_writes_the_door_s_client_and_only_what_it_asks_for() {
    let dir = temp_dir("direct");
    let file = dir.0.join("hits.log");
    let rated = dir.0.join("rated.log");
    let rules = format!(
        "[log_rule.hits]\ncodes = [\"2xx\", \"404\"]\nfields = [\"client\", \"path\", \"status\", \"query\", \"user_agent\", \"referrer\"]\ndestination = \"file:{}\"\nrate = 0\n\n\
         [log_rule.rated]\ncodes = [\"2xx\"]\nfields = [\"path\"]\ninclude_query = true\ndestination = \"file:{}\"\nrate = 1\n",
        slash(&file),
        slash(&rated)
    );
    let (door, addr) = open(IngressMode::Direct, &rules);
    // A spoofed forwarded address from a peer that is no proxy at all.
    assert_eq!(
        status(
            addr,
            "/?token=secret",
            &format!(
                "X-Forwarded-For: {SPOOFED}\r\nUser-Agent: probe/1\r\nReferer: https://example.com/from\r\n"
            ),
        ),
        200
    );
    assert_eq!(status(addr, "/?token=again", ""), 200);
    assert_eq!(status(addr, "/?token=third", ""), 200);
    let got = lines(&file, 3);
    assert_eq!(got.len(), 3, "{got:?}");
    let first = &got[0];
    assert!(first.contains("\"client\":\"127.0.0.1\""), "{first}");
    assert!(
        !first.contains(SPOOFED),
        "never the spoofed header: {first}"
    );
    assert!(first.contains("\"user_agent\":\"probe/1\""), "{first}");
    assert!(
        first.contains("\"referrer\":\"https://example.com/from\""),
        "{first}"
    );
    assert!(first.contains("\"rule\":\"hits\""), "{first}");
    assert!(
        !first.contains("secret"),
        "no query without include_query: {first}"
    );

    // The rated rule: the query with its switch, one line a second.
    let r = lines(&rated, 1);
    std::thread::sleep(Duration::from_millis(300));
    let r2 = lines(&rated, 1);
    assert_eq!(
        r2.len(),
        1,
        "the rest of the second is over the cap: {r2:?}"
    );
    assert!(r[0].contains("\"query\":\"token=secret\""), "{}", r[0]);
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn behind_a_proxy_only_a_trusted_one_names_the_client() {
    let dir = temp_dir("proxy");
    let file = dir.0.join("hits.log");
    let rules = format!(
        "[log_rule.hits]\ncodes = [\"1xx\", \"2xx\", \"3xx\", \"4xx\", \"5xx\"]\nfields = [\"client\", \"status\"]\ndestination = \"file:{}\"\nrate = 0\n",
        slash(&file)
    );
    // The loopback peer is the trusted proxy: its header names the client.
    let (door, addr) = open(
        IngressMode::Proxy {
            trusted: vec!["127.0.0.1".into()],
            forwarded_proto: true,
        },
        &rules,
    );
    assert_eq!(status(addr, "/", "X-Forwarded-For: 203.0.113.10\r\n"), 200);
    let got = lines(&file, 1);
    assert!(got[0].contains("\"client\":\"203.0.113.10\""), "{got:?}");
    let _ = door.close(Duration::from_secs(2));

    // Another proxy is trusted, not this peer: its header is never believed.
    let file2 = dir.0.join("untrusted.log");
    let rules = format!(
        "[log_rule.hits]\ncodes = [\"1xx\", \"2xx\", \"3xx\", \"4xx\", \"5xx\"]\nfields = [\"client\", \"status\"]\ndestination = \"file:{}\"\nrate = 0\n",
        slash(&file2)
    );
    let (door, addr) = open(
        IngressMode::Proxy {
            trusted: vec!["10.9.9.9".into()],
            forwarded_proto: true,
        },
        &rules,
    );
    let _ = status(addr, "/", &format!("X-Forwarded-For: {SPOOFED}\r\n"));
    std::thread::sleep(Duration::from_millis(300));
    let text = std::fs::read_to_string(&file2).unwrap_or_default();
    assert!(
        !text.contains(SPOOFED),
        "an untrusted peer's header: {text}"
    );
    let _ = door.close(Duration::from_secs(2));
}
