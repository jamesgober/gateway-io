//! The site signing in and out through nex-db (`auth.store = "nex"`):
//! web-net's CSRF engine on every form, sessions that survive a restart.

#![cfg(feature = "store-nex")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::nex::{MEMBER_ROLE, NexAuth};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

const EMAIL: &str = "ann@example.com";
const PASSWORD: &str = "correct horse battery staple";

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("wasp-nexsite-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    TempDir(dir)
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn config(data: &Path) -> Config {
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[auth]\nstore = \"nex\"\n\n[nex]\npath = \"{}\"\n",
        slash(&theme),
        slash(&data.join("nex"))
    ))
    .expect("config")
}

/// Opens the site; the account exists once.
fn open(conf: &Config) -> (Door, SocketAddr) {
    let t = Instant::now();
    let wiring = loop {
        match wasp::wire(conf) {
            Ok(w) => break w,
            // A closed door's threads let go of the database a moment later.
            Err(e) if e.contains("another instance") && t.elapsed() < Duration::from_secs(5) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("wiring: {e}"),
        }
    };
    NexAuth::new(wiring.nex.clone().expect("nex-db"))
        .ensure_account(EMAIL, PASSWORD, &[MEMBER_ROLE])
        .expect("account");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        ..Settings::default()
    };
    let door = Door::open(wiring.core, &settings, UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

#[derive(Debug)]
struct Got {
    status: u16,
    fields: Vec<(String, String)>,
    body: String,
}

impl Got {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `name=value` pair of the last cookie set under `name`.
    fn cookie(&self, name: &str) -> Option<String> {
        self.fields
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.as_str())
            .rev()
            .find(|c| c.starts_with(&format!("{name}=")))
            .map(|c| c.split(';').next().unwrap_or_default().to_owned())
    }

    fn csrf(&self) -> String {
        let at = self
            .body
            .find("name=\"csrf_token\" value=\"")
            .expect("csrf field")
            + 25;
        let rest = &self.body[at..];
        rest[..rest.find('"').expect("end")].to_owned()
    }
}

fn send(addr: SocketAddr, request: &str) -> Got {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    s.write_all(request.as_bytes()).expect("write");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.get(9..12))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let fields = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Got {
        status,
        fields,
        body: body.to_owned(),
    }
}

fn get(addr: SocketAddr, target: &str, cookies: &[&str]) -> Got {
    let c = if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    };
    send(
        addr,
        &format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n{c}Connection: close\r\n\r\n"),
    )
}

fn post(addr: SocketAddr, target: &str, cookies: &[&str], site: &str, body: &str) -> Got {
    let c = if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    };
    send(
        addr,
        &format!(
            "POST {target} HTTP/1.1\r\nHost: localhost\r\n{c}Sec-Fetch-Site: {site}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn sign_in_body(email: &str, password: &str, csrf: &str) -> String {
    format!(
        "email={}&password={}&csrf_token={}",
        encode(email),
        encode(password),
        encode(csrf)
    )
}

/// The sign-in form for a fresh visitor: its pre-session cookie and token.
fn form(addr: SocketAddr) -> (String, String) {
    let first = get(addr, "/sign-in", &[]);
    assert_eq!(first.status, 303, "{first:?}");
    let pre = first.cookie("__Host-nexpre").expect("pre-session cookie");
    let page = get(addr, "/sign-in", &[&pre]);
    assert_eq!(page.status, 200, "{page:?}");
    (pre, page.csrf())
}

fn sign_in(addr: SocketAddr) -> String {
    let (pre, csrf) = form(addr);
    let done = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, &csrf),
    );
    assert_eq!(done.status, 303, "{done:?}");
    done.cookie("__Host-nex").expect("session")
}

#[test]
fn sign_in_account_and_sign_out_through_nex_db() {
    let data = temp_dir("flow");
    let conf = config(&data.0);
    let (door, addr) = open(&conf);

    let account = get(addr, "/account", &[]);
    assert_eq!(account.status, 303);
    assert_eq!(account.field("location"), Some("/sign-in?next=/account"));

    // Refused: a wrong password (401, the form again), no token (403).
    let (pre, csrf) = form(addr);
    let wrong = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, "not it", &csrf),
    );
    assert_eq!(wrong.status, 401, "{wrong:?}");
    assert!(wrong.cookie("__Host-nex").is_none());
    let bare = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &format!("email={}&password={}", encode(EMAIL), encode(PASSWORD)),
    );
    assert_eq!(bare.status, 403, "no CSRF token: {bare:?}");

    // Signing in: 303 back, the session cookie set, the pre-session cleared.
    let done = post(
        addr,
        "/sign-in?next=/account",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, &csrf),
    );
    assert_eq!(done.status, 303, "{done:?}");
    assert_eq!(done.field("location"), Some("/account"));
    let sid = done.cookie("__Host-nex").expect("session");
    assert_eq!(
        done.cookie("__Host-nexpre").as_deref(),
        Some("__Host-nexpre=")
    );

    let page = get(addr, "/account", &[&sid]);
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains("Signed in as"), "{}", page.body);
    let csrf = page.csrf();

    // Sign-out from another site is refused; the session stays.
    let forged = post(
        addr,
        "/sign-out",
        &[&sid],
        "cross-site",
        &format!("csrf_token={}", encode(&csrf)),
    );
    assert_eq!(forged.status, 403, "{forged:?}");
    assert_eq!(get(addr, "/account", &[&sid]).status, 200);

    let out = post(
        addr,
        "/sign-out",
        &[&sid],
        "same-origin",
        &format!("csrf_token={}", encode(&csrf)),
    );
    assert_eq!(out.status, 303, "{out:?}");
    assert_eq!(out.cookie("__Host-nex").as_deref(), Some("__Host-nex="));
    let after = get(addr, "/account", &[&sid]);
    assert_eq!(after.status, 303, "the old cookie no longer signs in");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_nex_db_session_survives_a_restart() {
    let data = temp_dir("restart");
    let conf = config(&data.0);
    let (door, addr) = open(&conf);
    let sid = sign_in(addr);
    assert_eq!(get(addr, "/account", &[&sid]).status, 200);
    let _ = door.close(Duration::from_secs(2));

    let (door, addr) = open(&conf);
    let page = get(addr, "/account", &[&sid]);
    assert_eq!(
        page.status, 200,
        "still signed in after a restart: {page:?}"
    );
    let _ = door.close(Duration::from_secs(2));
}
