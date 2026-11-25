//! WebSockets on the nex-db site (G-81), with the `ws-echo` route: a
//! browser opens one with its session cookie and a program with an API key,
//! by the same rules as a page, and the account events end what is open.

#![cfg(all(feature = "store-nex", feature = "ws-echo"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::nex::{MEMBER_ROLE, NexAuth};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;
use ws_net::blocking::WebSocket;
use ws_net::{Connection, Message};

const ANN: &str = "ann@example.com";
const PASSWORD: &str = "correct horse battery staple";

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("wasp-ws-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    TempDir(dir)
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

/// The site with the echo route at `/ws/echo` and the API (for keys).
fn open(data: &Path) -> (Door, SocketAddr, NexAuth) {
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    let conf = Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\nws_echo = \"/ws/echo\"\n[ws]\nrecheck = \"1h\"\n[auth]\nstore = \"nex\"\n[content]\nstore = \"nex\"\n[nex]\npath = \"{}\"\n[api]\nenabled = true\n",
        slash(&theme),
        slash(&data.join("nex")),
    ))
    .expect("config");
    let t = Instant::now();
    let wiring = loop {
        match wasp::wire(&conf) {
            Ok(w) => break w,
            Err(e)
                if e.contains("in use by another process")
                    && t.elapsed() < Duration::from_secs(5) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("wiring: {e}"),
        }
    };
    // The wiring's revoker: account events here end sockets as the site's do.
    let auth =
        NexAuth::new(wiring.nex.clone().expect("nex-db")).with_revoker(wiring.revoker.clone());
    auth.ensure_account(ANN, PASSWORD, &[MEMBER_ROLE])
        .expect("ann");
    let revoker = wiring.revoker.clone();
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        exempt: vec![std::net::IpAddr::from([127, 0, 0, 1])],
        ..Settings::default()
    };
    let door = Door::open(wiring.core, &settings, UrgentLine::detached(), web).expect("opens");
    revoker.attach_to(&door);
    let addr = door.local_addr().expect("addr");
    (door, addr, auth)
}

#[derive(Debug)]
struct Got {
    status: u16,
    fields: Vec<(String, String)>,
    body: String,
}

impl Got {
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
            .expect("csrf")
            + 25;
        let rest = &self.body[at..];
        rest[..rest.find('"').expect("end")].to_owned()
    }
}

fn call(addr: SocketAddr, method: &str, target: &str, cookie: &str, body: &str) -> Got {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let c = if cookie.is_empty() {
        String::new()
    } else {
        format!("Cookie: {cookie}\r\n")
    };
    let form = if method == "POST" {
        format!(
            "Sec-Fetch-Site: same-origin\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            body.len()
        )
    } else {
        String::new()
    };
    s.write_all(
        format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\n{c}{form}Connection: close\r\n\r\n{body}")
            .as_bytes(),
    )
    .expect("write");
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

fn sign_in(addr: SocketAddr) -> String {
    let first = call(addr, "GET", "/sign-in", "", "");
    let pre = first.cookie("__Host-nexpre").expect("pre");
    let page = call(addr, "GET", "/sign-in", &pre, "");
    let done = call(
        addr,
        "POST",
        "/sign-in",
        &pre,
        &format!(
            "email={}&password={}&csrf_token={}",
            encode(ANN),
            encode(PASSWORD),
            encode(&page.csrf())
        ),
    );
    assert_eq!(done.status, 303, "{done:?}");
    done.cookie("__Host-nex").expect("session")
}

fn make_key(addr: SocketAddr, session: &str, scopes: &str) -> String {
    let page = call(addr, "GET", "/account/security", session, "");
    let made = call(
        addr,
        "POST",
        "/account/keys",
        session,
        &format!(
            "label=ws&days=30&password={}{scopes}&csrf_token={}",
            encode(PASSWORD),
            encode(&page.csrf())
        ),
    );
    assert_eq!(made.status, 200, "{made:?}");
    let at = made.body.find("class=\"key\">").expect("the key") + 12;
    let rest = &made.body[at..];
    rest[..rest.find('<').expect("end")].to_owned()
}

/// Opens the echo route with these fields: the socket on 101, else the status.
fn connect(addr: SocketAddr, fields: &str) -> Result<WebSocket<TcpStream>, u16> {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    s.write_all(
        format!(
            "GET /ws/echo HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{fields}\r\n"
        )
        .as_bytes(),
    )
    .expect("write");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    let status: u16 = String::from_utf8_lossy(&head)
        .get(9..12)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if status == 101 {
        Ok(WebSocket::from_upgraded(s, &[], Connection::client()))
    } else {
        Err(status)
    }
}

fn echoes(ws: &mut WebSocket<TcpStream>, text: &str) -> bool {
    ws.send_text(text).is_ok() && ws.read().ok() == Some(Message::Text(text.into()))
}

/// Whether the server ends `ws` within ten seconds. The recheck runs once an
/// hour here, so only an event can.
fn ended(ws: WebSocket<TcpStream>) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut ws = ws;
        loop {
            match ws.read() {
                Ok(Message::Close(_)) | Err(_) => {
                    let _ = tx.send(());
                    return;
                }
                Ok(_) => {}
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(10)).is_ok()
}

#[test]
fn a_browser_and_a_program_open_the_echo_route_by_the_page_rules() {
    let data = temp_dir("rules");
    let (door, addr, _) = open(&data.0);
    let session = sign_in(addr);
    let reader = make_key(addr, &session, "&scope=account%3Aread");
    let bare = make_key(addr, &session, "");

    let mut by_cookie = connect(addr, &format!("Cookie: {session}\r\n")).expect("101");
    assert!(echoes(&mut by_cookie, "from the browser"));
    let mut by_key = connect(addr, &format!("Authorization: Bearer {reader}\r\n")).expect("101");
    assert!(echoes(&mut by_key, "from a program"));
    // A key without `account:read` is not a member here.
    assert_eq!(
        connect(addr, &format!("Authorization: Bearer {bare}\r\n")).err(),
        Some(403)
    );
    // No one, and a bad key.
    assert_eq!(connect(addr, "").err(), Some(401));
    assert_eq!(
        connect(addr, "Authorization: Bearer nope\r\n").err(),
        Some(401)
    );
    // A page on another site, with the browser's cookie.
    assert_eq!(
        connect(
            addr,
            &format!("Cookie: {session}\r\nOrigin: https://evil.example\r\n")
        )
        .err(),
        Some(403)
    );
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn account_events_end_what_is_open() {
    let data = temp_dir("events");
    let (door, addr, auth) = open(&data.0);
    let session = sign_in(addr);
    let one = make_key(addr, &session, "&scope=account%3Aread");
    let two = make_key(addr, &session, "&scope=account%3Aread");
    let by_one = connect(addr, &format!("Authorization: Bearer {one}\r\n")).expect("101");
    let by_two = connect(addr, &format!("Authorization: Bearer {two}\r\n")).expect("101");
    let mut by_cookie = connect(addr, &format!("Cookie: {session}\r\n")).expect("101");

    // Revoking one key ends what it opened, and nothing else.
    let page = call(addr, "GET", "/account/security", &session, "");
    let id = {
        let at = page.body.find("name=\"key\" value=\"").expect("a key") + 18;
        page.body[at..at + 32].to_owned()
    };
    let revoked = call(
        addr,
        "POST",
        "/account/keys/revoke",
        &session,
        &format!("key={id}&csrf_token={}", encode(&page.csrf())),
    );
    assert_eq!(revoked.status, 200, "{revoked:?}");
    let (mut gone, mut kept) = (by_one, by_two);
    if echoes(&mut gone, "which one?") {
        std::mem::swap(&mut gone, &mut kept);
    }
    assert!(ended(gone), "the revoked key's socket ended");
    assert!(echoes(&mut kept, "the other key"));
    assert!(echoes(&mut by_cookie, "the browser"));

    // Signing out everywhere ends the browser's socket and the keys'.
    let page = call(addr, "GET", "/account/security", &session, "");
    let out = call(
        addr,
        "POST",
        "/account/sign-out-everywhere",
        &session,
        &format!("csrf_token={}", encode(&page.csrf())),
    );
    assert_eq!(out.status, 303, "{out:?}");
    assert!(ended(by_cookie), "the browser's socket ended");
    assert!(ended(kept), "the key's socket ended");

    // Disabling the account ends a socket opened since, at once.
    let session = sign_in(addr);
    let mut again = connect(addr, &format!("Cookie: {session}\r\n")).expect("101");
    assert!(echoes(&mut again, "back"));
    let me = call(addr, "GET", "/api/v1/me", &session, "");
    let hex = {
        let at = me.body.find("\"id\":\"").expect("id") + 6;
        me.body[at..at + 32].to_owned()
    };
    let user = wasp_core::UserId(u128::from_str_radix(&hex, 16).expect("hex"));
    auth.disable(user, user).expect("disable");
    assert!(ended(again), "disabled: the socket ended");
    assert_eq!(
        connect(addr, &format!("Cookie: {session}\r\n")).err(),
        Some(401)
    );
    let _ = door.close(Duration::from_secs(2));
}
