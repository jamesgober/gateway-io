//! The messenger (G-83) on the nex-db site: two members talk live, a member
//! who was away catches up, the rules hold for every frame, and the
//! conversations are kept across a restart.

#![cfg(feature = "store-nex")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::json::{self, Value};
use wasp::nex::{EDITOR_ROLE, MEMBER_ROLE, NexAuth};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;
use ws_net::{Connection, Event};

const PASSWORD: &str = "correct horse battery staple";
const ANN: &str = "ann@example.com";
const BOB: &str = "bob@example.com";
const EVE: &str = "eve@example.com";
const ED: &str = "ed@example.com";
const NOBODY: &str = "nobody@example.com";

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("wasp-chat-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    TempDir(dir)
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

/// The messenger on, with a member's page of history at two.
const CHAT_ON: &str =
    "[api]\nenabled = true\n[chat]\nenabled = true\n[chat.role.member]\npage = 2\n";

fn open(data: &Path) -> (Door, SocketAddr) {
    open_with(data, CHAT_ON)
}

fn open_with(data: &Path, more: &str) -> (Door, SocketAddr) {
    let (door, addr, _) = open_auth(data, more);
    (door, addr)
}

/// The site, and its accounts (with `NOBODY`, an account with no roles).
fn open_auth(data: &Path, more: &str) -> (Door, SocketAddr, NexAuth) {
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    let conf = Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n[auth]\nstore = \"nex\"\n[content]\nstore = \"nex\"\n[nex]\npath = \"{}\"\n{more}",
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
    let auth = NexAuth::new(wiring.nex.clone().expect("nex-db"));
    for who in [ANN, BOB, EVE] {
        auth.ensure_account(who, PASSWORD, &[MEMBER_ROLE])
            .expect("member");
    }
    auth.ensure_account(ED, PASSWORD, &[MEMBER_ROLE, EDITOR_ROLE])
        .expect("editor");
    auth.ensure_account(NOBODY, PASSWORD, &[])
        .expect("no roles");
    let revoker = wiring.revoker.clone();
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    // The gateway's own settings from the same text (`[ws]`), on a free
    // port.
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        exempt: vec![std::net::IpAddr::from([127, 0, 0, 1])],
        ..Settings::from_config(&conf).expect("gateway settings")
    };
    let door = Door::open(wiring.core, &settings, UrgentLine::detached(), web).expect("opens");
    revoker.attach_to(&door);
    let addr = door.local_addr().expect("addr");
    (door, addr, auth)
}

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

fn sign_in(addr: SocketAddr, who: &str) -> String {
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
            encode(who),
            encode(PASSWORD),
            encode(&page.csrf())
        ),
    );
    assert_eq!(done.status, 303, "{}", done.body);
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
            "label=chat&days=30&password={}{scopes}&csrf_token={}",
            encode(PASSWORD),
            encode(&page.csrf())
        ),
    );
    assert_eq!(made.status, 200, "{}", made.body);
    let at = made.body.find("class=\"key\">").expect("the key") + 12;
    let rest = &made.body[at..];
    rest[..rest.find('<').expect("end")].to_owned()
}

/// A WebSocket client that waits for a frame with a deadline.
struct Client {
    s: TcpStream,
    c: Connection,
}

impl Client {
    fn connect(addr: SocketAddr, fields: &str) -> Result<Client, u16> {
        let mut s = TcpStream::connect(addr).expect("connect");
        s.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("timeout");
        s.write_all(
            format!(
                "GET /ws/chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{fields}\r\n"
            )
            .as_bytes(),
        )
        .expect("write");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        let until = Instant::now() + Duration::from_secs(10);
        while !head.ends_with(b"\r\n\r\n") && Instant::now() < until {
            match s.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                Ok(_) => break,
                Err(_) => {}
            }
        }
        let status: u16 = String::from_utf8_lossy(&head)
            .get(9..12)
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        if status == 101 {
            Ok(Client {
                s,
                c: Connection::client(),
            })
        } else {
            Err(status)
        }
    }

    fn send(&mut self, frame: &str) {
        self.c.send_text(frame).expect("frame");
        self.flush();
    }

    fn flush(&mut self) {
        loop {
            let out = self.c.output();
            if out.is_empty() {
                return;
            }
            let n = self.s.write(out).expect("write");
            self.c.advance_output(n);
        }
    }

    /// The next text frame, within ten seconds.
    fn next(&mut self) -> Value {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let text = match self.c.poll().expect("protocol") {
                Event::Text(t) => Some(t.to_owned()),
                Event::NeedInput => None,
                Event::Close(_) => panic!("the server closed the socket"),
                _ => None,
            };
            self.flush();
            if let Some(t) = text {
                return json::parse(&t).expect("json");
            }
            assert!(Instant::now() < until, "no frame within ten seconds");
            match self.s.read(self.c.read_buf()) {
                Ok(0) => panic!("the server closed the connection"),
                Ok(n) => self.c.commit(n),
                Err(_) => {}
            }
        }
    }

    /// The next frame with this `op`, skipping others.
    fn next_op(&mut self, op: &str) -> Value {
        loop {
            let f = self.next();
            if f.get("op").and_then(Value::as_str) == Some(op) {
                return f;
            }
            assert_ne!(
                f.get("op").and_then(Value::as_str),
                Some("error"),
                "an error while waiting for {op}: {f:?}"
            );
        }
    }

    /// Sends `frame` and returns the answer (the next frame that is not a
    /// push).
    fn ask(&mut self, frame: &str) -> Value {
        self.send(frame);
        loop {
            let f = self.next();
            match f.get("op").and_then(Value::as_str) {
                Some("message" | "read" | "member" | "invited" | "removed")
                    if !frame.contains("\"op\":\"read\"") => {}
                _ => return f,
            }
        }
    }
}

fn s(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn n(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(Value::as_int).unwrap_or(-1)
}

/// A member's socket, and its account id from the catch-up frame.
fn member(addr: SocketAddr, session: &str) -> (Client, String) {
    let mut c = Client::connect(addr, &format!("Cookie: {session}\r\n")).expect("101");
    let hello = c.next_op("conversations");
    let me = s(&hello, "me");
    (c, me)
}

fn texts(history: &Value) -> Vec<String> {
    history
        .get("messages")
        .and_then(Value::as_arr)
        .unwrap_or_default()
        .iter()
        .map(|m| {
            m.get("body").and_then(Value::as_arr).unwrap_or_default()[0]
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

#[test]
fn two_members_talk_live_and_one_catches_up() {
    let data = temp_dir("talk");
    let (door, addr) = open(&data.0);
    let (ann_s, bob_s) = (sign_in(addr, ANN), sign_in(addr, BOB));
    let (mut ann, _) = member(addr, &ann_s);
    let (mut bob, bob_id) = member(addr, &bob_s);

    let opened = ann.ask(&format!(r#"{{"op":"open","with":"{bob_id}"}}"#));
    let id = s(&opened, "id");
    assert_eq!(id.len(), 32, "{opened:?}");
    let sent = ann.ask(&format!(
        r#"{{"op":"send","conversation":"{id}","nonce":"a1","body":[{{"text":"hello bob"}}]}}"#
    ));
    assert_eq!(
        (s(&sent, "op"), s(&sent, "nonce"), n(&sent, "number")),
        ("sent".into(), "a1".into(), 1)
    );
    // Live: Bob's socket gets it at once.
    let pushed = bob.next_op("message");
    let m = pushed.get("message").expect("message");
    assert_eq!(s(m, "conversation"), id);
    assert_eq!(
        texts(&Value::Obj(vec![(
            "messages".into(),
            Value::Arr(vec![m.clone()])
        )])),
        ["hello bob"]
    );

    // Bob goes away; Ann writes twice more.
    drop(bob);
    for t in ["are you there", "call me"] {
        ann.ask(&format!(
            r#"{{"op":"send","conversation":"{id}","body":[{{"text":"{t}"}}]}}"#
        ));
    }
    // Back: the catch-up frame says what is unread, and history pages back.
    let mut bob = Client::connect(addr, &format!("Cookie: {bob_s}\r\n")).expect("101");
    let hello = bob.next_op("conversations");
    let item = &hello.get("items").and_then(Value::as_arr).expect("items")[0];
    assert_eq!(
        (s(item, "id"), n(item, "last"), n(item, "unread")),
        (id.clone(), 3, 3)
    );
    let page = bob.ask(&format!(r#"{{"op":"history","conversation":"{id}"}}"#));
    assert_eq!(
        texts(&page),
        ["are you there", "call me"],
        "a page of two, newest last"
    );
    let older = bob.ask(&format!(
        r#"{{"op":"history","conversation":"{id}","before":{}}}"#,
        n(&page, "more")
    ));
    assert_eq!(texts(&older), ["hello bob"]);
    assert_eq!(older.get("more"), Some(&Value::Null));
    // Read: Ann's socket hears it.
    bob.ask(&format!(
        r#"{{"op":"read","conversation":"{id}","number":3}}"#
    ));
    let read = ann.next_op("read");
    assert_eq!(n(&read, "number"), 3);
    let _ = door.close(Duration::from_secs(2));
    drop((ann, bob));

    // Kept across a restart, in nex-db.
    let (door, addr) = open(&data.0);
    let (mut bob, _) = member(addr, &sign_in(addr, BOB));
    let page = bob.ask(&format!(r#"{{"op":"history","conversation":"{id}"}}"#));
    assert_eq!(texts(&page), ["are you there", "call me"]);
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn the_rules_hold_for_every_frame() {
    let data = temp_dir("rules");
    let (door, addr) = open(&data.0);
    let (ann_s, bob_s, eve_s, ed_s) = (
        sign_in(addr, ANN),
        sign_in(addr, BOB),
        sign_in(addr, EVE),
        sign_in(addr, ED),
    );
    let (mut ann, ann_id) = member(addr, &ann_s);
    let (mut bob, bob_id) = member(addr, &bob_s);
    let (mut eve, _) = member(addr, &eve_s);
    let (mut ed, _) = member(addr, &ed_s);
    let id = s(
        &ann.ask(&format!(r#"{{"op":"open","with":"{bob_id}"}}"#)),
        "id",
    );

    // Someone else's conversation.
    let e = eve.ask(&format!(r#"{{"op":"history","conversation":"{id}"}}"#));
    assert_eq!(s(&e, "code"), "chat.not_a_member");
    let e = eve.ask(&format!(
        r#"{{"op":"send","conversation":"{id}","body":[{{"text":"hi"}}]}}"#
    ));
    assert_eq!(s(&e, "code"), "chat.not_a_member");
    // A member's marks, and an editor's.
    let e = ann.ask(&format!(
        r#"{{"op":"send","conversation":"{id}","nonce":"x","body":[{{"text":"x","marks":["code"]}}]}}"#
    ));
    assert_eq!(
        (s(&e, "code"), s(&e, "nonce")),
        ("chat.bad_body".into(), "x".into())
    );
    let ed_bob = s(
        &ed.ask(&format!(r#"{{"op":"open","with":"{bob_id}"}}"#)),
        "id",
    );
    let ok = ed.ask(&format!(
        r#"{{"op":"send","conversation":"{ed_bob}","body":[{{"text":"x","marks":["code"]}}]}}"#
    ));
    assert_eq!(s(&ok, "op"), "sent", "{ok:?}");
    // Too long.
    let e = ann.ask(&format!(
        r#"{{"op":"send","conversation":"{id}","body":[{{"text":"{}"}}]}}"#,
        "x".repeat(4001)
    ));
    assert_eq!(s(&e, "code"), "chat.bad_body");

    // Muted: Bob's socket gets no push. The answer to Bob's own next
    // request comes first, so a push would have been read before it.
    bob.ask(&format!(
        r#"{{"op":"mute","conversation":"{id}","on":true}}"#
    ));
    ann.ask(&format!(
        r#"{{"op":"send","conversation":"{id}","body":[{{"text":"quiet"}}]}}"#
    ));
    bob.send(r#"{"op":"conversations"}"#);
    let first = bob.next();
    assert_eq!(
        s(&first, "op"),
        "conversations",
        "no push while muted: {first:?}"
    );

    // A block stops both ways, and opening again.
    bob.ask(&format!(
        r#"{{"op":"block","account":"{ann_id}","on":true}}"#
    ));
    let e = ann.ask(&format!(
        r#"{{"op":"send","conversation":"{id}","body":[{{"text":"hi"}}]}}"#
    ));
    assert_eq!(s(&e, "code"), "chat.cannot_write");
    let e = ann.ask(&format!(r#"{{"op":"open","with":"{bob_id}"}}"#));
    assert_eq!(s(&e, "code"), "chat.cannot_write");
    // Not a frame, not an op, no such account.
    assert_eq!(s(&ann.ask("hello"), "code"), "chat.bad_frame");
    assert_eq!(s(&ann.ask(r#"{"op":"dance"}"#), "code"), "chat.bad_op");
    let e = ann.ask(&format!(r#"{{"op":"open","with":"{:032x}"}}"#, 7));
    assert_eq!(s(&e, "code"), "chat.cannot_write", "the same answer");

    // Who may open the socket: no one, a key without `chat`, with it.
    assert_eq!(Client::connect(addr, "").err(), Some(401));
    let reader = make_key(addr, &ann_s, "&scope=account%3Aread");
    assert_eq!(
        Client::connect(addr, &format!("Authorization: Bearer {reader}\r\n")).err(),
        Some(403)
    );
    let chatter = make_key(addr, &ann_s, "&scope=chat");
    let mut by_key = Client::connect(addr, &format!("Authorization: Bearer {chatter}\r\n"))
        .expect("a key with the chat scope");
    assert_eq!(s(&by_key.next_op("conversations"), "me"), ann_id);
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn the_chat_page_is_for_members() {
    let data = temp_dir("page");
    let (door, addr) = open(&data.0);
    let page = call(addr, "GET", "/chat", &sign_in(addr, ANN), "");
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("data-socket=\"/ws/chat\""),
        "{}",
        page.body
    );
    assert!(page.body.contains("/theme/chat.js"), "{}", page.body);
    let script = call(addr, "GET", "/theme/chat.js", "", "");
    assert_eq!(script.status, 200);
    assert!(
        !script.body.contains("innerHTML"),
        "text only, never markup"
    );
    let guest = call(addr, "GET", "/chat", "", "");
    assert_eq!(guest.status, 303, "a guest is sent to sign in");
    let _ = door.close(Duration::from_secs(2));
}

/// The status a guest's upgrade to `path` on `host` gets: 401 where the
/// route is, 404 where it is not.
fn upgrade_status(addr: SocketAddr, host: &str, path: &str) -> u16 {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    s.write_all(
        format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    )
    .expect("write");
    let mut head = [0u8; 12];
    s.read_exact(&mut head).expect("status line");
    String::from_utf8_lossy(&head[9..12]).parse().unwrap_or(0)
}

#[test]
fn the_messenger_is_off_until_a_site_turns_it_on() {
    let data = temp_dir("off");
    let (door, addr) = open_with(&data.0, "");
    assert_eq!(upgrade_status(addr, "localhost", "/ws/chat"), 404);
    assert_eq!(call(addr, "GET", "/chat", "", "").status, 404);
    let _ = door.close(Duration::from_secs(2));

    // With host profiles each profile says, and `[chat]` is what they
    // inherit.
    let profiles = "[host.a]\nhosts = [\"localhost\"]\n[host.b]\nhosts = [\"b.test\"]\n";
    let (door, addr) = open_with(
        &data.0,
        &format!("{profiles}[host.a.chat]\nenabled = true\npath = \"/ws/talk\"\n"),
    );
    assert_eq!(upgrade_status(addr, "localhost", "/ws/talk"), 401);
    assert_eq!(upgrade_status(addr, "localhost", "/ws/chat"), 404);
    assert_eq!(upgrade_status(addr, "b.test", "/ws/talk"), 404);
    assert_eq!(upgrade_status(addr, "b.test", "/ws/chat"), 404);
    let _ = door.close(Duration::from_secs(2));
    let (door, addr) = open_with(
        &data.0,
        &format!("[chat]\nenabled = true\n{profiles}[host.b.chat]\nenabled = false\n"),
    );
    assert_eq!(upgrade_status(addr, "localhost", "/ws/chat"), 401);
    assert_eq!(upgrade_status(addr, "b.test", "/ws/chat"), 404);
    let _ = door.close(Duration::from_secs(2));

    // A key a profile's chat table does not know refuses the boot.
    let conf = Config::from_text(&format!(
        "[auth]\nstore = \"nex\"\n[nex]\npath = \"{}\"\n{profiles}[host.a.chat]\nmax_length = 10\n",
        slash(&data.0.join("nex"))
    ))
    .expect("config");
    let Err(err) = wasp::wire(&conf) else {
        panic!("a profile chat key wasp does not know is refused");
    };
    assert!(err.contains("host.a.chat.max_length"), "{err}");
}

impl Client {
    /// Sends `frame` and returns every push that came before its answer,
    /// with the answer last.
    fn frames_until_answer(&mut self, frame: &str, answer_op: &str) -> Vec<Value> {
        self.send(frame);
        let mut out = Vec::new();
        loop {
            let f = self.next();
            let done = s(&f, "op") == answer_op;
            out.push(f);
            if done {
                return out;
            }
        }
    }

    /// Whether the server ends the connection within `secs` seconds.
    fn ends_within(&mut self, secs: u64) -> bool {
        let until = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < until {
            match self.c.poll() {
                Ok(Event::Close(_)) | Err(_) => return true,
                Ok(Event::NeedInput) => match self.s.read(self.c.read_buf()) {
                    Ok(0) => return true,
                    Ok(n) => self.c.commit(n),
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => return true,
                },
                Ok(_) => {}
            }
            self.flush();
        }
        false
    }
}

fn reads(frames: &[Value]) -> usize {
    frames.iter().filter(|f| s(f, "op") == "read").count()
}

#[test]
fn a_read_reaches_the_other_member_once_and_never_across_a_block() {
    let data = temp_dir("reads");
    let (door, addr) = open(&data.0);
    let (ann_s, bob_s) = (sign_in(addr, ANN), sign_in(addr, BOB));
    let (mut ann, ann_id) = member(addr, &ann_s);
    let (mut ann2, _) = member(addr, &ann_s);
    let (mut bob, bob_id) = member(addr, &bob_s);
    let (mut bob2, _) = member(addr, &bob_s);
    let id = s(
        &ann.ask(&format!(r#"{{"op":"open","with":"{bob_id}"}}"#)),
        "id",
    );
    for t in ["one", "two"] {
        ann.ask(&format!(
            r#"{{"op":"send","conversation":"{id}","body":[{{"text":"{t}"}}]}}"#
        ));
    }
    // Every connection takes in the message pushes before what follows.
    let drain = |c: &mut Client| {
        c.frames_until_answer(r#"{"op":"conversations"}"#, "conversations");
    };
    drain(&mut ann2);
    drain(&mut bob);
    drain(&mut bob2);

    let read = format!(r#"{{"op":"read","conversation":"{id}","number":1}}"#);
    bob.ask(&read);
    // Each of Ann's connections hears it once; Bob's other one does not.
    for c in [&mut ann, &mut ann2] {
        let frames = c.frames_until_answer(r#"{"op":"conversations"}"#, "conversations");
        assert_eq!(reads(&frames), 1, "{frames:?}");
        let pushed = frames.iter().find(|f| s(f, "op") == "read").expect("read");
        assert_eq!(
            (s(pushed, "member"), n(pushed, "number")),
            (bob_id.clone(), 1)
        );
    }
    let frames = bob2.frames_until_answer(r#"{"op":"conversations"}"#, "conversations");
    assert_eq!(reads(&frames), 0, "not to the reader's own: {frames:?}");

    // The same read again moves nothing, so no one hears of it.
    for _ in 0..5 {
        assert_eq!(n(&bob.ask(&read), "number"), 1);
    }
    let frames = ann.frames_until_answer(r#"{"op":"conversations"}"#, "conversations");
    assert_eq!(reads(&frames), 0, "{frames:?}");

    // Ann blocks Bob: his reads no longer reach her.
    ann.ask(&format!(
        r#"{{"op":"block","account":"{bob_id}","on":true}}"#
    ));
    bob.ask(&format!(
        r#"{{"op":"read","conversation":"{id}","number":2}}"#
    ));
    let frames = ann.frames_until_answer(r#"{"op":"conversations"}"#, "conversations");
    assert_eq!(reads(&frames), 0, "never across a block: {frames:?}");
    let _ = ann_id;
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn only_members_can_be_written_to_and_changed_permissions_end_a_connection() {
    let data = temp_dir("perms");
    // Both rechecks every second: the session's (its roles read again) and
    // the connection's.
    let (door, addr, auth) = open_auth(
        &data.0,
        &format!("{CHAT_ON}[ws]\nrecheck = \"1s\"\n[auth.session]\nrecheck = \"1s\"\n"),
    );
    let (mut ann, _) = member(addr, &sign_in(addr, ANN));
    // An account without the member role is not one to write to: the same
    // answer as for none.
    let nobody = auth.known(NOBODY).expect("lookup").expect("there");
    let e = ann.ask(&format!(r#"{{"op":"open","with":"{:032x}"}}"#, nobody.0));
    assert_eq!(s(&e, "code"), "chat.cannot_write");
    // Ann becomes an editor: the connection that read her member limits
    // ends, and a new one has the editor's.
    auth.ensure_roles(ANN, &[EDITOR_ROLE]).expect("grant");
    assert!(ann.ends_within(10), "a change of roles ends the connection");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_taken_number_is_never_written_over() {
    use wasp::chat::{ChatStore, ConvId, Message, Span};
    let data = temp_dir("numbers");
    let (door, addr, auth) = open_auth(&data.0, CHAT_ON);
    let (mut ann, ann_id) = member(addr, &sign_in(addr, ANN));
    let (mut bob, bob_id) = member(addr, &sign_in(addr, BOB));
    let id = s(
        &ann.ask(&format!(r#"{{"op":"open","with":"{bob_id}"}}"#)),
        "id",
    );
    // Message 1 is kept, but whoever wrote it stopped before it moved the
    // conversation's last number (a crash, or another node).
    let store = auth.chat_store();
    let planted = Message {
        conversation: id.parse::<ConvId>().expect("id"),
        number: 1,
        author: u128::from_str_radix(&ann_id, 16).expect("hex"),
        at_ms: 1,
        body: vec![Span {
            text: "first".to_owned(),
            marks: 0,
            href: None,
        }],
    };
    assert!(store.append(&planted).expect("append"));
    assert!(!store.append(&planted).expect("append"), "create only");
    let sent = ann.ask(&format!(
        r#"{{"op":"send","conversation":"{id}","body":[{{"text":"second"}}]}}"#
    ));
    assert_eq!(n(&sent, "number"), 2, "{sent:?}");
    let page = bob.ask(&format!(r#"{{"op":"history","conversation":"{id}"}}"#));
    assert_eq!(texts(&page), ["first", "second"]);
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_group_reaches_its_members_live_and_outlives_a_restart() {
    let data = temp_dir("group");
    let (door, addr) = open(&data.0);
    let (ann_s, bob_s, eve_s, ed_s) = (
        sign_in(addr, ANN),
        sign_in(addr, BOB),
        sign_in(addr, EVE),
        sign_in(addr, ED),
    );
    let (mut ann, ann_id) = member(addr, &ann_s);
    let (mut bob, bob_id) = member(addr, &bob_s);
    let (mut eve, eve_id) = member(addr, &eve_s);
    let (mut ed, ed_id) = member(addr, &ed_s);
    let made = ann.ask(r#"{"op":"create","name":"Crew"}"#);
    assert_eq!(s(&made, "op"), "group", "{made:?}");
    let id = s(&made, "id");
    for (who, c) in [(&bob_id, &mut bob), (&eve_id, &mut eve), (&ed_id, &mut ed)] {
        let inv = ann.ask(&format!(
            r#"{{"op":"invite","conversation":"{id}","account":"{who}"}}"#
        ));
        assert_eq!(s(&inv, "op"), "invite", "{inv:?}");
        // The invitee hears of it at once.
        let heard = c.next_op("invited");
        assert_eq!(
            (s(&heard, "conversation"), s(&heard, "name")),
            (id.clone(), "Crew".into())
        );
        let joined = c.ask(&format!(r#"{{"op":"join","conversation":"{id}"}}"#));
        assert_eq!(s(&joined, "op"), "group", "{joined:?}");
    }
    // Eve mutes the group; Ed blocks Ann.
    eve.ask(&format!(
        r#"{{"op":"mute","conversation":"{id}","on":true}}"#
    ));
    ed.ask(&format!(
        r#"{{"op":"block","account":"{ann_id}","on":true}}"#
    ));
    let sent = ann.ask(&format!(
        r#"{{"op":"send","conversation":"{id}","body":[{{"text":"hello crew"}}]}}"#
    ));
    assert_eq!(n(&sent, "number"), 1, "{sent:?}");
    let pushed = bob.next_op("message");
    assert_eq!(
        s(pushed.get("message").expect("message"), "conversation"),
        id
    );
    for (c, why) in [(&mut eve, "muted"), (&mut ed, "blocked the author")] {
        let frames = c.frames_until_answer(r#"{"op":"invites"}"#, "invites");
        assert!(
            !frames.iter().any(|f| s(f, "op") == "message"),
            "no push to one who {why}: {frames:?}"
        );
    }
    // Kicked: Ed's socket hears it, and the group is shut to him.
    let kicked = ann.ask(&format!(
        r#"{{"op":"kick","conversation":"{id}","account":"{ed_id}"}}"#
    ));
    assert_eq!(s(&kicked, "op"), "kicked", "{kicked:?}");
    assert_eq!(s(&ed.next_op("removed"), "conversation"), id);
    let e = ed.ask(&format!(r#"{{"op":"history","conversation":"{id}"}}"#));
    assert_eq!(s(&e, "code"), "chat.not_a_member");
    let _ = door.close(Duration::from_secs(2));
    drop((ann, bob, eve, ed));

    // The record and the messages are kept in nex-db.
    let (door, addr) = open(&data.0);
    let (mut bob, _) = member(addr, &sign_in(addr, BOB));
    let g = bob.ask(&format!(r#"{{"op":"group","conversation":"{id}"}}"#));
    assert_eq!(
        (s(&g, "name"), n(&g, "count"), s(&g, "owner")),
        ("Crew".into(), 3, ann_id.clone())
    );
    let page = bob.ask(&format!(r#"{{"op":"history","conversation":"{id}"}}"#));
    assert_eq!(texts(&page), ["hello crew"]);
    // Everyone leaves: the group is gone.
    bob.ask(&format!(r#"{{"op":"leave","conversation":"{id}"}}"#));
    let (mut ann, _) = member(addr, &sign_in(addr, ANN));
    let (mut eve, _) = member(addr, &sign_in(addr, EVE));
    eve.ask(&format!(r#"{{"op":"leave","conversation":"{id}"}}"#));
    ann.ask(&format!(r#"{{"op":"leave","conversation":"{id}"}}"#));
    let e = ann.ask(&format!(r#"{{"op":"history","conversation":"{id}"}}"#));
    assert_eq!(s(&e, "code"), "chat.not_a_member");
    let _ = door.close(Duration::from_secs(2));
}
