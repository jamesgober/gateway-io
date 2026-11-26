//! WebSockets through the gateway (G-81): the caller is authenticated and
//! authorized before the switch, the origin is checked, budgets hold, and an
//! open connection ends when its caller is revoked, by an event or by the
//! recheck.

mod h2c;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gateway_io::ws::{WebSocketConn, WebSocketService, WsMessage};
use gateway_io::{
    Answered, Caller, Door, Revoker, Settings, Upgrade, WebService, WebServices, WsAccept,
    WsSettings,
};
use serve_net::{Envelope, HttpHead, HttpReply, HttpRequest, Outcome};
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{
    Access, AuthOut, Authentication, Authenticator, Core, Decision, Identity, PermSet, Profile,
    Refusal, RequestView, Rule, SessionId, Standing, UserId,
};
use ws_net::blocking::WebSocket;
use ws_net::{CloseCode, Connection, Message};

/// A caller: the account, its permissions, its standing.
type Caller3 = (u128, u64, Standing);

/// Callers by bearer token.
#[derive(Clone, Default)]
struct Tokens(Arc<Mutex<HashMap<String, Caller3>>>);

impl Tokens {
    fn set(&self, token: &str, account: u128, perms: u64) {
        self.0
            .lock()
            .expect("tokens")
            .insert(token.to_owned(), (account, perms, Standing::Good));
    }
    fn remove(&self, token: &str) {
        self.0.lock().expect("tokens").remove(token);
    }
}

impl Authenticator for Tokens {
    fn authenticate(
        &self,
        request: RequestView<'_>,
        _profile: &Profile,
        _out: &mut AuthOut,
    ) -> Authentication {
        let token = request
            .head()
            .header("authorization")
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| h.strip_prefix("Bearer "));
        let Some(token) = token else {
            return Authentication::Identified(Identity::guest());
        };
        if token == "banned" {
            return Authentication::Refused(Refusal::status(403));
        }
        match self.0.lock().expect("tokens").get(token) {
            Some((account, perms, standing)) => Authentication::Identified(
                Identity::user(UserId(*account), SessionId(account + 1000), PermSet(*perms))
                    .with_standing(*standing),
            ),
            None => Authentication::Identified(Identity::guest()),
        }
    }
}

/// Echoes every message.
struct Echo;

impl WebSocketService for Echo {
    fn message(&self, _env: &Envelope, message: WsMessage<'_>, conn: &mut WebSocketConn<'_>) {
        let _ = match message {
            WsMessage::Text(t) => conn.send_text(t),
            WsMessage::Binary(b) => conn.send_binary(b),
            _ => Ok(()),
        };
    }
}

/// A site with one WebSocket route, `/ws`, for members (permission 1).
struct Site {
    access: Access,
}

const MEMBERS: Rule = Rule::needs(1, PermSet(1));

impl WebService for Site {
    fn respond(
        &self,
        _req: &HttpRequest<'_>,
        _env: &Envelope,
        _caller: &Caller<'_>,
        reply: &mut HttpReply,
    ) -> Answered {
        reply.text(404, "not here");
        Outcome::Done.into()
    }

    fn upgrade(&self, head: &HttpHead<'_>, _env: &Envelope, caller: &Caller<'_>) -> Upgrade {
        if head.path() != "/ws" {
            return Upgrade::NotHere;
        }
        match self.access.check(caller.identity(), &MEMBERS) {
            Decision::Allow => Upgrade::Accept(WsAccept {
                service: Arc::new(Echo),
                origins: ws_net::OriginPolicy::allow(&["https://example.com"]).expect("origins"),
                rule: MEMBERS,
            }),
            Decision::Deny(r) => Upgrade::Refuse(r.status),
        }
    }
}

fn open_with(ws: WsSettings, listen: &str) -> (Door, Tokens) {
    open_ingress(ws, listen, gateway_io::IngressMode::Direct)
}

fn open_ingress(ws: WsSettings, listen: &str, ingress: gateway_io::IngressMode) -> (Door, Tokens) {
    let tokens = Tokens::default();
    let core = Arc::new(
        Core::builder()
            .authenticator(tokens.clone())
            .external("web")
            .profile("site", "web", |_| {})
            .load()
            .expect("core"),
    );
    let mut web = WebServices::new();
    web.attach(
        core.service_tag("web").expect("tag"),
        Site {
            access: core.access().clone(),
        },
    );
    let settings = Settings {
        listen: listen.into(),
        workers: 1,
        passports: 8,
        ws,
        ingress,
        ..Settings::default()
    };
    let door = Door::open(core, &settings, UrgentLine::detached(), web).expect("opens");
    (door, tokens)
}

fn open(ws: WsSettings) -> (Door, SocketAddr, Tokens) {
    let (door, tokens) = open_with(ws, "127.0.0.1:0");
    let addr = door.local_addr().expect("addr");
    (door, addr, tokens)
}

/// The upgrade request with these extra fields.
fn upgrade_request(path: &str, fields: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{fields}\r\n"
    )
}

/// Sends the upgrade on `stream`: a WebSocket on 101, else the status.
fn handshake<S: Read + Write>(
    mut stream: S,
    path: &str,
    fields: &str,
) -> Result<WebSocket<S>, u16> {
    stream
        .write_all(upgrade_request(path, fields).as_bytes())
        .expect("write");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    let text = String::from_utf8_lossy(&head);
    let status: u16 = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    if status == 101 {
        Ok(WebSocket::from_upgraded(stream, &[], Connection::client()))
    } else {
        Err(status)
    }
}

fn connect(addr: SocketAddr, path: &str, fields: &str) -> Result<WebSocket<TcpStream>, u16> {
    let stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    handshake(stream, path, fields)
}

const MEMBER: &str = "Authorization: Bearer ann\r\nOrigin: https://example.com\r\n";

/// Waits for `door` to count `n` open WebSockets.
fn wait_open(door: &Door, n: usize) {
    let t = Instant::now();
    while door.websockets() != n && t.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(door.websockets(), n);
}

/// Whether the server ended `ws` (a close, or the connection cut).
fn ended(ws: &mut WebSocket<TcpStream>) -> bool {
    loop {
        match ws.read() {
            Ok(Message::Close(_)) | Err(_) => return true,
            Ok(_) => {}
        }
    }
}

#[test]
fn a_member_upgrades_and_talks() {
    let (door, addr, tokens) = open(WsSettings::default());
    tokens.set("ann", 7, 1);
    let mut ws = connect(addr, "/ws", MEMBER).expect("101");
    ws.send_text("hello").expect("send");
    assert_eq!(ws.read().expect("echo"), Message::Text("hello".into()));
    ws.send_binary(&[1, 2, 3]).expect("send");
    assert_eq!(ws.read().expect("echo"), Message::Binary(vec![1, 2, 3]));
    wait_open(&door, 1);
    ws.close(CloseCode::NORMAL, "").expect("close");
    assert!(ended(&mut ws));
    wait_open(&door, 0);
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn nothing_is_switched_for_the_wrong_caller_page_or_path() {
    let (door, addr, tokens) = open(WsSettings::default());
    tokens.set("ann", 7, 1);
    tokens.set("guest-ish", 8, 0);
    let refused = |path: &str, fields: &str| connect(addr, path, fields).err();
    // No credential: sign in first.
    assert_eq!(refused("/ws", "Origin: https://example.com\r\n"), Some(401));
    // Signed in without the permission.
    assert_eq!(
        refused(
            "/ws",
            "Authorization: Bearer guest-ish\r\nOrigin: https://example.com\r\n"
        ),
        Some(403)
    );
    // Banned: refused by authentication.
    assert_eq!(
        refused("/ws", "Authorization: Bearer banned\r\n"),
        Some(403)
    );
    // A page on another site, with the member's credential.
    assert_eq!(
        refused(
            "/ws",
            "Authorization: Bearer ann\r\nOrigin: https://evil.example\r\n"
        ),
        Some(403)
    );
    // A path that is no WebSocket route is an ordinary request.
    assert_eq!(refused("/elsewhere", MEMBER), Some(404));
    // Not a browser (no Origin): its credential decides.
    assert!(connect(addr, "/ws", "Authorization: Bearer ann\r\n").is_ok());
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn budgets_hold_connections_messages_and_sizes() {
    let (door, addr, tokens) = open(WsSettings {
        per_account: 1,
        rate: 1,
        burst: 2,
        max_frame: 1024,
        max_message: 1024,
        ..WsSettings::default()
    });
    tokens.set("ann", 7, 1);
    let mut first = connect(addr, "/ws", MEMBER).expect("101");
    wait_open(&door, 1);
    // One connection per account: the second is refused.
    assert_eq!(connect(addr, "/ws", MEMBER).err(), Some(429));
    // Two messages in the burst, then 1008.
    first.send_text("a").expect("send");
    assert_eq!(first.read().expect("echo"), Message::Text("a".into()));
    first.send_text("b").expect("send");
    assert_eq!(first.read().expect("echo"), Message::Text("b".into()));
    first.send_text("c").expect("send");
    match first.read() {
        Ok(Message::Close(Some((code, _)))) => assert_eq!(code, CloseCode::POLICY_VIOLATION),
        other => panic!("expected 1008, got {other:?}"),
    }
    drop(first);
    wait_open(&door, 0);
    // Room again; a message over the size is refused by ws-net (1009).
    let mut ws = connect(addr, "/ws", MEMBER).expect("101");
    ws.send_text(&"x".repeat(2000)).expect("send");
    match ws.read() {
        Ok(Message::Close(Some((code, _)))) => assert_eq!(code, CloseCode::MESSAGE_TOO_BIG),
        other => panic!("expected 1009, got {other:?}"),
    }
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn the_message_budget_is_the_account_s_across_its_connections() {
    let (door, addr, tokens) = open(WsSettings {
        per_account: 2,
        rate: 1,
        burst: 2,
        ..WsSettings::default()
    });
    tokens.set("ann", 7, 1);
    let mut one = connect(addr, "/ws", MEMBER).expect("101");
    let mut two = connect(addr, "/ws", MEMBER).expect("101");
    wait_open(&door, 2);
    for t in ["a", "b"] {
        one.send_text(t).expect("send");
        assert_eq!(one.read().expect("echo"), Message::Text(t.into()));
    }
    // The burst is spent on the first: the second's first message is over.
    two.send_text("c").expect("send");
    match two.read() {
        Ok(Message::Close(Some((code, _)))) => assert_eq!(code, CloseCode::POLICY_VIOLATION),
        other => panic!("expected 1008, got {other:?}"),
    }
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_revoked_account_s_idle_connection_ends_at_once_and_may_come_back() {
    let (door, addr, tokens) = open(WsSettings::default());
    tokens.set("ann", 7, 1);
    tokens.set("bob", 9, 1);
    let revoker = Revoker::new();
    revoker.attach_to(&door);
    let mut ann = connect(addr, "/ws", MEMBER).expect("101");
    let mut bob = connect(
        addr,
        "/ws",
        "Authorization: Bearer bob\r\nOrigin: https://example.com\r\n",
    )
    .expect("101");
    wait_open(&door, 2);
    // Idle: no message crosses a checkpoint, the eject reaches it anyway.
    revoker.account(7);
    assert!(ended(&mut ann), "ann's connection ended");
    wait_open(&door, 1);
    bob.send_text("still here").expect("send");
    assert_eq!(
        bob.read().expect("echo"),
        Message::Text("still here".into())
    );
    // A revocation ends what ran; it is not a ban.
    let mut again = connect(addr, "/ws", MEMBER).expect("a new connection");
    again.send_text("back").expect("send");
    assert_eq!(again.read().expect("echo"), Message::Text("back".into()));
    // One session or key, by its id.
    revoker.session(9 + 1000);
    assert!(ended(&mut bob), "bob's session ended");
    // The key was revoked, not banned: a new ticket binds it as usual.
    let bob_header = "Authorization: Bearer bob\r\nOrigin: https://example.com\r\n";
    let mut bob = connect(addr, "/ws", bob_header).expect("bob comes back");
    bob.send_text("back").expect("send");
    assert_eq!(bob.read().expect("echo"), Message::Text("back".into()));
    // The account's own request asked: only its sockets end.
    revoker.account_sockets(7);
    assert!(ended(&mut again), "ann's socket ended");
    bob.send_text("still").expect("send");
    assert_eq!(bob.read().expect("echo"), Message::Text("still".into()));
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn the_recheck_ends_a_connection_whose_credential_stopped_working() {
    let (door, addr, tokens) = open(WsSettings {
        recheck: Duration::from_secs(1),
        ..WsSettings::default()
    });
    tokens.set("ann", 7, 1);
    tokens.set("bob", 9, 1);
    let mut ann = connect(addr, "/ws", MEMBER).expect("101");
    let mut bob = connect(
        addr,
        "/ws",
        "Authorization: Bearer bob\r\nOrigin: https://example.com\r\n",
    )
    .expect("101");
    wait_open(&door, 2);
    // No event: the token just stops working (expired, revoked elsewhere).
    tokens.remove("ann");
    assert!(ended(&mut ann), "the recheck ended it");
    wait_open(&door, 1);
    bob.send_text("fine").expect("send");
    assert_eq!(bob.read().expect("echo"), Message::Text("fine".into()));
    // Losing the permission ends it too.
    tokens.set("bob", 9, 0);
    assert!(ended(&mut bob), "no longer a member");
    let _ = door.close(Duration::from_secs(2));
}

#[cfg(unix)]
#[test]
fn a_websocket_upgrades_over_the_unix_socket() {
    use std::os::unix::net::UnixStream;

    let dir = std::env::temp_dir().join(format!("gw-ws-unix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("wasp.sock");
    let (door, tokens) = open_with(WsSettings::default(), &format!("unix:{}", sock.display()));
    tokens.set("ann", 7, 1);
    let stream = UnixStream::connect(&sock).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let mut ws = handshake(stream, "/ws", MEMBER).expect("101");
    ws.send_text("over the socket").expect("send");
    assert_eq!(
        ws.read().expect("echo"),
        Message::Text("over the socket".into())
    );
    let _ = door.close(Duration::from_secs(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn over_http2_the_websocket_route_is_refused_and_http1_still_upgrades() {
    // Behind a trusted proxy, where the listener speaks cleartext HTTP/2.
    let (door, tokens) = open_ingress(
        WsSettings::default(),
        "127.0.0.1:0",
        gateway_io::IngressMode::Proxy {
            trusted: vec!["127.0.0.1".into()],
            forwarded_proto: true,
        },
    );
    let addr = door.local_addr().expect("addr");
    tokens.set("ann", 7, 1);
    let visitor = ("x-forwarded-for", "203.0.113.10");
    let bearer = ("authorization", "Bearer ann");
    // WebSockets over HTTP/2 (RFC 8441, extended CONNECT) are not served:
    // the stream is refused, never switched.
    let extended = h2c::request(
        addr,
        "CONNECT",
        "/ws",
        &[(":protocol", "websocket"), visitor, bearer],
    );
    assert!(extended.spoke_h2, "{extended:?}");
    assert!(
        extended.reset.is_some()
            || extended.goaway.is_some()
            || extended.status.is_some_and(|s| s >= 400),
        "refused: {extended:?}"
    );
    // A plain HTTP/2 GET of the route is an ordinary request, not a switch.
    let get = h2c::request(addr, "GET", "/ws", &[visitor, bearer]);
    assert!(get.status.is_some_and(|s| s != 101 && s != 200), "{get:?}");
    assert_eq!(door.websockets(), 0);
    // HTTP/1.1 on the same listener still upgrades.
    let mut ws = connect(
        addr,
        "/ws",
        "Authorization: Bearer ann\r\nOrigin: https://example.com\r\nX-Forwarded-For: 203.0.113.10\r\n",
    )
    .expect("101 over HTTP/1.1");
    ws.send_text("hi").expect("send");
    assert_eq!(ws.read().expect("echo"), Message::Text("hi".into()));
    let _ = door.close(Duration::from_secs(2));
}
