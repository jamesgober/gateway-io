//! A gate that authenticates and authorizes with its own identity type, as
//! gatekeeper-io's `Gatekeeper` does: the core's authenticator keeps that
//! identity as the passport's token, and web-net is handed the gate's own
//! identity for its routes. A local double until gatekeeper-io is on
//! crates.io; the real gate plugs in the same way (`impl WebGate for
//! Gatekeeper {}` and an authenticator that keeps its `Identified`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebGate, WebServices};
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{
    AuthOut, Authentication, Authenticator, Core, Identity, PermSet, Profile, RequestView,
    SessionId, UserId,
};
use web_net::{App, Cx, Denial, Gate, Request, Route, get};

/// The gate's own identity: what gatekeeper-io's `Identified` is to its gate.
#[derive(Clone, Debug)]
struct GateIdentity {
    user: Option<String>,
}

impl web_net::Identity for GateIdentity {
    fn is_guest(&self) -> bool {
        self.user.is_none()
    }
}

#[derive(Clone, Copy, Debug)]
enum GateRule {
    SignedIn,
}

/// A web-net gate that authorizes with its own identity.
struct DoubleGate;

impl Gate for DoubleGate {
    type Identity = GateIdentity;
    type Rule = GateRule;

    fn authenticate(&self, _req: &Request<'_>) -> Result<GateIdentity, Denial> {
        Err(Denial::status(500, "test.core_authenticates"))
    }

    fn authorize(
        &self,
        who: &GateIdentity,
        rule: &GateRule,
        _req: &Request<'_>,
    ) -> Result<(), Denial> {
        match rule {
            GateRule::SignedIn if who.user.is_none() => Err(Denial::sign_in("test.sign_in")),
            GateRule::SignedIn => Ok(()),
        }
    }
}

/// The one line the real gate needs: its identity comes from the token.
impl WebGate for DoubleGate {}

/// The core's authenticator, keeping the gate's identity as the token.
/// `authorization: Bearer <name>` signs in as `<name>`.
struct DoubleAuth {
    keep_token: bool,
}

impl Authenticator for DoubleAuth {
    fn authenticate(
        &self,
        request: RequestView<'_>,
        _profile: &Profile,
        out: &mut AuthOut,
    ) -> Authentication {
        let user = request
            .head()
            .header_str("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        let identity = match &user {
            Some(_) => Identity::user(UserId(7), SessionId(9), PermSet(1)),
            None => Identity::guest(),
        };
        if self.keep_token {
            out.keep(GateIdentity { user });
        }
        Authentication::Identified(identity)
    }
}

fn open(keep_token: bool) -> (Door, SocketAddr) {
    let core = Arc::new(
        Core::builder()
            .authenticator(DoubleAuth { keep_token })
            .external("web")
            .profile("site", "web", |_| {})
            .load()
            .expect("core"),
    );
    let me: Route<GateIdentity, GateRule> = get("/me", |cx: &mut Cx<'_, GateIdentity>| {
        let name = cx.identity().user.clone().unwrap_or_default();
        cx.text(200, &format!("hello {name}"));
        Ok(())
    })
    .allow(GateRule::SignedIn);
    let home: Route<GateIdentity, GateRule> = get("/", |cx: &mut Cx<'_, GateIdentity>| {
        cx.text(200, "home");
        Ok(())
    })
    .public();
    let sign_in: Route<GateIdentity, GateRule> =
        get("/sign-in", |cx: &mut Cx<'_, GateIdentity>| {
            cx.text(200, "sign in");
            Ok(())
        })
        .public();
    let app = App::with_gate(DoubleGate)
        .development()
        .sign_in("/sign-in")
        .route(me)
        .route(home)
        .route(sign_in)
        .build()
        .expect("app");
    let mut web = WebServices::new();
    web.attach(core.service_tag("web").expect("tag"), app);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        ..Settings::default()
    };
    let door = Door::open(core, &settings, UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

fn send(addr: SocketAddr, request: &str) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    s.write_all(request.as_bytes()).expect("write");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, head.to_owned(), body.to_owned())
}

fn settle(door: &Door) {
    let until = Instant::now() + Duration::from_secs(2);
    while (door.pool().stats().in_use != 0 || door.tickets_held() != 0) && Instant::now() < until {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(door.pool().stats().in_use, 0);
    assert_eq!(door.tickets_held(), 0);
}

#[test]
fn the_gate_authorizes_with_its_own_identity_from_the_token() {
    let (door, addr) = open(true);
    let (status, _, body) = send(
        addr,
        "GET /me HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alice\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(body, "hello alice");

    let (status, head, _) = send(
        addr,
        "GET /me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 303, "{head}");
    assert!(
        head.to_ascii_lowercase().contains("location: /sign-in"),
        "{head}"
    );

    let (status, _, body) = send(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!((status, body.as_str()), (200, "home"));
    settle(&door);
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn no_token_fails_closed() {
    // An authenticator that keeps no token of the gate's type: the gateway
    // answers 500 instead of serving without the gate.
    let (door, addr) = open(false);
    let (status, _, body) = send(
        addr,
        "GET /me HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alice\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 500);
    assert!(!body.contains("hello"));
    let (status, _, _) = send(
        addr,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(status, 500, "even a public page needs the gate's identity");
    settle(&door);
    let _ = door.close(Duration::from_secs(1));
}
