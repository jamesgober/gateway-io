//! The gatekeeper as the platform's gates (feature `gatekeeper`, build-path
//! step 7): gatekeeper-io authenticates in the core and authorizes in
//! web-net, and the site signs in and out through it.
//!
//! ```text
//!  core:    GatekeeperAuth::authenticate ─▶ identity stamp + kept Session (+ cookie to clear)
//!  web-net: GatekeeperGate::authorize(Session, Rule) ─▶ Gatekeeper::check (no token consumed)
//!  site:    visit(cx.request()) ─▶ Gatekeeper::login_form / login / csrf_token / logout
//! ```
//!
//! The kept token is [`Session`], gatekeeper-io's `Identified` wrapped so
//! web-net (this workspace's version) can read it; the gateway hands it to
//! web-net for every identified request. A gatekeeper `check` refusal never
//! carries a cookie: the cookie that clears a dead session comes from
//! authentication once, and the gateway writes it ahead of the web reply, so
//! a handler's own cookie of the same name (a new session after a sign-in)
//! comes later and wins.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use gatekeeper_io::{DenialKind, Gatekeeper, Identified, Inspected, Refusal, RefusalKind, Visit};
use wasp_core::{
    AuthOut, Authentication, Authenticator, Identity, PermSet, Profile, RequestView, SessionId,
    UserId,
};
use web_net::{Denial, Gate, Request};

use crate::web::WebGate;

pub use gatekeeper_io;

/// The gatekeeper's identity for one request, as web-net sees it.
#[derive(Clone, Debug)]
pub struct Session(pub Identified);

impl Session {
    /// gatekeeper-io's own stage, for its calls (`authorize`, `check`).
    #[must_use]
    pub fn identified(&self) -> &Identified {
        &self.0
    }
}

impl web_net::Identity for Session {
    fn is_guest(&self) -> bool {
        self.0.is_guest()
    }

    fn csrf_binding(&self) -> Option<&[u8]> {
        self.0.csrf_binding()
    }

    fn set_cookie(&self) -> Option<&str> {
        self.0.set_cookie()
    }
}

/// The core's authenticator over the gatekeeper.
#[derive(Clone, Debug)]
pub struct GatekeeperAuth(pub Arc<Gatekeeper>);

impl Authenticator for GatekeeperAuth {
    fn authenticate(
        &self,
        request: RequestView<'_>,
        _profile: &Profile,
        out: &mut AuthOut,
    ) -> Authentication {
        let head = request.head();
        let peer = request
            .trip()
            .client
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        // Several Cookie lines are HTTP/2 crumbs; only then collect them.
        let mut cookies = head
            .fields()
            .filter(|(n, _)| n.eq_ignore_ascii_case(b"cookie"))
            .map(|(_, v)| v);
        let lines: Vec<&[u8]> = match (cookies.next(), cookies.next()) {
            (Some(a), Some(b)) => [a, b].into_iter().chain(cookies).collect(),
            _ => Vec::new(),
        };
        let mut visit = Visit::new(peer)
            .method(head.method().as_bytes())
            .cookie_header(head.header("cookie"))
            .authorization(head.header("authorization"))
            .user_agent(head.header("user-agent"))
            .fetch_site(head.header("sec-fetch-site"))
            .origin(head.header("origin"))
            .referer(head.header("referer"));
        if lines.len() > 1 {
            visit = visit.cookie_lines(&lines);
        }
        match gatekeeper_io::Authenticator::authenticate(&*self.0, Inspected::new(), &visit) {
            Ok(identified) => {
                if let Some(c) = identified.set_cookie() {
                    out.set_cookie(c.as_bytes());
                }
                let identity = stamp(&identified);
                out.keep(Session(identified));
                Authentication::Identified(identity)
            }
            Err(refusal) => {
                if let Some(c) = refusal.set_cookie() {
                    out.set_cookie(c.as_bytes());
                }
                Authentication::Refused(wasp_core::Refusal::status(refusal.status()))
            }
        }
    }
}

/// The core's identity stamp for a gatekeeper identity. Permissions stay
/// with the gatekeeper (web services authorize through it); the stamp's
/// permission set is empty.
fn stamp(identified: &Identified) -> Identity {
    match (identified.user(), identified.identity().session()) {
        (Some(user), Some(session)) => Identity::user(
            UserId(user.as_u128()),
            SessionId(u128::from_be_bytes(*session.as_bytes())),
            PermSet::NONE,
        ),
        _ => Identity::guest(),
    }
}

/// web-net's gate for a site behind the gatekeeper: the core authenticated,
/// so this only authorizes, with [`Gatekeeper::check`].
#[derive(Clone, Debug)]
pub struct GatekeeperGate(pub Arc<Gatekeeper>);

impl Gate for GatekeeperGate {
    type Identity = Session;
    type Rule = gatekeeper_io::Rule;

    /// Never trusted to run: the core authenticates (see
    /// [`WaspGate::authenticate`](crate::WaspGate)).
    fn authenticate(&self, _req: &Request<'_>) -> Result<Session, Denial> {
        Err(Denial::with_status(500, "gateway.authenticates_in_core"))
    }

    fn authorize(
        &self,
        who: &Session,
        rule: &gatekeeper_io::Rule,
        _req: &Request<'_>,
    ) -> Result<(), Denial> {
        self.0.check(&who.0, rule, None).map_err(|r| denial(&r))
    }
}

/// The token the authenticator kept is the identity: the default.
impl WebGate for GatekeeperGate {}

/// web-net's denial for a gatekeeper refusal, with its cookie when it has one.
#[must_use]
pub fn denial(refusal: &Refusal) -> Denial {
    let d = match refusal.kind() {
        RefusalKind::NeedsSignIn => Denial::sign_in("gate.sign_in"),
        RefusalKind::Forbidden(DenialKind::StaleFactor) => Denial::sign_in("gate.step_up"),
        RefusalKind::GuestOnly => Denial::forbidden("gate.guest_only"),
        RefusalKind::Banned { .. } => Denial::forbidden("gate.banned"),
        RefusalKind::Csrf => Denial::forbidden("gate.csrf"),
        RefusalKind::Unavailable => Denial::unavailable("gate.unavailable"),
        RefusalKind::ForeignStage => Denial::forbidden("gate.foreign_stage"),
        _ => Denial::forbidden("gate.forbidden"),
    };
    match refusal.set_cookie() {
        Some(c) => d.with_cookie(c),
        None => d,
    }
}

/// The cookie lines of a web-net request, when it has more than one
/// (HTTP/2 crumbs); empty otherwise. Pass them to [`visit`].
#[must_use]
pub fn cookie_lines<'a>(req: &Request<'a>) -> Vec<&'a [u8]> {
    let mut all = req.raw().head().header_all("cookie");
    match (all.next(), all.next()) {
        (Some(a), Some(b)) => [a, b].into_iter().chain(all).collect(),
        _ => Vec::new(),
    }
}

/// The gatekeeper's view of a web-net request, for the sign-in, sign-out,
/// and CSRF calls a handler makes.
#[must_use]
pub fn visit<'a>(req: &Request<'a>, cookie_lines: &'a [&'a [u8]]) -> Visit<'a> {
    let peer = req
        .client()
        .addr()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let method: &'static str = req.method().as_str().unwrap_or("EXTENSION");
    let mut v = Visit::new(peer)
        .method(method.as_bytes())
        .cookie_header(req.header("cookie"))
        .authorization(req.header("authorization"))
        .user_agent(req.header("user-agent"))
        .fetch_site(req.header("sec-fetch-site"))
        .origin(req.header("origin"))
        .referer(req.header("referer"));
    if cookie_lines.len() > 1 {
        v = v.cookie_lines(cookie_lines);
    }
    v
}
