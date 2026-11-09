//! The web service: web-net answering on serve-net's own request and reply,
//! after the core authenticated the request.
//!
//! ```text
//!  core: authenticate ─▶ Handoff (identified, assigned to the web service)
//!  web-net: site ─▶ url ─▶ route (404) ─▶ method (405) ─▶ WaspGate::authorize ─▶ handler ─▶ render
//!  gateway: the hand-off's passport goes back to the pool; the response carries its cookie
//! ```
//!
//! web-net never authenticates here: [`WaspGate::authenticate`] refuses, so a
//! web-net app wired with this gate answers nothing unless the core handed it
//! an identity. Authorization runs per route through the core's access gate
//! ([`wasp_core::Access::check`]), and web-net builds a handler's context only
//! after it passed, so no handler runs on an unauthorized request.

use serve_net::{Envelope, HttpHead, HttpReply, HttpRequest, Outcome, WorkClass};
use wasp_core::{Access, Decision, Identity, Rule, ServiceTag};
use web_net::{Denial, Gate, Request};

/// The identity web-net sees: the one the core's authentication wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Who(pub Identity);

impl web_net::Identity for Who {
    fn is_guest(&self) -> bool {
        self.0.is_guest()
    }
}

/// web-net's gate for the platform: authentication is the core's, authorization
/// is the core's access gate.
#[derive(Clone, Debug)]
pub struct WaspGate {
    access: Access,
}

impl WaspGate {
    /// The gate over the core's access handle (`core.access().clone()`).
    #[must_use]
    pub fn new(access: Access) -> WaspGate {
        WaspGate { access }
    }
}

impl Gate for WaspGate {
    type Identity = Who;
    type Rule = Rule;

    /// Never trusted to run: the core authenticates. Reached only if the app
    /// were served without the gateway (`App::respond`), and then it refuses
    /// every request that needs a gate.
    fn authenticate(&self, _req: &Request<'_>) -> Result<Who, Denial> {
        Err(Denial::status(500, "gateway.authenticates_in_core"))
    }

    fn authorize(&self, who: &Who, rule: &Rule, _req: &Request<'_>) -> Result<(), Denial> {
        match self.access.check(&who.0, rule) {
            Decision::Allow => Ok(()),
            Decision::Deny(refusal) => Err(match refusal.status {
                401 => Denial::sign_in("access.sign_in"),
                403 => Denial::forbidden("access.forbidden"),
                404 => Denial::hidden("access.hidden"),
                other => Denial::status(other, "access.refused"),
            }),
        }
    }
}

/// A service that answers on serve-net's request and reply, given the
/// identity the core decided. web-net's `App<WaspGate>` is one.
pub trait WebService: Send + Sync + 'static {
    /// Answers one identified request into `reply`.
    fn respond(
        &self,
        req: &HttpRequest<'_>,
        env: &Envelope,
        who: &Identity,
        reply: &mut HttpReply,
    ) -> Outcome;

    /// A cheap look at the head before admission (the route's work class).
    fn classify(&self, head: &HttpHead<'_>) -> WorkClass {
        let _ = head;
        WorkClass::Quick
    }
}

impl WebService for web_net::App<WaspGate> {
    #[inline]
    fn respond(
        &self,
        req: &HttpRequest<'_>,
        env: &Envelope,
        who: &Identity,
        reply: &mut HttpReply,
    ) -> Outcome {
        self.respond_identified(req, env, &Who(*who), reply)
    }

    fn classify(&self, head: &HttpHead<'_>) -> WorkClass {
        web_net::App::classify(self, head).work
    }
}

/// The web services attached to the gateway, by the core's service tag.
#[derive(Default)]
pub struct WebServices {
    by_tag: Vec<Option<Box<dyn WebService>>>,
}

impl WebServices {
    /// No web service.
    #[must_use]
    pub fn new() -> WebServices {
        WebServices::default()
    }

    /// Attaches `service` under `tag`.
    pub fn attach(&mut self, tag: ServiceTag, service: impl WebService) {
        let i = usize::from(tag.0);
        if self.by_tag.len() <= i {
            self.by_tag.resize_with(i + 1, || None);
        }
        self.by_tag[i] = Some(Box::new(service));
    }

    /// The service under `tag`.
    #[inline]
    #[must_use]
    pub fn get(&self, tag: ServiceTag) -> Option<&dyn WebService> {
        self.by_tag.get(usize::from(tag.0))?.as_deref()
    }

    /// The tags that have a service.
    pub fn tags(&self) -> impl Iterator<Item = ServiceTag> + '_ {
        self.by_tag
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .filter_map(|(i, _)| u8::try_from(i).ok().map(ServiceTag))
    }
}

impl std::fmt::Debug for WebServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebServices")
            .field("tags", &self.tags().collect::<Vec<_>>())
            .finish()
    }
}
