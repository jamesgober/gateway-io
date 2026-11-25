//! A site's WebSocket routes (G-81): which paths upgrade, who may open
//! them, and which pages may. The gateway authenticates the caller and keeps
//! the connection honest while it is open; this decides the route.
//!
//! Nothing upgrades unless a route is declared. The only route so far is the
//! echo route of the `ws-echo` feature (`site.ws_echo`), for tests and
//! trials: a signed-in member's messages come back as they were sent.

use std::sync::Arc;

use gateway_io::ws::WebSocketService;
#[cfg(feature = "ws-echo")]
use gateway_io::ws::WsMessage;
use gateway_io::{Answered, Caller, Upgrade, WebService, WsAccept};
use serve_net::{Envelope, Finished, HttpHead, HttpReply, HttpRequest, WorkClass};
use wasp_core::{Access, Decision, Rule};

use crate::site::SiteSettings;

/// One WebSocket route.
pub struct WsRoute {
    /// The path, under the site's base (`/blog/ws/chat`).
    pub path: String,
    /// Who may open it, checked again while it is open.
    pub rule: Rule,
    /// The conversation.
    pub service: Arc<dyn WebSocketService>,
}

impl std::fmt::Debug for WsRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsRoute")
            .field("path", &self.path)
            .field("rule", &self.rule)
            .finish_non_exhaustive()
    }
}

/// A site with WebSocket routes: HTTP goes to the site, an upgrade on one of
/// the routes is answered here.
pub struct WsSite {
    site: Box<dyn WebService>,
    routes: Vec<WsRoute>,
    access: Access,
    /// The site's hosts as `https://` origins; empty for the same-origin
    /// rule (a development site, or one that answers any host).
    origins: Vec<String>,
}

impl std::fmt::Debug for WsSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsSite")
            .field("routes", &self.routes)
            .field("origins", &self.origins)
            .finish_non_exhaustive()
    }
}

impl WsSite {
    /// `site` with `routes`; pages may open them from the site's own hosts.
    #[must_use]
    pub fn new(
        site: Box<dyn WebService>,
        routes: Vec<WsRoute>,
        access: Access,
        settings: &SiteSettings,
    ) -> WsSite {
        let origins = if settings.any_host {
            Vec::new()
        } else {
            settings
                .hosts
                .iter()
                .map(|h| format!("https://{h}"))
                .collect()
        };
        WsSite {
            site,
            routes,
            access,
            origins,
        }
    }

    fn origin_policy(&self) -> ws_net::OriginPolicy {
        if self.origins.is_empty() {
            return ws_net::OriginPolicy::same_origin();
        }
        let list: Vec<&str> = self.origins.iter().map(String::as_str).collect();
        // Hosts were checked at boot; one that is no origin falls back to
        // the same-origin rule rather than to any page.
        ws_net::OriginPolicy::allow(&list).unwrap_or_else(|_| ws_net::OriginPolicy::same_origin())
    }
}

impl WebService for WsSite {
    fn respond(
        &self,
        req: &HttpRequest<'_>,
        env: &Envelope,
        caller: &Caller<'_>,
        reply: &mut HttpReply,
    ) -> Answered {
        self.site.respond(req, env, caller, reply)
    }

    fn classify(&self, head: &HttpHead<'_>) -> WorkClass {
        self.site.classify(head)
    }

    fn upgrade(&self, head: &HttpHead<'_>, env: &Envelope, caller: &Caller<'_>) -> Upgrade {
        let Some(route) = self.routes.iter().find(|r| r.path == head.path()) else {
            return self.site.upgrade(head, env, caller);
        };
        match self.access.check(caller.identity(), &route.rule) {
            Decision::Allow => Upgrade::Accept(WsAccept {
                service: Arc::clone(&route.service),
                origins: self.origin_policy(),
                rule: route.rule,
            }),
            Decision::Deny(refusal) => Upgrade::Refuse(refusal.status),
        }
    }

    fn done(&self, env: &Envelope, finished: &Finished) {
        self.site.done(env, finished);
    }
}

/// The echo route's rule: a signed-in member (an API key needs
/// `account:read`).
#[cfg(feature = "ws-echo")]
pub const ECHO_RULE: Rule = Rule::needs(10, crate::site_nex::MEMBER);

/// Every message back as it came (feature `ws-echo`).
#[cfg(feature = "ws-echo")]
#[derive(Debug, Default)]
pub struct Echo;

#[cfg(feature = "ws-echo")]
impl WebSocketService for Echo {
    fn message(
        &self,
        _env: &Envelope,
        message: WsMessage<'_>,
        conn: &mut gateway_io::ws::WebSocketConn<'_>,
    ) {
        let _ = match message {
            WsMessage::Text(t) => conn.send_text(t),
            WsMessage::Binary(b) => conn.send_binary(b),
            _ => Ok(()),
        };
    }
}

/// The routes `settings` declare.
#[must_use]
pub fn routes(settings: &SiteSettings) -> Vec<WsRoute> {
    #[allow(unused_mut)]
    let mut routes = Vec::new();
    #[cfg(feature = "ws-echo")]
    if let Some(path) = &settings.ws_echo {
        routes.push(WsRoute {
            path: format!("{}{path}", settings.base.trim_end_matches('/')),
            rule: ECHO_RULE,
            service: Arc::new(Echo),
        });
    }
    #[cfg(not(feature = "ws-echo"))]
    let _ = settings;
    routes
}
