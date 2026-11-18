//! The site behind nex-db (`auth.store = "nex"`): accounts and sessions are
//! durable, the core authenticates with [`NexAuth`], and web-net authorizes
//! routes through the core's access gate and checks every form's CSRF token
//! with its own engine.
//!
//! A guest's first visit to the sign-in page sets a pre-session cookie and
//! comes back to it, so the sign-in form's token is bound to that visitor;
//! a signed-in visitor's tokens are bound to the session.

use gateway_io::{Caller, WebGate};
use wasp_core::{Access, Decision, Identity, PermSet, Rule};
use web_net::form_net::{self, Secret};
use web_net::{App, Context, Denial, Gate, Request, Route, get, post};

use crate::content::Manifest;
use crate::nex::{NexAuth, NexToken, PRE_COOKIE, SESSION_COOKIE, cookie};
use crate::site::{Pages, SiteSettings, configure, content_routes, query_value};
use crate::theme::{Form, SiteEngine};

/// The permission the account page needs (the `member` role's bit).
pub const MEMBER: PermSet = PermSet(1);

/// Who a request is from, as web-net sees it on this site.
#[derive(Clone, Copy, Debug)]
pub struct NexWho {
    /// The core's identity stamp.
    pub identity: Identity,
    token: NexToken,
}

impl web_net::Identity for NexWho {
    fn is_guest(&self) -> bool {
        self.identity.is_guest()
    }

    fn csrf_binding(&self) -> Option<&[u8]> {
        let b = self.token.binding();
        (!b.is_empty()).then_some(b)
    }
}

/// web-net's gate for the site: the core authenticated (with [`NexAuth`]);
/// routes are authorized by the core's access gate.
#[derive(Clone, Debug)]
pub struct NexGate {
    access: Access,
}

impl Gate for NexGate {
    type Identity = NexWho;
    type Rule = Rule;

    fn authenticate(&self, _req: &Request<'_>) -> Result<NexWho, Denial> {
        Err(Denial::with_status(500, "gateway.authenticates_in_core"))
    }

    fn authorize(&self, who: &NexWho, rule: &Rule, _req: &Request<'_>) -> Result<(), Denial> {
        match self.access.check(&who.identity, rule) {
            Decision::Allow => Ok(()),
            Decision::Deny(refusal) => Err(match refusal.status {
                401 => Denial::sign_in("access.sign_in"),
                404 => Denial::hidden("access.hidden"),
                _ => Denial::forbidden("access.forbidden"),
            }),
        }
    }
}

impl WebGate for NexGate {
    fn with_identity<R>(caller: &Caller<'_>, f: impl FnOnce(&NexWho) -> R) -> Option<R> {
        let token = caller
            .token::<NexToken>()
            .copied()
            .unwrap_or_else(NexToken::empty);
        Some(f(&NexWho {
            identity: *caller.identity(),
            token,
        }))
    }
}

/// A handler's context on this site.
pub type NexCx<'a> = Context<'a, NexWho, SiteEngine>;

/// The site's app type.
pub type NexApp = App<NexGate, SiteEngine>;

/// A route on this site.
pub type NexRoute = Route<NexWho, Rule, SiteEngine>;

form_net::form! {
    /// The sign-in form (web-net checked its `csrf_token` before the handler).
    struct SignIn {
        email: String,
        password: Secret,
    }
    ignore = ["csrf_token"];
}

fn random_hex() -> Result<String, web_net::Error> {
    let bytes = crypt_io::generate_key().map_err(|_| web_net::Error::internal("random"))?;
    Ok(bytes[..16].iter().map(|b| format!("{b:02x}")).collect())
}

/// Builds the site behind nex-db's accounts.
pub fn build(
    auth: NexAuth,
    access: Access,
    manifest: Manifest,
    engine: SiteEngine,
    settings: &SiteSettings,
    ready: impl Fn() -> bool + Send + Sync + 'static,
) -> Result<NexApp, String> {
    let pages = Pages::new(settings, manifest);
    // Tokens are keyed for this run of the process; a form rendered before a
    // restart is refused once and rendered again.
    let key = crypt_io::generate_key().map_err(|e| format!("csrf key: {e}"))?;
    let csrf = web_net::csrf_sec::Csrf::new(*key).map_err(|e| format!("csrf: {e}"))?;
    let builder = configure(
        App::with_gate(NexGate { access }).render(engine).csrf(csrf),
        settings,
        ready,
    );

    let p = pages.clone();
    let account: NexRoute = get("/account", move |cx: &mut NexCx<'_>| {
        let user = match cx.identity().identity.subject() {
            wasp_core::Subject::User(u) => format!("{:032x}", u.0),
            _ => String::new(),
        };
        let form = Form {
            action: cx.url("/sign-out")?,
            csrf: cx.csrf_token()?,
            user,
            ..Form::default()
        };
        cx.render(&p.page("Account", None, "", Some(form)))
    })
    .allow(Rule::needs(2, MEMBER))
    .template("account")
    .name("account");

    let sign_in_form = {
        let p = pages.clone();
        move |cx: &mut NexCx<'_>, error: &str, email: &str| -> web_net::Result {
            // The form posts back here, keeping where to go after.
            let mut back = "/sign-in".to_owned();
            if let Some(next) = cx.next_path()? {
                back.push_str("?next=");
                back.push_str(&query_value(&cx.url(&next)?));
            }
            if web_net::Identity::csrf_binding(cx.identity()).is_none() {
                // The first visit: a pre-session cookie, then the same page,
                // so the form's token is bound to this visitor.
                let pre = random_hex()?;
                cx.set_header(
                    "set-cookie",
                    format!("{PRE_COOKIE}={pre}; Path=/; Secure; HttpOnly; SameSite=Lax"),
                );
                return cx.redirect(303, &back);
            }
            let action = cx.url(&back)?;
            let form = Form {
                action,
                csrf: cx.csrf_token()?,
                error: error.to_owned(),
                email: email.to_owned(),
                ..Form::default()
            };
            cx.render(&p.page("Sign in", None, "", Some(form)))
        }
    };

    let show = sign_in_form.clone();
    let sign_in: NexRoute = get("/sign-in", move |cx: &mut NexCx<'_>| {
        if !cx.identity().identity.is_guest() {
            let next = cx.next_path()?.unwrap_or_else(|| "/account".to_owned());
            return cx.redirect(303, &next);
        }
        show(cx, "", "")
    })
    .public()
    .template("sign-in")
    .name("sign-in");

    let show = sign_in_form;
    let a = auth.clone();
    let sign_in_post: NexRoute = post("/sign-in", move |cx: &mut NexCx<'_>| {
        let next = cx.next_path()?.unwrap_or_else(|| "/account".to_owned());
        if !cx.identity().identity.is_guest() {
            return cx.redirect(303, &next);
        }
        let form: SignIn = cx.form()?;
        // Argon2id runs here, on this worker (see the limits).
        match a
            .sign_in(&form.email, form.password.expose())
            .map_err(|_| web_net::Error::unavailable("auth.unavailable"))?
        {
            Some(set) => {
                cx.set_header("set-cookie", set);
                cx.set_header(
                    "set-cookie",
                    format!("{PRE_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"),
                );
                cx.redirect(303, &next)
            }
            None => {
                cx.status(401);
                show(
                    cx,
                    "Those sign-in details are not right. Please try again.",
                    &form.email,
                )
            }
        }
    })
    .public()
    .template("sign-in")
    .name("sign-in-post");

    let a = auth;
    let sign_out: NexRoute = post("/sign-out", move |cx: &mut NexCx<'_>| {
        if let Some(token) = cx
            .header("cookie")
            .and_then(|h| cookie(h, SESSION_COOKIE))
            .map(str::to_owned)
        {
            let clear = a
                .sign_out(&token)
                .map_err(|_| web_net::Error::unavailable("auth.unavailable"))?;
            cx.set_header("set-cookie", clear);
        }
        cx.redirect(303, "/")
    })
    .allow(Rule::needs(3, PermSet::NONE))
    .name("sign-out");

    let [home, post_page, about] = content_routes::<NexWho, Rule>(&pages);
    builder
        .route(home)
        .route(post_page)
        .route(about)
        .route(account)
        .route(sign_in)
        .route(sign_in_post)
        .route(sign_out)
        .build()
        .map_err(|e| format!("site: {e}"))
}
