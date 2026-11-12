//! The site: web-net on the gateway, content from the content store, pages
//! and error pages rendered by the theme (build-path step 5), behind the
//! gatekeeper (step 7).
//!
//! | Path | Rule | Template | What |
//! |---|---|---|---|
//! | `/` | public | `home` | the post listing, newest first |
//! | `/posts/:slug` | public | `post` | a post; 404 (themed) when there is none |
//! | `/about` | public | `page` | the `about` page from the manifest |
//! | `/account` | `account.read` | `account` | who is signed in, and the sign-out button; guests are sent to `/sign-in` (303) |
//! | `/sign-in` | public | `sign-in` | the sign-in form (`GET`); signs in (`POST`, the gatekeeper's own token) |
//! | `/sign-out` | signed in | none | signs out (`POST`, the session-bound token), 303 to `/` |
//! | `/health` | none | none | liveness, answered before the gate |
//! | `/theme/...` | none | none | the theme's static files (the stylesheet) |
//!
//! Error pages (404, 405, 500, ...) come from the theme's `errors/` folder
//! through web-net's error-page hook.
//!
//! Configuration (`[site]`): `name`, `base` (the folder the site lives under,
//! for example `/blog`), `hosts` (none means a development site answering
//! localhost), `assets` (a folder served under `/static`), `theme` (the theme
//! folder, default `themes/default`), `theme_poll` (how often the watcher
//! looks for changes, default `1s`; `0s` turns it off).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use gateway_io::gatekeeper::gatekeeper_io::{Gatekeeper, Login, LoginForm, Refusal, Rule};
use gateway_io::gatekeeper::{GatekeeperGate, Session, cookie_lines, visit};
use wasp_core::suite::config::Config;
use web_net::form_net::{self, Secret};
use web_net::{App, Assets, Cx, Route, get, post};

use crate::auth::ACCOUNT_READ;
use crate::content::{Kind, Manifest};
use crate::theme::{Form, Page, SiteEngine, SiteInfo};

/// A handler's context on this site.
pub type SiteCx<'a> = Cx<'a, Session, SiteEngine>;

/// The site's app type.
pub type SiteApp = App<GatekeeperGate, SiteEngine>;

/// A route on this site.
pub type SiteRoute = Route<Session, Rule, SiteEngine>;

form_net::form! {
    /// The sign-in form.
    struct SignIn {
        email: String,
        password: Secret,
        csrf: String,
    }
}

form_net::form! {
    /// The sign-out button.
    struct SignOut {
        csrf: String,
    }
}

/// The handler error for a gate refusal: its status, a stable code.
fn refused(r: &Refusal) -> web_net::Error {
    web_net::Error::new(r.status(), "gate.refused")
}

/// `s` as a query value: everything but unreserved characters and `/`
/// percent-encoded.
fn query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Where the site lives and what it serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteSettings {
    /// The site's name.
    pub name: String,
    /// The folder the site is installed under (`/blog`), or empty.
    pub base: String,
    /// The site's hosts, canonical first; empty for a development site.
    pub hosts: Vec<String>,
    /// A folder served under `/static`.
    pub assets: Option<PathBuf>,
    /// The theme folder.
    pub theme: PathBuf,
    /// How often the theme watcher looks for changes; zero turns it off.
    pub theme_poll: Duration,
}

impl Default for SiteSettings {
    fn default() -> SiteSettings {
        SiteSettings {
            name: "WASP".to_owned(),
            base: String::new(),
            hosts: Vec::new(),
            assets: None,
            theme: PathBuf::from("themes/default"),
            theme_poll: Duration::from_secs(1),
        }
    }
}

impl SiteSettings {
    /// Reads `[site]`; every key is optional.
    pub fn from_config(config: &Config) -> Result<SiteSettings, String> {
        let d = SiteSettings::default();
        let e = |e: wasp_core::suite::Error| e.to_string();
        Ok(SiteSettings {
            name: config.get_or("site.name", d.name).map_err(e)?,
            base: {
                let base: String = config.get_or("site.base", d.base).map_err(e)?;
                let ok = base.is_empty()
                    || (base.starts_with('/')
                        && !base.ends_with('/')
                        && base[1..].split('/').all(|seg| {
                            !seg.is_empty()
                                && seg != "."
                                && seg != ".."
                                && seg
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                        }));
                if !ok {
                    return Err(format!(
                        "site.base must be empty or like `/blog` (a leading `/`, no trailing `/`), not `{base}`"
                    ));
                }
                base
            },
            hosts: config.get_or("site.hosts", d.hosts).map_err(e)?,
            assets: config.get("site.assets").map_err(e)?,
            theme: config.get_or("site.theme", d.theme).map_err(e)?,
            theme_poll: config.get_or("site.theme_poll", d.theme_poll).map_err(e)?,
        })
    }
}

/// Builds the site behind `gatekeeper`, rendering with `engine`.
pub fn build(
    gatekeeper: Arc<Gatekeeper>,
    manifest: Manifest,
    engine: SiteEngine,
    settings: &SiteSettings,
) -> Result<SiteApp, String> {
    let base = settings.base.trim_end_matches('/').to_owned();
    let site = Arc::new(SiteInfo {
        name: settings.name.clone(),
        home: format!("{base}/"),
        about: format!("{base}/about"),
        account: format!("{base}/account"),
        css: format!("{base}/theme/site.css"),
    });
    let manifest = Arc::new(manifest);
    let page = {
        let site = site.clone();
        let manifest = manifest.clone();
        move |title: &str, entry, message: &str, form: Option<Form>| Page {
            site: site.clone(),
            title: title.to_owned(),
            entry,
            posts: manifest.posts(),
            message: message.to_owned(),
            form: form.map(Arc::new),
        }
    };
    let members = Rule::signed_in()
        .needs(gatekeeper.schema(), &[ACCOUNT_READ])
        .map_err(|e| format!("site rule: {e}"))?;

    let mut builder = App::with(GatekeeperGate(gatekeeper.clone()), engine);
    if settings.hosts.is_empty() {
        builder = builder.development();
    }
    for host in &settings.hosts {
        builder = builder.host(host);
    }
    if !base.is_empty() {
        builder = builder.base(&base);
    }
    if let Some(dir) = &settings.assets {
        builder = builder.assets(Assets::new("/static", dir.clone()));
    }
    builder = builder.assets(Assets::new("/theme", settings.theme.join("static")));

    let p = page.clone();
    let home: SiteRoute = get("/", move |cx: &mut SiteCx<'_>| {
        cx.render(&p("Home", None, "", None))
    })
    .public()
    .template("home")
    .name("home");

    let p = page.clone();
    let m = manifest.clone();
    let post_page: SiteRoute = get("/posts/:slug", move |cx: &mut SiteCx<'_>| {
        let slug = cx.param("slug").map(|s| s.into_owned()).unwrap_or_default();
        let Some(entry) = m.get(Kind::Post, &slug) else {
            return Err(web_net::Error::not_found("post.unknown"));
        };
        let view = p(&entry.title, Some(entry.clone()), "", None);
        cx.render(&view)
    })
    .public()
    .template("post")
    .name("post");

    let p = page.clone();
    let m = manifest.clone();
    let about: SiteRoute = get("/about", move |cx: &mut SiteCx<'_>| {
        let entry = m.get(Kind::Page, "about");
        cx.render(&p("About", entry, "Nothing here yet.", None))
    })
    .public()
    .template("page")
    .name("about");

    let p = page.clone();
    let gk = gatekeeper.clone();
    let account: SiteRoute = get("/account", move |cx: &mut SiteCx<'_>| {
        let cleared = gk
            .authorize(cx.identity().identified().clone(), &Rule::signed_in())
            .map_err(|r| refused(&r))?;
        let csrf = gk.csrf_token(&cleared).map_err(|r| refused(&r))?;
        let user = cleared.user().map(|u| u.to_string()).unwrap_or_default();
        let form = Form {
            action: cx.url("/sign-out"),
            csrf,
            user,
            ..Form::default()
        };
        cx.render(&p("Account", None, "", Some(form)))
    })
    .allow(members)
    .template("account")
    .name("account");

    // The sign-in form: a token bound to the visitor's pre-session cookie.
    let sign_in_form = {
        let gk = gatekeeper.clone();
        let p = page.clone();
        move |cx: &mut SiteCx<'_>, error: &str, email: &str| -> web_net::Result {
            let lines = cookie_lines(cx.request());
            let v = visit(cx.request(), &lines);
            let cleared = gk
                .authorize(cx.identity().identified().clone(), &Rule::guest_only())
                .map_err(|r| refused(&r))?;
            let token = gk.login_form(&cleared, &v).map_err(|r| refused(&r))?;
            let next = cx.next_path()?;
            let mut action = cx.url("/sign-in");
            if let Some(next) = next {
                action.push_str("?next=");
                action.push_str(&query_value(&cx.url(&next)));
            }
            if let Some(c) = token.set_cookie() {
                cx.set_header("set-cookie", c);
            }
            let form = Form {
                action,
                csrf: token.token().to_owned(),
                error: error.to_owned(),
                email: email.to_owned(),
                ..Form::default()
            };
            cx.render(&p("Sign in", None, "", Some(form)))
        }
    };

    let show = sign_in_form.clone();
    let sign_in: SiteRoute = get("/sign-in", move |cx: &mut SiteCx<'_>| {
        if !cx.identity().identified().is_guest() {
            let next = cx.next_path()?.unwrap_or_else(|| "/account".to_owned());
            return cx.see_other(&next);
        }
        show(cx, "", "")
    })
    .public()
    .template("sign-in")
    .name("sign-in");

    let show = sign_in_form;
    let gk = gatekeeper.clone();
    let sign_in_post: SiteRoute = post("/sign-in", move |cx: &mut SiteCx<'_>| {
        let next = cx.next_path()?.unwrap_or_else(|| "/account".to_owned());
        if !cx.identity().identified().is_guest() {
            return cx.see_other(&next);
        }
        let form: SignIn = cx.form()?;
        let lines = cookie_lines(cx.request());
        let v = visit(cx.request(), &lines);
        let cleared = gk
            .authorize(cx.identity().identified().clone(), &Rule::guest_only())
            .map_err(|r| refused(&r))?;
        // Argon2id runs here, on this worker (see the step 7 limits).
        let login = gk.login(
            &cleared,
            &v,
            LoginForm {
                identifier: &form.email,
                password: form.password.expose(),
                csrf: form.csrf.as_bytes(),
            },
        );
        match login {
            Login::SignedIn(signed_in) => {
                for c in signed_in.set_cookies() {
                    cx.set_header("set-cookie", c);
                }
                cx.see_other(&next)
            }
            Login::SecondFactor(_) => {
                cx.status(501);
                show(
                    cx,
                    "This account asks for a second factor, which this site does not offer yet.",
                    &form.email,
                )
            }
            Login::Failed(failed) => {
                cx.status(401);
                show(cx, failed.message(), &form.email)
            }
        }
    })
    .public()
    .csrf_exempt("the gatekeeper checks its sign-in token and the origin itself")
    .template("sign-in")
    .name("sign-in-post");

    let gk = gatekeeper;
    let sign_out: SiteRoute = post("/sign-out", move |cx: &mut SiteCx<'_>| {
        let form: SignOut = cx.form()?;
        let lines = cookie_lines(cx.request());
        let v = visit(cx.request(), &lines);
        let cleared = gk
            .authorize(cx.identity().identified().clone(), &Rule::signed_in())
            .map_err(|r| refused(&r))?;
        let out = gk
            .logout(cleared, &v, form.csrf.as_bytes())
            .map_err(|r| refused(&r))?;
        if let Some(c) = out.set_cookie() {
            cx.set_header("set-cookie", c);
        }
        cx.see_other("/")
    })
    .allow(Rule::signed_in())
    .csrf_exempt("the gatekeeper checks the session-bound token and the origin itself")
    .name("sign-out");

    builder
        .sign_in("/sign-in")
        .health("/health")
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
