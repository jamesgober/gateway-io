//! The site: web-net on the gateway, content from the content store, pages
//! and error pages rendered by the theme, behind the process's gates: the
//! gatekeeper (`auth.store = "gatekeeper"`, in memory) or nex-db
//! (`auth.store = "nex"`, durable; the `site_nex` module, feature `store-nex`).
//!
//! | Path | Rule | Template | What |
//! |---|---|---|---|
//! | `/` | public | `home` | the post listing, newest first |
//! | `/posts/:slug` | public | `post` | a post; 404 (themed) when there is none |
//! | `/about` | public | `page` | the `about` page from the manifest |
//! | `/account` | `account.read` | `account` | who is signed in, and the sign-out button; guests are sent to `/sign-in` (303) |
//! | `/sign-in` | public | `sign-in` | the sign-in form (`GET`); signs in (`POST`) |
//! | `/sign-out` | signed in | none | signs out (`POST`, a session-bound token), 303 to `/` |
//! | `/health` | none | none | liveness, answered before the gate |
//! | `/ready` | none | none | 503 while a store cannot serve |
//! | `/theme/...` | none | none | the theme's static files (the stylesheet) |
//!
//! Every form carries its CSRF token in the hidden `csrf_token` field.
//!
//! Configuration (`[site]`): `name`, `base` (the folder the site lives under,
//! for example `/blog`), `hosts` (none means a development site answering
//! localhost), `assets` (a folder served under `/static`), `theme` (the theme
//! folder, default `themes/default`), `theme_poll` (how often the watcher
//! looks for changes, default `1s`; `0s` turns it off).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use wasp_core::suite::config::Config;
use web_net::{Assets, CachePolicy, Context, Route, get};

use crate::content::{Content, Entry, Kind};
use crate::theme::{
    ADMIN_CSS, AdminSource, Editor, Form, Head, Page, Security, SiteEngine, SiteInfo,
};

#[cfg(feature = "gatekeeper")]
pub use gatekeeper_site::{SiteApp, SiteCx, SiteRoute, build};

/// `s` as a query value: everything but unreserved characters and `/`
/// percent-encoded.
pub(crate) fn query_value(s: &str) -> String {
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
    /// Answer any host (a host profile with wildcards: the host router has
    /// already picked the profile).
    pub any_host: bool,
    /// A folder served under `/static`.
    pub assets: Option<PathBuf>,
    /// The theme folder.
    pub theme: PathBuf,
    /// How often the theme watcher looks for changes; zero turns it off.
    pub theme_poll: Duration,
    /// Send sign-in pages asked for over plain http to https: on behind an
    /// application server (`PORT` set), unless `site.development`.
    pub https_sign_in: bool,
    /// Where the admin pages' theme comes from (`[admin] theme`).
    pub admin_theme: AdminSource,
    /// The API (`[api]`, or a host profile's `[host.<name>.api]`).
    pub api: crate::api::ApiSettings,
}

impl Default for SiteSettings {
    fn default() -> SiteSettings {
        SiteSettings {
            name: "WASP".to_owned(),
            base: String::new(),
            hosts: Vec::new(),
            any_host: false,
            assets: None,
            theme: PathBuf::from("themes/default"),
            theme_poll: Duration::from_secs(1),
            https_sign_in: false,
            admin_theme: AdminSource::Builtin,
            api: crate::api::ApiSettings::default(),
        }
    }
}

/// `[admin] theme`: `builtin` (the default), or a folder, which is allowed
/// only with `[admin] custom_theme = true` (an install can keep its admin
/// pages to the one built in).
fn admin_source(config: &Config) -> Result<AdminSource, String> {
    let e = |e: wasp_core::suite::Error| e.to_string();
    let theme: String = config
        .get_or("admin.theme", "builtin".to_owned())
        .map_err(e)?;
    let custom: bool = config.get_or("admin.custom_theme", false).map_err(e)?;
    if theme == "builtin" {
        return Ok(AdminSource::Builtin);
    }
    if !custom {
        return Err(format!(
            "admin.theme names the folder `{theme}`, but custom admin themes are off: set admin.custom_theme = true to allow one, or remove admin.theme"
        ));
    }
    Ok(AdminSource::Folder(PathBuf::from(theme)))
}

/// Whether the site's accounts are nex-db's (`auth.store = "nex"`).
fn nex_accounts(config: &Config) -> bool {
    config
        .get_or("auth.store", crate::DEFAULT_AUTH_STORE.to_owned())
        .is_ok_and(|s| s == "nex")
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
            any_host: false,
            assets: config.get("site.assets").map_err(e)?,
            theme: config.get_or("site.theme", d.theme).map_err(e)?,
            theme_poll: config.get_or("site.theme_poll", d.theme_poll).map_err(e)?,
            https_sign_in: std::env::var_os("PORT").is_some()
                && !config.get_or("site.development", false).map_err(e)?,
            admin_theme: admin_source(config)?,
            api: crate::api::ApiSettings::from_config(config, !nex_accounts(config))?,
        })
    }
}

/// What every page of the site shares: the site's values and the content.
#[derive(Clone)]
pub(crate) struct Pages {
    site: Arc<SiteInfo>,
    /// `https://<first host>`, or empty on a development site: what makes a
    /// canonical address or a sharing image absolute.
    origin: String,
    pub(crate) content: Arc<Content>,
}

impl Pages {
    pub(crate) fn new(settings: &SiteSettings, content: Content) -> Pages {
        let base = settings.base.trim_end_matches('/');
        Pages {
            site: Arc::new(SiteInfo {
                name: settings.name.clone(),
                home: format!("{base}/"),
                about: format!("{base}/about"),
                account: format!("{base}/account"),
                admin: format!("{base}/admin"),
                css: format!("{base}/theme/site.css"),
                icon: format!("{base}/theme/favicon.svg"),
            }),
            origin: settings
                .hosts
                .first()
                .map(|h| format!("https://{h}"))
                .unwrap_or_default(),
            content: Arc::new(content),
        }
    }

    /// `address` (a site path or an absolute URL) made absolute with the
    /// site's origin, when it has one.
    fn absolute(&self, address: &str) -> String {
        if address.starts_with('/') {
            format!("{}{address}", self.origin)
        } else {
            address.to_owned()
        }
    }

    /// The head of a page showing `entry`, or of a page titled `title`
    /// without one.
    fn head(&self, title: &str, entry: Option<&Entry>) -> Head {
        let Some(e) = entry else {
            return Head {
                title: title.to_owned(),
                og_type: "website".to_owned(),
                og_title: title.to_owned(),
                twitter_card: "summary".to_owned(),
                ..Head::default()
            };
        };
        let m = &e.meta;
        let or = |a: &str, b: &str| {
            if a.is_empty() {
                b.to_owned()
            } else {
                a.to_owned()
            }
        };
        let head_title = or(&m.seo_title, &e.title);
        let description = or(&m.description, &e.summary);
        // A site path is under the site's base, like the entry's own address.
        let base = self.site.home.trim_end_matches('/');
        let canonical = if m.canonical.is_empty() {
            self.absolute(&e.url)
        } else if m.canonical.starts_with('/') {
            self.absolute(&format!("{base}{}", m.canonical))
        } else {
            m.canonical.clone()
        };
        let og_image = if m.og_image.starts_with('/') {
            self.absolute(&format!("{base}{}", m.og_image))
        } else {
            m.og_image.clone()
        };
        let twitter_card = if !m.twitter_card.is_empty() {
            m.twitter_card.clone()
        } else if og_image.is_empty() {
            "summary".to_owned()
        } else {
            "summary_large_image".to_owned()
        };
        Head {
            og_title: or(&m.og_title, &head_title),
            og_description: or(&m.og_description, &description),
            title: head_title,
            description,
            canonical,
            robots: m.robots.clone(),
            og_type: if e.kind == "post" {
                "article"
            } else {
                "website"
            }
            .to_owned(),
            og_image,
            twitter_card,
        }
    }

    /// The home page's view: a page without an entry, whose canonical
    /// address is the site's root.
    pub(crate) fn home(&self, title: &str) -> Page {
        let mut page = self.page(title, None, "", None);
        page.head = Arc::new(Head {
            canonical: self.absolute(&self.site.home),
            ..(*page.head).clone()
        });
        page
    }

    /// A page view.
    pub(crate) fn page(
        &self,
        title: &str,
        entry: Option<Arc<Entry>>,
        message: &str,
        form: Option<Form>,
    ) -> Page {
        Page {
            site: self.site.clone(),
            head: Arc::new(self.head(title, entry.as_deref())),
            title: title.to_owned(),
            entry,
            posts: self.content.snapshot().posts(),
            message: message.to_owned(),
            form: form.map(Arc::new),
            editor: None,
            security: None,
        }
    }

    /// A security page view (the admin theme renders it).
    #[cfg_attr(not(feature = "store-nex"), allow(dead_code))]
    pub(crate) fn security_page(&self, title: &str, security: Security) -> Page {
        Page {
            security: Some(Arc::new(security)),
            ..self.page(title, None, "", None)
        }
    }

    /// The site's name.
    #[cfg_attr(not(feature = "mfa"), allow(dead_code))]
    pub(crate) fn site_name(&self) -> &str {
        &self.site.name
    }

    /// An editor's page view.
    #[cfg_attr(not(feature = "store-nex"), allow(dead_code))]
    pub(crate) fn editor_page(&self, title: &str, editor: Editor) -> Page {
        Page {
            editor: Some(Arc::new(editor)),
            ..self.page(title, None, "", None)
        }
    }
}

/// Ends a handler with `status` (400 to 599) and the application error code
/// `code`, its error page showing `message` instead of the configured or
/// generic one; the code and the message go to the log too. A status
/// outside 400 to 599 is a 500 with the code `site.bad_status`.
///
/// ```ignore
/// return Err(site::fail(cx, 410, "content.gone", "This post was taken down."));
/// ```
pub fn fail<I, E>(
    cx: &web_net::Context<'_, I, E>,
    status: u16,
    code: &'static str,
    message: &str,
) -> web_net::Error
where
    I: web_net::Identity,
    E: web_net::Render,
{
    let reference = cx.id().to_string();
    if !(400..=599).contains(&status) {
        gateway_io::note::note(
            "site.bad_status",
            &format!("site::fail was given status {status}"),
            &reference,
        );
        return web_net::Error::internal("site.bad_status");
    }
    let message = message.split_whitespace().collect::<Vec<_>>().join(" ");
    crate::events::fail_with(&reference, &message);
    gateway_io::note::note(code, &message, &reference);
    web_net::Error::new(status, code)
}

/// The site's builder settings every gate shares: hosts, base, assets, the
/// theme's files, the sign-in page, health and readiness.
pub(crate) fn configure<G: web_net::Gate>(
    mut builder: web_net::Builder<G, SiteEngine>,
    settings: &SiteSettings,
    ready: impl Fn() -> bool + Send + Sync + 'static,
) -> web_net::Builder<G, SiteEngine> {
    let base = settings.base.trim_end_matches('/');
    if settings.any_host {
        // The host router has picked this site already; `hosts` still names
        // the canonical host (the origin, the sign-in redirect).
        builder = builder.any_host();
    } else {
        if settings.hosts.is_empty() {
            builder = builder.development();
        }
        for host in &settings.hosts {
            builder = builder.host(host);
        }
    }
    if !base.is_empty() {
        builder = builder.base(base);
    }
    if let Some(dir) = &settings.assets {
        builder = builder.assets(Assets::new("/static", dir.clone()));
    }
    builder = match &settings.admin_theme {
        AdminSource::Builtin => builder.route(
            get(
                "/admin/static/admin.css",
                |cx: &mut Context<'_, G::Identity, SiteEngine>| {
                    cx.set_header("cache-control", "public, max-age=3600");
                    cx.bytes(200, "text/css; charset=utf-8", ADMIN_CSS.as_bytes())
                },
            )
            .public()
            .name("admin-css"),
        ),
        AdminSource::Folder(dir) => {
            builder.assets(Assets::new("/admin/static", dir.join("static")))
        }
    };
    builder
        .assets(Assets::new("/theme", settings.theme.join("static")))
        .sign_in("/sign-in")
        .events(crate::events::SiteEvents)
        .health("/health")
        .ready("/ready", ready)
}

/// The public content routes (home, posts, about, other pages), for any
/// gate.
/// How long guests' copies of the content pages are kept, in browsers and in
/// the core's guest cache (which also drops them whenever the content
/// changes).
const GUEST_PAGES: CachePolicy = CachePolicy::Guests { max_age: 60 };

pub(crate) fn content_routes<I: web_net::Identity, R: Send + Sync + 'static>(
    pages: &Pages,
) -> [Route<I, R, SiteEngine>; 4] {
    let p = pages.clone();
    let home = get("/", move |cx: &mut Context<'_, I, SiteEngine>| {
        cx.render(&p.home("Home"))
    })
    .public()
    .cache(GUEST_PAGES)
    .template("home")
    .name("home");

    let p = pages.clone();
    let post_page = get(
        "/posts/:slug",
        move |cx: &mut Context<'_, I, SiteEngine>| {
            let slug = cx.param("slug")?.into_owned();
            let Some(entry) = p.content.snapshot().get(Kind::Post, &slug) else {
                return Err(web_net::Error::not_found("post.unknown"));
            };
            let view = p.page(&entry.title, Some(entry.clone()), "", None);
            cx.render(&view)
        },
    )
    .public()
    .cache(GUEST_PAGES)
    .template("post")
    .name("post");

    let p = pages.clone();
    let about = get("/about", move |cx: &mut Context<'_, I, SiteEngine>| {
        let entry = p.content.snapshot().get(Kind::Page, "about");
        cx.render(&p.page("About", entry, "Nothing here yet.", None))
    })
    .public()
    .cache(GUEST_PAGES)
    .template("page")
    .name("about");

    // Every other page at its own path; the site's own paths are tried first.
    let p = pages.clone();
    let page = get("/:slug", move |cx: &mut Context<'_, I, SiteEngine>| {
        let slug = cx.param("slug")?.into_owned();
        let Some(entry) = p.content.snapshot().get(Kind::Page, &slug) else {
            return Err(web_net::Error::not_found("page.unknown"));
        };
        let view = p.page(&entry.title, Some(entry.clone()), "", None);
        cx.render(&view)
    })
    .public()
    .cache(GUEST_PAGES)
    .template("page")
    .name("page");
    [home, post_page, about, page]
}

/// The site behind the gatekeeper (accounts and sessions in memory).
#[cfg(feature = "gatekeeper")]
mod gatekeeper_site {
    use std::sync::Arc;

    use gateway_io::gatekeeper::gatekeeper_io::{Gatekeeper, Login, LoginForm, Refusal, Rule};
    use gateway_io::gatekeeper::{GatekeeperGate, Session, cookie_lines, visit};
    use web_net::form_net::{self, Secret};
    use web_net::{App, Context, Route, get, post};

    use super::{Pages, SiteSettings, configure, content_routes, query_value};
    use crate::auth::ACCOUNT_READ;
    use crate::content::Content;
    use crate::theme::{Form, SiteEngine};

    /// A handler's context on this site.
    pub type SiteCx<'a> = Context<'a, Session, SiteEngine>;

    /// The site's app type.
    pub type SiteApp = App<GatekeeperGate, SiteEngine>;

    /// A route on this site.
    pub type SiteRoute = Route<Session, Rule, SiteEngine>;

    form_net::form! {
        /// The sign-in form.
        struct SignIn {
            email: String,
            password: Secret,
            csrf_token: String,
        }
    }

    form_net::form! {
        /// The sign-out button.
        struct SignOut {
            csrf_token: String,
        }
    }

    /// The handler error for a gate refusal: its status, a stable code.
    fn refused(r: &Refusal) -> web_net::Error {
        web_net::Error::new(r.status(), "gate.refused")
    }

    /// Builds the site behind `gatekeeper`, rendering with `engine`.
    pub fn build(
        gatekeeper: Arc<Gatekeeper>,
        content: Content,
        engine: SiteEngine,
        settings: &SiteSettings,
        ready: impl Fn() -> bool + Send + Sync + 'static,
    ) -> Result<SiteApp, String> {
        let pages = Pages::new(settings, content);
        let members = Rule::signed_in()
            .needs(gatekeeper.schema(), &[ACCOUNT_READ])
            .map_err(|e| format!("site rule: {e}"))?;
        let builder = configure(
            App::with_gate(GatekeeperGate(gatekeeper.clone())).render(engine),
            settings,
            ready,
        );

        let p = pages.clone();
        let gk = gatekeeper.clone();
        let account: SiteRoute = get("/account", move |cx: &mut SiteCx<'_>| {
            let cleared = gk
                .authorize(cx.identity().identified().clone(), &Rule::signed_in())
                .map_err(|r| refused(&r))?;
            let csrf = gk.csrf_token(&cleared).map_err(|r| refused(&r))?;
            let user = cleared.user().map(|u| u.to_string()).unwrap_or_default();
            let form = Form {
                action: cx.url("/sign-out")?,
                csrf,
                user,
                ..Form::default()
            };
            cx.render(&p.page("Account", None, "", Some(form)))
        })
        .allow(members)
        .template("account")
        .name("account");

        // The sign-in form: a token bound to the visitor's pre-session cookie.
        let sign_in_form = {
            let gk = gatekeeper.clone();
            let p = pages.clone();
            move |cx: &mut SiteCx<'_>, error: &str, email: &str| -> web_net::Result {
                let lines = cookie_lines(cx.request());
                let v = visit(cx.request(), &lines);
                let cleared = gk
                    .authorize(cx.identity().identified().clone(), &Rule::guest_only())
                    .map_err(|r| refused(&r))?;
                let token = gk.login_form(&cleared, &v).map_err(|r| refused(&r))?;
                let next = cx.next_path()?;
                let mut action = cx.url("/sign-in")?;
                if let Some(next) = next {
                    action.push_str("?next=");
                    action.push_str(&query_value(&cx.url(&next)?));
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
                cx.render(&p.page("Sign in", None, "", Some(form)))
            }
        };

        let show = sign_in_form.clone();
        let sign_in: SiteRoute = get("/sign-in", move |cx: &mut SiteCx<'_>| {
            if !cx.identity().identified().is_guest() {
                let next = cx.next_path()?.unwrap_or_else(|| "/account".to_owned());
                return cx.redirect(303, &next);
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
                return cx.redirect(303, &next);
            }
            let form: SignIn = cx.form()?;
            let lines = cookie_lines(cx.request());
            let v = visit(cx.request(), &lines);
            let cleared = gk
                .authorize(cx.identity().identified().clone(), &Rule::guest_only())
                .map_err(|r| refused(&r))?;
            // Argon2id runs here, on this worker (see the limits).
            let login = gk.login(
                &cleared,
                &v,
                LoginForm {
                    identifier: &form.email,
                    password: form.password.expose(),
                    csrf: form.csrf_token.as_bytes(),
                },
            );
            match login {
                Login::SignedIn(signed_in) => {
                    for c in signed_in.set_cookies() {
                        cx.set_header("set-cookie", c);
                    }
                    cx.redirect(303, &next)
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
                .logout(cleared, &v, form.csrf_token.as_bytes())
                .map_err(|r| refused(&r))?;
            if let Some(c) = out.set_cookie() {
                cx.set_header("set-cookie", c);
            }
            cx.redirect(303, "/")
        })
        .allow(Rule::signed_in())
        .csrf_exempt("the gatekeeper checks the session-bound token and the origin itself")
        .name("sign-out");

        let [home, post_page, about, page] = content_routes::<Session, Rule>(&pages);
        builder
            .route(home)
            .route(post_page)
            .route(about)
            .route(page)
            .route(account)
            .route(sign_in)
            .route(sign_in_post)
            .route(sign_out)
            .build()
            .map_err(|e| format!("site: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{Draft, Kind, Manifest, Meta};

    fn pages(meta: Meta) -> (Pages, Arc<Entry>) {
        let config = wasp_core::suite::config::Config::from_text(
            "[site]\nhosts = [\"example.com\"]\nbase = \"/blog\"\n",
        )
        .expect("config");
        let settings = SiteSettings::from_config(&config).expect("settings");
        let mut manifest = Manifest::with_base("/blog");
        manifest
            .save(&Draft {
                kind: Kind::Page,
                slug: "about",
                title: "About",
                summary: "Who we are.",
                body: "Text.",
                date: "",
                meta,
                fields: Vec::new(),
            })
            .expect("save");
        let entry = manifest.get(Kind::Page, "about").expect("entry");
        (Pages::new(&settings, Content::new(manifest)), entry)
    }

    #[test]
    fn addresses_in_the_head_are_absolute_under_the_base() {
        let (p, entry) = pages(Meta::default());
        let head = p.page("About", Some(entry), "", None).head;
        assert_eq!(head.canonical, "https://example.com/blog/about");
        assert_eq!(head.description, "Who we are.");
        assert_eq!(head.og_type, "website");
        assert_eq!(p.home("Home").head.canonical, "https://example.com/blog/");

        let (p, entry) = pages(Meta {
            canonical: "/team".into(),
            og_image: "https://cdn.example.net/card.png".into(),
            ..Meta::default()
        });
        let head = p.page("About", Some(entry), "", None).head;
        assert_eq!(head.canonical, "https://example.com/blog/team");
        assert_eq!(head.og_image, "https://cdn.example.net/card.png");
        assert_eq!(head.twitter_card, "summary_large_image");
    }
}
