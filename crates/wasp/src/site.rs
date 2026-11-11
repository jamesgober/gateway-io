//! The site: web-net on the gateway, content from the in-memory manifest,
//! pages and error pages rendered by the theme (build-path step 5).
//!
//! | Path | Rule | Template | What |
//! |---|---|---|---|
//! | `/` | public | `home` | the post listing, newest first |
//! | `/posts/:slug` | public | `post` | a post; 404 (themed) when there is none |
//! | `/about` | public | `page` | the `about` page from the manifest |
//! | `/account` | signed in | `page` | guests are sent to `/sign-in` (303) |
//! | `/sign-in` | public | `page` | a placeholder until sign-in exists (step 7) |
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

use gateway_io::{WaspGate, Who};
use wasp_core::suite::config::Config;
use wasp_core::{Access, PermSet, Rule};
use web_net::{App, Assets, BuildError, Cx, Route, get};

use crate::content::{Kind, Manifest};
use crate::theme::{Page, SiteEngine, SiteInfo};

/// The permission the account page needs (any signed-in account holds it).
pub const MEMBER: PermSet = PermSet(1);

/// A handler's context on this site.
pub type SiteCx<'a> = Cx<'a, Who, SiteEngine>;

/// The site's app type.
pub type SiteApp = App<WaspGate, SiteEngine>;

/// A route on this site.
pub type SiteRoute = Route<Who, Rule, SiteEngine>;

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
            base: config.get_or("site.base", d.base).map_err(e)?,
            hosts: config.get_or("site.hosts", d.hosts).map_err(e)?,
            assets: config.get("site.assets").map_err(e)?,
            theme: config.get_or("site.theme", d.theme).map_err(e)?,
            theme_poll: config.get_or("site.theme_poll", d.theme_poll).map_err(e)?,
        })
    }
}

/// Builds the site over the core's access gate, rendering with `engine`.
pub fn build(
    access: Access,
    manifest: Manifest,
    engine: SiteEngine,
    settings: &SiteSettings,
) -> Result<SiteApp, BuildError> {
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
        move |title: &str, entry, message: &str| Page {
            site: site.clone(),
            title: title.to_owned(),
            entry,
            posts: manifest.posts(),
            message: message.to_owned(),
        }
    };

    let mut builder = App::with(WaspGate::new(access), engine);
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
        cx.render(&p("Home", None, ""))
    })
    .public()
    .template("home")
    .name("home");

    let p = page.clone();
    let m = manifest.clone();
    let post: SiteRoute = get("/posts/:slug", move |cx: &mut SiteCx<'_>| {
        let slug = cx.param("slug").map(|s| s.into_owned()).unwrap_or_default();
        let Some(entry) = m.get(Kind::Post, &slug) else {
            return Err(web_net::Error::not_found("post.unknown"));
        };
        let view = p(&entry.title, Some(entry.clone()), "");
        cx.render(&view)
    })
    .public()
    .template("post")
    .name("post");

    let p = page.clone();
    let m = manifest.clone();
    let about: SiteRoute = get("/about", move |cx: &mut SiteCx<'_>| {
        let entry = m.get(Kind::Page, "about");
        cx.render(&p("About", entry, "Nothing here yet."))
    })
    .public()
    .template("page")
    .name("about");

    let p = page.clone();
    let account: SiteRoute = get("/account", move |cx: &mut SiteCx<'_>| {
        cx.render(&p("Account", None, "Signed in."))
    })
    .allow(Rule::needs(2, MEMBER))
    .template("page")
    .name("account");

    let p = page;
    let sign_in: SiteRoute = get("/sign-in", move |cx: &mut SiteCx<'_>| {
        cx.render(&p(
            "Sign in",
            None,
            "Sign-in arrives with the gates (step 7).",
        ))
    })
    .public()
    .template("page")
    .name("sign-in");

    builder
        .sign_in("/sign-in")
        .health("/health")
        .route(home)
        .route(post)
        .route(about)
        .route(account)
        .route(sign_in)
        .build()
}
