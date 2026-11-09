//! The first site: web-net on the gateway, content from an in-memory map,
//! templates as plain strings (build-path step 4).
//!
//! | Path | Rule | What |
//! |---|---|---|
//! | `/` | public | the home page, listing the posts |
//! | `/posts/:slug` | public | a post, 404 when the map has no such slug |
//! | `/about` | public | a static page |
//! | `/account` | signed in | guests are sent to `/sign-in` (303) |
//! | `/sign-in` | public | a placeholder until sign-in exists (step 7) |
//! | `/health` | none | liveness, answered before the gate |
//!
//! Configuration (`[site]`): `base` (the folder the site lives under, for
//! example `/blog`), `hosts` (the site's hosts; none means a development site
//! answering localhost), `assets` (a folder served under `/static`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use gateway_io::{WaspGate, Who};
use wasp_core::suite::config::Config;
use wasp_core::{Access, PermSet, Rule};
use web_net::{App, Assets, BuildError, Cx, Route, get};

/// The permission the account page needs (any signed-in account holds it).
pub const MEMBER: PermSet = PermSet(1);

/// One post: title and body (plain text).
#[derive(Clone, Debug)]
pub struct Post {
    /// The title.
    pub title: &'static str,
    /// The body, plain text.
    pub body: &'static str,
}

/// The site's content, in memory until a content store exists (step 8).
#[derive(Clone, Debug, Default)]
pub struct Content {
    posts: BTreeMap<&'static str, Post>,
}

impl Content {
    /// The sample content.
    #[must_use]
    pub fn sample() -> Content {
        let mut posts = BTreeMap::new();
        posts.insert(
            "hello-world",
            Post {
                title: "Hello, world",
                body: "The first page served through the gateway, the core, and the web service.",
            },
        );
        posts.insert(
            "the-passport",
            Post {
                title: "The passport",
                body: "Every request carries one from the pool to the reply, and back, wiped.",
            },
        );
        Content { posts }
    }
}

/// Where the site lives and what it serves.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SiteSettings {
    /// The folder the site is installed under (`/blog`), or empty.
    pub base: String,
    /// The site's hosts, canonical first; empty for a development site.
    pub hosts: Vec<String>,
    /// A folder served under `/static`.
    pub assets: Option<PathBuf>,
}

impl SiteSettings {
    /// Reads `[site]`; every key is optional.
    pub fn from_config(config: &Config) -> Result<SiteSettings, String> {
        let base: String = config
            .get_or("site.base", String::new())
            .map_err(|e| e.to_string())?;
        let hosts: Vec<String> = config
            .get_or("site.hosts", Vec::new())
            .map_err(|e| e.to_string())?;
        let assets: Option<PathBuf> = config.get("site.assets").map_err(|e| e.to_string())?;
        Ok(SiteSettings {
            base,
            hosts,
            assets,
        })
    }
}

/// HTML-escapes `text`.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The page template: a plain string.
fn page(cx: &Cx<'_, Who>, title: &str, body: &str) -> String {
    let home = escape(&cx.url("/"));
    let about = escape(&cx.url("/about"));
    let account = escape(&cx.url("/account"));
    format!(
        "<!doctype html><html lang=en><meta charset=utf-8><title>{t}</title>\
         <nav><a href=\"{home}\">Home</a> | <a href=\"{about}\">About</a> | <a href=\"{account}\">Account</a></nav>\
         <main><h1>{t}</h1>{body}</main></html>",
        t = escape(title)
    )
}

/// Builds the site over the core's access gate.
pub fn build(
    access: Access,
    content: Content,
    settings: &SiteSettings,
) -> Result<App<WaspGate>, BuildError> {
    let content = Arc::new(content);
    let mut builder = App::with_gate(WaspGate::new(access));
    if settings.hosts.is_empty() {
        builder = builder.development();
    }
    for host in &settings.hosts {
        builder = builder.host(host);
    }
    if !settings.base.is_empty() {
        builder = builder.base(&settings.base);
    }
    if let Some(dir) = &settings.assets {
        builder = builder.assets(Assets::new("/static", dir.clone()));
    }

    let list = content.clone();
    let home: Route<Who, Rule> = get("/", move |cx: &mut Cx<'_, Who>| {
        let mut items = String::from("<ul>");
        for (slug, post) in &list.posts {
            let href = escape(&cx.url(&format!("/posts/{slug}")));
            items.push_str(&format!(
                "<li><a href=\"{href}\">{}</a></li>",
                escape(post.title)
            ));
        }
        items.push_str("</ul>");
        let html = page(cx, "Home", &items);
        cx.html(200, &html);
        Ok(())
    })
    .public()
    .name("home");

    let posts = content.clone();
    let post: Route<Who, Rule> = get("/posts/:slug", move |cx: &mut Cx<'_, Who>| {
        let slug = cx.param("slug").map(|s| s.into_owned()).unwrap_or_default();
        let Some(post) = posts.posts.get(slug.as_str()) else {
            return Err(web_net::Error::not_found("post.unknown"));
        };
        let html = page(cx, post.title, &format!("<p>{}</p>", escape(post.body)));
        cx.html(200, &html);
        Ok(())
    })
    .public()
    .name("post");

    let about: Route<Who, Rule> = get("/about", |cx: &mut Cx<'_, Who>| {
        let html = page(
            cx,
            "About",
            "<p>A site in memory, on the platform's walking skeleton.</p>",
        );
        cx.html(200, &html);
        Ok(())
    })
    .public()
    .name("about");

    let account: Route<Who, Rule> = get("/account", |cx: &mut Cx<'_, Who>| {
        let html = page(cx, "Account", "<p>Signed in.</p>");
        cx.html(200, &html);
        Ok(())
    })
    .allow(Rule::needs(2, MEMBER))
    .name("account");

    let sign_in: Route<Who, Rule> = get("/sign-in", |cx: &mut Cx<'_, Who>| {
        let html = page(
            cx,
            "Sign in",
            "<p>Sign-in arrives with the gates (step 7).</p>",
        );
        cx.html(200, &html);
        Ok(())
    })
    .public()
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
