//! The API: JSON routes under a prefix (`[api] prefix`, default `/api/v1`),
//! on a site with nex-db accounts.
//!
//! | Path | Who | What |
//! |---|---|---|
//! | `GET <prefix>/me` | signed in; a key needs `account:read` | the account: id, email, roles, how it is signed in |
//! | `GET <prefix>/posts` | anyone | the posts, newest first (`limit` 1 to 100, default 20; `offset`) |
//! | `GET <prefix>/posts/:slug` | anyone | a post |
//! | `GET <prefix>/pages/:slug` | anyone | a page |
//!
//! A browser is signed in by its session cookie, a program by
//! `Authorization: Bearer <key>`. A bearer key that does not count makes
//! every API request 401 `api.bad_key`. An error is
//! `{"status":..,"code":..,"message":..,"reference":..}`, the code, message
//! and reference going to the log as a page's do; anything else under the
//! prefix is 404 `api.not_found`.

use wasp_core::suite::config::Config;

/// The API's settings for one site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiSettings {
    /// Whether the site has the API.
    pub enabled: bool,
    /// Where it lives, under the site's base (`/api/v1`).
    pub prefix: String,
}

impl Default for ApiSettings {
    fn default() -> ApiSettings {
        ApiSettings {
            enabled: false,
            prefix: DEFAULT_PREFIX.to_owned(),
        }
    }
}

/// The prefix when none is set.
pub const DEFAULT_PREFIX: &str = "/api/v1";

/// What each caller may spend on API requests: `per_second`, in bursts of
/// `burst`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApiBudget {
    /// Requests a second; 0 for no budget.
    pub per_second: u32,
    /// The most at once after a quiet spell.
    pub burst: u32,
}

/// Paths the site uses itself, which the API never covers.
const TAKEN: &[&str] = &[
    "/admin",
    "/account",
    "/sign-in",
    "/sign-out",
    "/theme",
    "/static",
    "/health",
    "/ready",
    "/posts",
    "/about",
];

/// `path` checked as [`checked_prefix`] checks a prefix: a path the site
/// does not use itself.
pub(crate) fn checked_path(path: &str, key: &str) -> Result<String, String> {
    checked_prefix(path, key)
}

/// `prefix`, or why it is refused (named by `key`).
fn checked_prefix(prefix: &str, key: &str) -> Result<String, String> {
    let ok = prefix.len() > 1
        && prefix.len() <= 64
        && prefix.starts_with('/')
        && !prefix.ends_with('/')
        && prefix[1..].split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        });
    if !ok {
        return Err(format!(
            "{key} must be like `/api/v1` (a leading `/`, no trailing `/`, letters, digits and `-._~`), not `{prefix}`"
        ));
    }
    let lower = prefix.to_ascii_lowercase();
    if let Some(t) = TAKEN.iter().find(|t| {
        lower
            .strip_prefix(**t)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    }) {
        return Err(format!(
            "{key} `{prefix}` is under `{t}`, which the site uses"
        ));
    }
    Ok(prefix.to_owned())
}

impl ApiSettings {
    /// Reads `[api]` (`enabled`, `prefix`), each key optional. The API is
    /// off until `enabled = true`: a site that does not use it does not
    /// expose it. With `gatekeeper` (no nex-db accounts) there is no API,
    /// and `enabled = true` is refused.
    pub fn from_config(config: &Config, gatekeeper: bool) -> Result<ApiSettings, String> {
        let api = ApiSettings::read(config, "api", &ApiSettings::default())?;
        if gatekeeper && api.enabled {
            return Err(
                "api.enabled needs nex-db accounts (auth.store = \"nex\"): the API's keys are kept there"
                    .to_owned(),
            );
        }
        Ok(api)
    }

    /// The settings `section` (`api`, or `host.<name>.api`) gives, each key
    /// falling back to `base`.
    pub fn read(config: &Config, section: &str, base: &ApiSettings) -> Result<ApiSettings, String> {
        let e = |e: wasp_core::suite::Error| e.to_string();
        let key = format!("{section}.prefix");
        let prefix: String = config.get_or(&key, base.prefix.clone()).map_err(e)?;
        Ok(ApiSettings {
            enabled: config
                .get_or(&format!("{section}.enabled"), base.enabled)
                .map_err(e)?,
            prefix: checked_prefix(&prefix, &key)?,
        })
    }
}

impl ApiBudget {
    /// Reads `[api] rate` (default 10 a second; 0 turns the budget off) and
    /// `burst` (default twice the rate, at least the rate).
    pub fn from_config(config: &Config) -> Result<ApiBudget, String> {
        let e = |e: wasp_core::suite::Error| e.to_string();
        let rate: i64 = config.get_or("api.rate", 10).map_err(e)?;
        let per_second = u32::try_from(rate)
            .ok()
            .filter(|r| *r <= 100_000)
            .ok_or_else(|| format!("api.rate must be 0 to 100000 requests a second, not {rate}"))?;
        let burst: i64 = config
            .get_or("api.burst", i64::from(per_second) * 2)
            .map_err(e)?;
        let burst = u32::try_from(burst)
            .ok()
            .filter(|b| *b >= per_second && *b <= 1_000_000)
            .ok_or_else(|| {
                format!("api.burst must be at least api.rate ({per_second}) and at most 1000000, not {burst}")
            })?;
        Ok(ApiBudget { per_second, burst })
    }
}

/// A JSON object, written as it is built.
#[cfg(feature = "store-nex")]
pub(crate) struct Obj {
    out: String,
    first: bool,
}

#[cfg(feature = "store-nex")]
impl Obj {
    pub(crate) fn new() -> Obj {
        Obj {
            out: String::from("{"),
            first: true,
        }
    }

    fn key(&mut self, k: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        push_str(&mut self.out, k);
        self.out.push(':');
    }

    /// `k` is the string `v`.
    pub(crate) fn str(mut self, k: &str, v: &str) -> Obj {
        self.key(k);
        push_str(&mut self.out, v);
        self
    }

    /// `k` is the number `v`.
    pub(crate) fn num(mut self, k: &str, v: u64) -> Obj {
        self.key(k);
        self.out.push_str(&v.to_string());
        self
    }

    /// `k` is `null`.
    pub(crate) fn null(mut self, k: &str) -> Obj {
        self.key(k);
        self.out.push_str("null");
        self
    }

    /// `k` is a list of strings.
    pub(crate) fn strs<'a>(mut self, k: &str, v: impl IntoIterator<Item = &'a str>) -> Obj {
        self.key(k);
        self.out.push('[');
        for (i, s) in v.into_iter().enumerate() {
            if i > 0 {
                self.out.push(',');
            }
            push_str(&mut self.out, s);
        }
        self.out.push(']');
        self
    }

    /// `k` is JSON already written (an object, a list).
    pub(crate) fn raw(mut self, k: &str, json: &str) -> Obj {
        self.key(k);
        self.out.push_str(json);
        self
    }

    pub(crate) fn end(mut self) -> String {
        self.out.push('}');
        self.out
    }
}

/// `items` as a JSON list.
#[cfg(feature = "store-nex")]
pub(crate) fn list(items: impl IntoIterator<Item = String>) -> String {
    let mut out = String::from("[");
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&item);
    }
    out.push(']');
    out
}

/// `s` as a JSON string.
#[cfg(feature = "store-nex")]
fn push_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // `<` too, so a reply never reads as markup if a browser is
            // ever talked into rendering it.
            c if (c as u32) < 0x20 || c == '<' || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(feature = "store-nex")]
pub(crate) use routes::routes;

#[cfg(feature = "store-nex")]
mod routes {
    use wasp_core::Subject;
    use web_net::Route;

    use super::{ApiSettings, Obj, list};
    use crate::content::{Entry, Kind, Meta};
    use crate::nex::{NexAuth, Scopes, Via};
    use crate::site::Pages;
    use crate::site_nex::{MEMBER, NexCx, NexRoute, NexWho};

    /// The most posts one listing gives.
    const MAX_LIMIT: usize = 100;

    /// The posts one listing gives when `limit` is not set.
    const DEFAULT_LIMIT: usize = 20;

    /// A JSON reply, never kept by a cache.
    fn answer(cx: &mut NexCx<'_>, status: u16, body: &str) -> web_net::Result {
        cx.set_header("cache-control", "no-store");
        cx.set_header("x-content-type-options", "nosniff");
        cx.bytes(status, "application/json", body.as_bytes())
    }

    /// An error reply: the status, the application code, the message and
    /// the request's reference, which go to the log as `site::fail`'s do.
    fn fail(cx: &mut NexCx<'_>, status: u16, code: &'static str, message: &str) -> web_net::Result {
        let reference = cx.id().to_string();
        gateway_io::note::note(code, message, &reference);
        match code {
            "api.bad_key" => {
                cx.set_header("www-authenticate", "Bearer error=\"invalid_token\"");
            }
            _ if status == 401 => {
                cx.set_header("www-authenticate", "Bearer");
            }
            _ => {}
        }
        let body = Obj::new()
            .num("status", u64::from(status))
            .str("code", code)
            .str("message", message)
            .str("reference", &reference)
            .end();
        answer(cx, status, &body)
    }

    /// Who is calling: a guest, a browser's account, or a key's account
    /// with its scopes; the error reply for a key that does not count.
    enum Caller {
        Guest,
        Browser(u128),
        Key(u128, Scopes),
    }

    fn caller(cx: &mut NexCx<'_>) -> Result<Caller, web_net::Result> {
        let who: NexWho = *cx.identity();
        match who.via() {
            Via::BadKey => Err(fail(
                cx,
                401,
                "api.bad_key",
                "The API key is not valid. It may have expired or been revoked.",
            )),
            Via::KeyRefused => Err(fail(
                cx,
                403,
                "api.account_disabled",
                "The API key's account cannot be used now.",
            )),
            via => Ok(match (who.identity.subject(), via) {
                (Subject::User(u), Via::Key(scopes)) => Caller::Key(u.0, scopes),
                (Subject::User(u), _) => Caller::Browser(u.0),
                _ => Caller::Guest,
            }),
        }
    }

    /// A post or page in a listing.
    fn summary(e: &Entry) -> String {
        Obj::new()
            .str("slug", &e.slug)
            .str("title", &e.title)
            .str("url", &e.url)
            .str("summary", &e.summary)
            .str("date", &e.date)
            .end()
    }

    /// A post or page in full.
    fn full(e: &Entry) -> String {
        let meta = Meta::FIELDS
            .iter()
            .fold(Obj::new(), |o, name| {
                o.str(name, e.meta.get(name).unwrap_or(""))
            })
            .end();
        let fields = list(e.fields.iter().map(|f| {
            Obj::new()
                .str("name", &f.name)
                .str("label", &f.label)
                .str("type", &f.kind)
                .str("value", &f.value)
                .end()
        }));
        Obj::new()
            .str("kind", &e.kind)
            .str("slug", &e.slug)
            .str("title", &e.title)
            .str("url", &e.url)
            .str("summary", &e.summary)
            .str("date", &e.date)
            .str("body", &e.body)
            .str("text", &e.text)
            .raw("meta", &meta)
            .raw("fields", &fields)
            .end()
    }

    /// A number from the query, or the error reply.
    fn number(cx: &mut NexCx<'_>, name: &str, default: usize) -> Result<usize, web_net::Result> {
        let Ok(value) = cx.query(name) else {
            return Err(fail(cx, 400, "api.bad_query", "The query is not valid."));
        };
        match value {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| {
                fail(
                    cx,
                    400,
                    "api.bad_query",
                    &format!("`{name}` must be a whole number."),
                )
            }),
        }
    }

    /// A read-only API address: `f` answers `GET` (and `HEAD`), any other
    /// method gets a 405 in JSON.
    fn read<F>(pattern: String, name: &'static str, f: F) -> NexRoute
    where
        F: Fn(&mut NexCx<'_>) -> web_net::Result + Send + Sync + 'static,
    {
        let only_reads = |cx: &mut NexCx<'_>| {
            cx.set_header("allow", "GET, HEAD");
            fail(
                cx,
                405,
                "api.method",
                "This API address only reads: use GET.",
            )
        };
        Route::at(pattern)
            .get(f)
            .post(only_reads)
            .put(only_reads)
            .patch(only_reads)
            .delete(only_reads)
            .public()
            .csrf_exempt("other methods only get a 405; nothing is read or changed")
            .name(name)
    }

    /// The API's routes for one site.
    pub(crate) fn routes(api: &ApiSettings, pages: &Pages, auth: &NexAuth) -> Vec<NexRoute> {
        let at = |path: &str| format!("{}{path}", api.prefix);

        let a = auth.clone();
        let me = read(at("/me"), "api-me", move |cx: &mut NexCx<'_>| {
            let (user, scopes) = match caller(cx) {
                Err(reply) => return reply,
                Ok(Caller::Guest) => {
                    return fail(
                        cx,
                        401,
                        "api.sign_in",
                        "Sign in, or send an API key as `Authorization: Bearer <key>`.",
                    );
                }
                Ok(Caller::Key(_, scopes)) if !scopes.has("account:read") => {
                    return fail(
                        cx,
                        403,
                        "api.scope",
                        "This API key does not have the account:read scope.",
                    );
                }
                Ok(Caller::Key(u, scopes)) => (u, Some(scopes)),
                Ok(Caller::Browser(u)) => (u, None),
            };
            if !cx.identity().identity.perms().contains(MEMBER) {
                return fail(
                    cx,
                    403,
                    "api.forbidden",
                    "This account may not use the API.",
                );
            }
            let id = wasp_core::UserId(user);
            let unavailable = |cx: &mut NexCx<'_>| {
                fail(
                    cx,
                    503,
                    "auth.unavailable",
                    "The accounts cannot be read now. Try again shortly.",
                )
            };
            let Ok(email) = a.identifier_of(id) else {
                return unavailable(cx);
            };
            let Ok(roles) = a.role_names(id) else {
                return unavailable(cx);
            };
            let body = Obj::new()
                .str("id", &format!("{user:032x}"))
                .str("email", email.as_deref().unwrap_or(""))
                .strs("roles", roles.iter().map(String::as_str))
                .str(
                    "signed_in_with",
                    if scopes.is_some() { "key" } else { "session" },
                );
            let body = match scopes {
                Some(s) => body.strs("scopes", s.names()),
                None => body.null("scopes"),
            };
            answer(cx, 200, &body.end())
        });

        let p = pages.clone();
        let posts = read(at("/posts"), "api-posts", move |cx: &mut NexCx<'_>| {
            if let Err(reply) = caller(cx) {
                return reply;
            }
            let limit = match number(cx, "limit", DEFAULT_LIMIT) {
                Ok(n) if (1..=MAX_LIMIT).contains(&n) => n,
                Ok(_) => {
                    return fail(
                        cx,
                        400,
                        "api.bad_query",
                        &format!("`limit` must be 1 to {MAX_LIMIT}."),
                    );
                }
                Err(reply) => return reply,
            };
            let offset = match number(cx, "offset", 0) {
                Ok(n) => n,
                Err(reply) => return reply,
            };
            let all = p.content.snapshot().posts();
            let body = Obj::new()
                .raw(
                    "posts",
                    &list(all.iter().skip(offset).take(limit).map(|e| summary(e))),
                )
                .num("total", all.len() as u64)
                .num("limit", limit as u64)
                .num("offset", offset as u64)
                .end();
            answer(cx, 200, &body)
        });

        let one = |kind: Kind, path: &str, name: &'static str, missing: &'static str| {
            let p = pages.clone();
            read(at(path), name, move |cx: &mut NexCx<'_>| {
                if let Err(reply) = caller(cx) {
                    return reply;
                }
                let Ok(slug) = cx.param("slug") else {
                    return fail(cx, 404, missing, "There is nothing at this address.");
                };
                let slug = slug.into_owned();
                match p.content.snapshot().get(kind, &slug) {
                    Some(e) => answer(cx, 200, &full(&e)),
                    None => fail(cx, 404, missing, "There is nothing at this address."),
                }
            })
        };
        let post = one(Kind::Post, "/posts/:slug", "api-post", "post.unknown");
        let page = one(Kind::Page, "/pages/:slug", "api-page", "page.unknown");

        // Anything else under the prefix, by any method: JSON, not a page.
        let missing =
            |cx: &mut NexCx<'_>| fail(cx, 404, "api.not_found", "There is no such API address.");
        let rest = |pattern: String, name: &'static str| -> NexRoute {
            Route::at(pattern)
                .get(missing)
                .post(missing)
                .put(missing)
                .patch(missing)
                .delete(missing)
                .public()
                .csrf_exempt("answers 404 to everything; reads nothing and changes nothing")
                .name(name)
        };
        vec![
            me,
            posts,
            post,
            page,
            rest(api.prefix.clone(), "api-root"),
            rest(at("/*rest"), "api-missing"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "store-nex")]
    #[test]
    fn json_strings_are_escaped() {
        let o = Obj::new()
            .str("a", "q\"b\\s\n<x>\u{1}\u{2028}é")
            .num("n", 7)
            .null("z")
            .strs("l", ["x", "y"])
            .end();
        assert_eq!(
            o,
            "{\"a\":\"q\\\"b\\\\s\\n\\u003cx>\\u0001\\u2028é\",\"n\":7,\"z\":null,\"l\":[\"x\",\"y\"]}"
        );
        assert_eq!(list(Vec::<String>::new()), "[]");
    }

    #[test]
    fn prefixes_are_paths_the_site_does_not_use() {
        let ok = |p: &str| checked_prefix(p, "api.prefix");
        assert_eq!(ok("/api/v1").as_deref(), Ok("/api/v1"));
        assert!(ok("/json").is_ok());
        for bad in [
            "",
            "/",
            "api",
            "/api/",
            "/a//b",
            "/a/../b",
            "/a b",
            "/admin",
            "/admin/api",
            "/Account",
            "/posts",
            "/posts/api",
            "/sign-in",
            "/health",
        ] {
            assert!(ok(bad).is_err(), "{bad}");
        }
        assert!(ok("/administer").is_ok());
    }

    #[test]
    fn the_api_is_off_until_turned_on_and_with_nex_db_only() {
        let c = |t: &str| Config::from_text(t).expect("config");
        let off = ApiSettings::from_config(&c(""), false).expect("nex");
        assert!(!off.enabled, "off by default");
        let on = ApiSettings::from_config(&c("[api]\nenabled = true\n"), false).expect("on");
        assert!(on.enabled);
        assert_eq!(on.prefix, "/api/v1");
        assert!(
            !ApiSettings::from_config(&c(""), true)
                .expect("keeper")
                .enabled
        );
        assert!(ApiSettings::from_config(&c("[api]\nenabled = true\n"), true).is_err());
        let own = ApiSettings::read(
            &c("[host.blog.api]\nprefix = \"/json\"\n"),
            "host.blog.api",
            &on,
        )
        .expect("profile");
        assert_eq!(
            own,
            ApiSettings {
                enabled: true,
                prefix: "/json".into()
            }
        );
        let b = ApiBudget::from_config(&c("")).expect("budget");
        assert_eq!((b.per_second, b.burst), (10, 20));
        let b = ApiBudget::from_config(&c("[api]\nrate = 0\n")).expect("off");
        assert_eq!(b.per_second, 0);
        assert!(ApiBudget::from_config(&c("[api]\nrate = 5\nburst = 4\n")).is_err());
        assert!(ApiBudget::from_config(&c("[api]\nrate = -1\n")).is_err());
    }
}
