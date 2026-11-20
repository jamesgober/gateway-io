//! The site signing in and out through nex-db (`auth.store = "nex"`):
//! web-net's CSRF engine on every form, sessions that survive a restart, and
//! the content editor.

#![cfg(feature = "store-nex")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::nex::{EDITOR_ROLE, MEMBER_ROLE, NexAuth};
use wasp_core::GuestPages;
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

const EMAIL: &str = "ann@example.com";
const PASSWORD: &str = "correct horse battery staple";
const EDITOR: &str = "ed@example.com";

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("wasp-nexsite-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    TempDir(dir)
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn config(data: &Path) -> Config {
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[auth]\nstore = \"nex\"\n\n[content]\nstore = \"nex\"\n\n[nex]\npath = \"{}\"\n",
        slash(&theme),
        slash(&data.join("nex"))
    ))
    .expect("config")
}

/// Opens the site; the account exists once.
fn open(conf: &Config) -> (Door, SocketAddr) {
    let (door, addr, _) = open_cached(conf);
    (door, addr)
}

/// Opens the site, with its guest cache.
fn open_cached(conf: &Config) -> (Door, SocketAddr, Arc<GuestPages>) {
    let t = Instant::now();
    let wiring = loop {
        match wasp::wire(conf) {
            Ok(w) => break w,
            // A closed door's threads let go of the database a moment later.
            Err(e)
                if e.contains("in use by another process")
                    && t.elapsed() < Duration::from_secs(5) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("wiring: {e}"),
        }
    };
    let pages = wiring.guest_pages.clone();
    let auth = NexAuth::new(wiring.nex.clone().expect("nex-db"));
    auth.ensure_account(EMAIL, PASSWORD, &[MEMBER_ROLE])
        .expect("account");
    auth.ensure_account(EDITOR, PASSWORD, &[MEMBER_ROLE, EDITOR_ROLE])
        .expect("editor");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        ..Settings::default()
    };
    let door = Door::open(wiring.core, &settings, UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr, pages)
}

#[derive(Debug)]
struct Got {
    status: u16,
    fields: Vec<(String, String)>,
    body: String,
}

impl Got {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `name=value` pair of the last cookie set under `name`.
    fn cookie(&self, name: &str) -> Option<String> {
        self.fields
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.as_str())
            .rev()
            .find(|c| c.starts_with(&format!("{name}=")))
            .map(|c| c.split(';').next().unwrap_or_default().to_owned())
    }

    fn csrf(&self) -> String {
        let at = self
            .body
            .find("name=\"csrf_token\" value=\"")
            .expect("csrf field")
            + 25;
        let rest = &self.body[at..];
        rest[..rest.find('"').expect("end")].to_owned()
    }
}

fn send(addr: SocketAddr, request: &str) -> Got {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    s.write_all(request.as_bytes()).expect("write");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.get(9..12))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let fields = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Got {
        status,
        fields,
        body: body.to_owned(),
    }
}

fn get(addr: SocketAddr, target: &str, cookies: &[&str]) -> Got {
    let c = if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    };
    send(
        addr,
        &format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n{c}Connection: close\r\n\r\n"),
    )
}

fn post(addr: SocketAddr, target: &str, cookies: &[&str], site: &str, body: &str) -> Got {
    let c = if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    };
    send(
        addr,
        &format!(
            "POST {target} HTTP/1.1\r\nHost: localhost\r\n{c}Sec-Fetch-Site: {site}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn sign_in_body(email: &str, password: &str, csrf: &str) -> String {
    format!(
        "email={}&password={}&csrf_token={}",
        encode(email),
        encode(password),
        encode(csrf)
    )
}

/// The sign-in form for a fresh visitor: its pre-session cookie and token.
fn form(addr: SocketAddr) -> (String, String) {
    let first = get(addr, "/sign-in", &[]);
    assert_eq!(first.status, 303, "{first:?}");
    let pre = first.cookie("__Host-nexpre").expect("pre-session cookie");
    let page = get(addr, "/sign-in", &[&pre]);
    assert_eq!(page.status, 200, "{page:?}");
    (pre, page.csrf())
}

fn sign_in(addr: SocketAddr) -> String {
    sign_in_as(addr, EMAIL)
}

fn sign_in_as(addr: SocketAddr, email: &str) -> String {
    let (pre, csrf) = form(addr);
    let done = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body(email, PASSWORD, &csrf),
    );
    assert_eq!(done.status, 303, "{done:?}");
    done.cookie("__Host-nex").expect("session")
}

#[test]
fn sign_in_account_and_sign_out_through_nex_db() {
    let data = temp_dir("flow");
    let conf = config(&data.0);
    let (door, addr) = open(&conf);

    let account = get(addr, "/account", &[]);
    assert_eq!(account.status, 303);
    assert_eq!(account.field("location"), Some("/sign-in?next=/account"));

    // Refused: a wrong password (401, the form again), no token (403).
    let (pre, csrf) = form(addr);
    let wrong = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, "not it", &csrf),
    );
    assert_eq!(wrong.status, 401, "{wrong:?}");
    assert!(wrong.cookie("__Host-nex").is_none());
    let bare = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &format!("email={}&password={}", encode(EMAIL), encode(PASSWORD)),
    );
    assert_eq!(bare.status, 403, "no CSRF token: {bare:?}");

    // Signing in: 303 back, the session cookie set, the pre-session cleared.
    let done = post(
        addr,
        "/sign-in?next=/account",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, &csrf),
    );
    assert_eq!(done.status, 303, "{done:?}");
    assert_eq!(done.field("location"), Some("/account"));
    let sid = done.cookie("__Host-nex").expect("session");
    assert_eq!(
        done.cookie("__Host-nexpre").as_deref(),
        Some("__Host-nexpre=")
    );

    let page = get(addr, "/account", &[&sid]);
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains("Signed in as"), "{}", page.body);
    let csrf = page.csrf();

    // Sign-out from another site is refused; the session stays.
    let forged = post(
        addr,
        "/sign-out",
        &[&sid],
        "cross-site",
        &format!("csrf_token={}", encode(&csrf)),
    );
    assert_eq!(forged.status, 403, "{forged:?}");
    assert_eq!(get(addr, "/account", &[&sid]).status, 200);

    let out = post(
        addr,
        "/sign-out",
        &[&sid],
        "same-origin",
        &format!("csrf_token={}", encode(&csrf)),
    );
    assert_eq!(out.status, 303, "{out:?}");
    assert_eq!(out.cookie("__Host-nex").as_deref(), Some("__Host-nex="));
    let after = get(addr, "/account", &[&sid]);
    assert_eq!(after.status, 303, "the old cookie no longer signs in");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_nex_db_session_survives_a_restart() {
    let data = temp_dir("restart");
    let conf = config(&data.0);
    let (door, addr) = open(&conf);
    let sid = sign_in(addr);
    assert_eq!(get(addr, "/account", &[&sid]).status, 200);
    let _ = door.close(Duration::from_secs(2));

    let (door, addr) = open(&conf);
    let page = get(addr, "/account", &[&sid]);
    assert_eq!(
        page.status, 200,
        "still signed in after a restart: {page:?}"
    );
    let _ = door.close(Duration::from_secs(2));
}

/// The site's configuration with its master secret in `data`, as the
/// process keeps it in its data folder.
fn config_with_secret(data: &Path) -> Config {
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[auth]\nstore = \"nex\"\nsecret = \"{}\"\n\n[content]\nstore = \"nex\"\n\n[nex]\npath = \"{}\"\n",
        slash(&theme),
        slash(&data.join("gate.key")),
        slash(&data.join("nex"))
    ))
    .expect("config")
}

#[test]
fn a_form_opened_before_a_restart_posts_after_it() {
    let data = temp_dir("form-restart");
    let conf = config_with_secret(&data.0);
    let (door, addr) = open(&conf);
    let (pre, csrf) = form(addr);
    let _ = door.close(Duration::from_secs(2));

    let (door, addr) = open(&conf);
    let done = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, &csrf),
    );
    assert_eq!(done.status, 303, "the old form still signs in: {done:?}");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_refused_form_says_it_expired() {
    let data = temp_dir("form-expired");
    let conf = config(&data.0);
    let (door, addr) = open(&conf);
    // The master secret is kept beside the database, with the site.
    let key = data.0.join("gate.key");
    assert!(key.is_file(), "{}", key.display());
    let (pre, _) = form(addr);
    let refused = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, "not-a-token"),
    );
    assert_eq!(refused.status, 403, "{refused:?}");
    assert!(
        refused.body.contains("This form expired. Reload the page"),
        "{}",
        refused.body
    );
    assert!(
        !refused.body.contains("do not have access"),
        "{}",
        refused.body
    );

    // A post from another site is still refused as one.
    let forged = post(
        addr,
        "/sign-in",
        &[&pre],
        "cross-site",
        &sign_in_body(EMAIL, PASSWORD, "not-a-token"),
    );
    assert_eq!(forged.status, 403, "{forged:?}");
    assert!(!forged.body.contains("form expired"), "{}", forged.body);
    let _ = door.close(Duration::from_secs(2));
}

fn entry_body(kind: &str, slug: &str, was: &str, title: &str, body: &str, csrf: &str) -> String {
    format!(
        "kind={kind}&slug={}&was={}&title={}&summary=&date=2026-11-18&body={}&csrf_token={}",
        encode(slug),
        encode(was),
        encode(title),
        encode(body),
        encode(csrf)
    )
}

/// The `content` of the `<meta>` tag `attr`, or the `href` of the
/// canonical link, in a page.
fn meta_of(body: &str, attr: &str) -> Option<String> {
    let start = format!("{attr} content=\"");
    let at = body.find(&start)? + start.len();
    Some(body[at..at + body[at..].find('"')?].to_owned())
}

#[test]
fn the_editor_sets_the_search_and_sharing_fields() {
    let data = temp_dir("meta");
    let conf = config(&data.0);
    let (door, addr) = open(&conf);
    let ed = sign_in_as(addr, EDITOR);
    let csrf = get(addr, "/admin/new/post", &[&ed]).csrf();
    let save = |slug: &str, meta: &str| {
        post(
            addr,
            "/admin/save",
            &[&ed],
            "same-origin",
            &format!(
                "{}{meta}",
                entry_body("post", slug, "", "Plain title", "Body.", &csrf)
                    .replace("summary=&", "summary=The+summary&")
            ),
        )
    };
    let saved = save(
        "with-meta",
        "&seo_title=Search+title&description=A%0D%0Asearch+line&canonical=%2Felsewhere&robots=NoIndex+%2CNOFOLLOW&og_title=&og_description=&og_image=%2Fstatic%2Fcard.png&twitter_card=",
    );
    assert_eq!(saved.status, 303, "{saved:?}");
    let page = get(addr, "/posts/with-meta", &[]).body;
    assert!(page.contains("<title>Search title | "), "{page}");
    assert_eq!(
        meta_of(&page, "name=\"description\"").as_deref(),
        Some("A search line")
    );
    assert!(
        page.contains("<link rel=\"canonical\" href=\"/elsewhere\">"),
        "{page}"
    );
    assert_eq!(
        meta_of(&page, "name=\"robots\"").as_deref(),
        Some("noindex, nofollow")
    );
    assert_eq!(
        meta_of(&page, "property=\"og:type\"").as_deref(),
        Some("article")
    );
    assert_eq!(
        meta_of(&page, "property=\"og:title\"").as_deref(),
        Some("Search title")
    );
    assert_eq!(
        meta_of(&page, "property=\"og:description\"").as_deref(),
        Some("A search line")
    );
    assert_eq!(
        meta_of(&page, "property=\"og:image\"").as_deref(),
        Some("/static/card.png")
    );
    assert_eq!(
        meta_of(&page, "name=\"twitter:card\"").as_deref(),
        Some("summary_large_image")
    );
    // The editor shows them again.
    let form = get(addr, "/admin/edit/with-meta", &[&ed]).body;
    assert!(form.contains("value=\"Search title\""), "{form}");
    assert!(
        form.contains("<option value=\"noindex, nofollow\" selected>"),
        "{form}"
    );

    // Nothing set: the title and summary stand in, and the entry's own
    // address is canonical.
    assert_eq!(save("plain", "").status, 303);
    let page = get(addr, "/posts/plain", &[]).body;
    assert!(page.contains("<title>Plain title | "), "{page}");
    assert_eq!(
        meta_of(&page, "name=\"description\"").as_deref(),
        Some("The summary")
    );
    assert!(
        page.contains("<link rel=\"canonical\" href=\"/posts/plain\">"),
        "{page}"
    );
    assert!(meta_of(&page, "name=\"robots\"").is_none(), "{page}");
    assert_eq!(
        meta_of(&page, "property=\"og:title\"").as_deref(),
        Some("Plain title")
    );
    assert_eq!(
        meta_of(&page, "name=\"twitter:card\"").as_deref(),
        Some("summary")
    );
    // The home page names itself canonical.
    assert!(
        get(addr, "/", &[])
            .body
            .contains("<link rel=\"canonical\" href=\"/\">")
    );

    // A canonical address that is not one, or an unknown directive, is
    // refused with the form kept.
    for (bad, says) in [
        ("&canonical=javascript%3Aalert(1)", "canonical address"),
        ("&canonical=%2F%2Fevil.example", "canonical address"),
        ("&og_image=%2Fa+b.png", "sharing image"),
        ("&robots=noarchive", "robots must be"),
        ("&twitter_card=player", "card must be"),
    ] {
        let refused = save("refused", bad);
        assert_eq!(refused.status, 422, "{bad}: {refused:?}");
        assert!(refused.body.contains(says), "{bad}: {}", refused.body);
    }
    drop(door);
}

#[test]
fn the_editor_writes_renames_and_removes_content() {
    let data = temp_dir("editor");
    let conf = config(&data.0);
    let (door, addr, pages) = open_cached(&conf);

    // Guests are sent to sign in; a member without the editor role is refused.
    assert_eq!(get(addr, "/admin", &[]).status, 303);
    let member = sign_in(addr);
    assert_eq!(get(addr, "/admin", &[&member]).status, 403);
    let account = get(addr, "/account", &[&member]);
    assert!(
        !account.body.contains("Edit the content"),
        "{}",
        account.body
    );

    let ed = sign_in_as(addr, EDITOR);
    let account = get(addr, "/account", &[&ed]);
    assert!(
        account.body.contains("Edit the content"),
        "{}",
        account.body
    );
    let list = get(addr, "/admin", &[&ed]);
    assert_eq!(list.status, 200, "{list:?}");
    assert_eq!(list.field("cache-control"), Some("no-store"));
    assert!(list.body.contains("The passport"), "{}", list.body);
    // The admin pages come from the built-in admin theme, under their own
    // content security policy.
    assert!(
        list.body.contains("/admin/static/admin.css"),
        "{}",
        list.body
    );
    assert_eq!(
        list.field("content-security-policy"),
        Some(wasp::theme::ADMIN_CSP)
    );
    let css = get(addr, "/admin/static/admin.css", &[]);
    assert_eq!(css.status, 200, "{css:?}");
    assert_eq!(css.field("content-type"), Some("text/css; charset=utf-8"));

    // A new page: saved, then served at its own path, escaped. The body's
    // line breaks are CRLF, as a browser sends a textarea's.
    let blank = get(addr, "/admin/new/page", &[&ed]);
    assert_eq!(blank.status, 200, "{blank:?}");
    let csrf = blank.csrf();
    let saved = post(
        addr,
        "/admin/save",
        &[&ed],
        "same-origin",
        &entry_body(
            "page",
            "contact",
            "",
            "Contact",
            "Write <b>to</b> us.\r\n\r\nSecond.",
            &csrf,
        ),
    );
    assert_eq!(saved.status, 303, "{saved:?}");
    assert_eq!(saved.field("location"), Some("/contact"));
    let page = get(addr, "/contact", &[]);
    assert_eq!(page.status, 200, "{page:?}");
    let hits = pages.stats().hits;
    assert_eq!(get(addr, "/contact", &[]).body, page.body);
    assert_eq!(pages.stats().hits, hits + 1, "the guest copy");
    assert!(
        page.body
            .contains("<p>Write &lt;b&gt;to&lt;/b&gt; us.</p><p>Second.</p>"),
        "{}",
        page.body
    );

    // Refused with the form again: a bad slug, a slug another entry has, a
    // post from another site.
    let bad = post(
        addr,
        "/admin/save",
        &[&ed],
        "same-origin",
        &entry_body("page", "Not A Slug", "", "Bad", "x", &csrf),
    );
    assert_eq!(bad.status, 422, "{bad:?}");
    assert!(bad.body.contains("lowercase letters"), "{}", bad.body);
    assert!(
        bad.body.contains("value=\"Not A Slug\""),
        "kept: {}",
        bad.body
    );
    let taken = post(
        addr,
        "/admin/save",
        &[&ed],
        "same-origin",
        &entry_body("page", "about", "", "About again", "x", &csrf),
    );
    assert_eq!(taken.status, 422, "{taken:?}");
    let forged = post(
        addr,
        "/admin/save",
        &[&ed],
        "cross-site",
        &entry_body("page", "evil", "", "Evil", "x", &csrf),
    );
    assert_eq!(forged.status, 403, "{forged:?}");
    let by_member = post(
        addr,
        "/admin/save",
        &[&member],
        "same-origin",
        &entry_body("page", "evil", "", "Evil", "x", &csrf),
    );
    assert_ne!(by_member.status, 303, "{by_member:?}");
    assert_eq!(get(addr, "/evil", &[]).status, 404);

    // Edited and renamed: the old path is gone.
    let form = get(addr, "/admin/edit/contact", &[&ed]);
    assert_eq!(form.status, 200, "{form:?}");
    assert!(
        form.body.contains("Write &lt;b&gt;to&lt;/b&gt; us."),
        "{}",
        form.body
    );
    let csrf = form.csrf();
    let renamed = post(
        addr,
        "/admin/save",
        &[&ed],
        "same-origin",
        &entry_body("page", "write-to-us", "contact", "Contact", "Here.", &csrf),
    );
    assert_eq!(renamed.status, 303, "{renamed:?}");
    // The save dropped every guest copy: the old path is gone at once.
    assert_eq!(get(addr, "/contact", &[]).status, 404);
    assert_eq!(get(addr, "/write-to-us", &[]).status, 200);
    let _ = door.close(Duration::from_secs(2));

    // Kept across a restart, then removed.
    let (door, addr) = open(&conf);
    assert_eq!(get(addr, "/write-to-us", &[]).status, 200);
    let form = get(addr, "/admin/edit/write-to-us", &[&ed]);
    assert_eq!(form.status, 200, "{form:?}");
    let gone = post(
        addr,
        "/admin/delete",
        &[&ed],
        "same-origin",
        &format!("slug=write-to-us&csrf_token={}", encode(&form.csrf())),
    );
    assert_eq!(gone.status, 303, "{gone:?}");
    assert_eq!(gone.field("location"), Some("/admin"));
    assert_eq!(get(addr, "/write-to-us", &[]).status, 404);
    let _ = door.close(Duration::from_secs(2));
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("dir");
    for e in std::fs::read_dir(src).expect("read") {
        let e = e.expect("entry");
        let to = dst.join(e.file_name());
        if e.file_type().expect("type").is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).expect("copy");
        }
    }
}

/// The site with its theme in `theme` and `admin` added to the config.
fn config_with_themes(data: &Path, theme: &Path, admin: &str) -> Config {
    Config::from_text(&format!(
        "[site]
theme = \"{}\"
theme_poll = \"0s\"

[auth]
store = \"nex\"

[content]
store = \"nex\"

[nex]
path = \"{}\"
lock_wait = \"0s\"

[admin]
{admin}
",
        slash(theme),
        slash(&data.join("nex"))
    ))
    .expect("config")
}

#[test]
fn error_pages_follow_the_errors_table_and_admin_errors_use_the_admin_theme() {
    let data = temp_dir("errors");
    let theme = data.0.join("theme");
    copy_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default"),
        &theme,
    );
    std::fs::write(
        theme.join("errors/error/gone.html"),
        "<p>gone: {{ error.status }} {{ error.message }} [{{ error.code }}]</p>",
    )
    .expect("template");
    let conf = Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n[auth]\nstore = \"nex\"\n[content]\nstore = \"nex\"\n[nex]\npath = \"{}\"\n\
         [errors.404]\nmessage = \"Nothing lives at this address.\"\ntemplate = \"error/gone\"\n\
         [errors.4xx]\nmessage = \"That request was not right.\"\n",
        slash(&theme),
        slash(&data.0.join("nex"))
    ))
    .expect("config");
    let (door, addr) = open(&conf);

    // The site: the configured template and message.
    let missing = get(addr, "/no/such/page", &[]);
    assert_eq!(missing.status, 404);
    assert!(
        missing
            .body
            .contains("gone: 404 Nothing lives at this address."),
        "{}",
        missing.body
    );

    // Under /admin: the admin theme's error page, with the handler's own
    // message and its code.
    let ed = sign_in_as(addr, EDITOR);
    let unknown = get(addr, "/admin/edit/no-such-entry", &[&ed]);
    assert_eq!(unknown.status, 404, "{unknown:?}");
    assert!(
        unknown.body.contains("/admin/static/admin.css"),
        "{}",
        unknown.body
    );
    assert!(
        !unknown.body.contains("gone:"),
        "never the site theme's page"
    );
    assert!(
        unknown.body.contains("No post or page has that slug."),
        "{}",
        unknown.body
    );
    assert!(unknown.body.contains("(admin.unknown)"), "{}", unknown.body);
    let _ = door.close(Duration::from_secs(2));

    // A rule naming a page the theme lacks stops the boot.
    let bad = Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n[auth]\nstore = \"nex\"\n[nex]\npath = \"{}\"\n[errors.5xx]\ntemplate = \"error/oops\"\n",
        slash(&theme),
        slash(&data.0.join("nex2"))
    ))
    .expect("config");
    let e = wasp::wire(&bad).expect_err("missing template");
    assert!(e.contains("errors/error/oops.html"), "{e}");
}

#[test]
fn a_site_theme_cannot_replace_the_admin_pages() {
    let data = temp_dir("admin-split");
    let site = data.0.join("site-theme");
    copy_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default"),
        &site,
    );
    // A site theme that tries: its own admin templates, by both names.
    for name in ["admin.html", "admin/list.html"] {
        let path = site.join("pages").join(name);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        std::fs::write(&path, "SITE THEME ADMIN <script>alert(1)</script>").expect("write");
    }
    let conf = config_with_themes(&data.0, &site, "");
    let (door, addr) = open(&conf);
    let ed = sign_in_as(addr, EDITOR);
    let list = get(addr, "/admin", &[&ed]);
    assert_eq!(list.status, 200, "{list:?}");
    assert!(!list.body.contains("SITE THEME ADMIN"), "{}", list.body);
    assert!(
        list.body.contains("/admin/static/admin.css"),
        "{}",
        list.body
    );
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_custom_admin_theme_needs_the_operator_to_allow_it() {
    let data = temp_dir("admin-custom");
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    let admin = data.0.join("admin-theme");
    copy_dir(&Path::new(env!("CARGO_MANIFEST_DIR")).join("admin"), &admin);
    std::fs::write(
        admin.join("pages/list.html"),
        "{% extends \"base\" %}{% block content %}CUSTOM ADMIN{% endblock %}",
    )
    .expect("write");
    let refused = config_with_themes(&data.0, &theme, &format!("theme = \"{}\"", slash(&admin)));
    let err = wasp::wire(&refused).expect_err("refused without custom_theme");
    assert!(err.contains("admin.custom_theme"), "{err}");

    let allowed = config_with_themes(
        &data.0,
        &theme,
        &format!(
            "theme = \"{}\"
custom_theme = true",
            slash(&admin)
        ),
    );
    let (door, addr) = open(&allowed);
    let ed = sign_in_as(addr, EDITOR);
    let list = get(addr, "/admin", &[&ed]);
    assert_eq!(list.status, 200, "{list:?}");
    assert!(list.body.contains("CUSTOM ADMIN"), "{}", list.body);
    let css = get(addr, "/admin/static/admin.css", &[]);
    assert_eq!(css.status, 200, "the custom theme's static folder: {css:?}");
    let _ = door.close(Duration::from_secs(2));
}
