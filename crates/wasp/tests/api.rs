//! The API: JSON under `/api/v1`, a browser signed in by its session cookie
//! and a program by an API key, keys made and revoked on the account page,
//! errors in JSON with the code, message and reference, and a budget for
//! each caller.

#![cfg(feature = "store-nex")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::nex::{EDITOR_ROLE, MEMBER_ROLE, NexAuth};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

const EDITOR: &str = "ed@example.com";
const PASSWORD: &str = "correct horse battery staple";
const OTHER: &str = "other@example.com";
const HOST: &str = "localhost";

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("wasp-api-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    TempDir(dir)
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn config(data: &Path, extra: &str) -> Config {
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n[auth]\nstore = \"nex\"\n[content]\nstore = \"nex\"\n[nex]\npath = \"{}\"\n{extra}",
        slash(&theme),
        slash(&data.join("nex")),
    ))
    .expect("config")
}

/// The site on a loopback port, with the editor's account. `budgets`: the
/// API's budget per caller is charged (loopback is not exempt).
fn open(conf: &Config, budgets: bool) -> (Door, SocketAddr, NexAuth) {
    let t = Instant::now();
    let wiring = loop {
        match wasp::wire(conf) {
            Ok(w) => break w,
            Err(e)
                if e.contains("in use by another process")
                    && t.elapsed() < Duration::from_secs(5) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("wiring: {e}"),
        }
    };
    let auth = NexAuth::new(wiring.nex.clone().expect("nex-db"));
    auth.ensure_account(EDITOR, PASSWORD, &[MEMBER_ROLE, EDITOR_ROLE])
        .expect("editor");
    auth.ensure_account(OTHER, PASSWORD, &[MEMBER_ROLE])
        .expect("other");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        exempt: if budgets {
            Vec::new()
        } else {
            vec![std::net::IpAddr::from([127, 0, 0, 1])]
        },
        lane_rates: wiring.api_budget.into_iter().collect(),
        ..Settings::default()
    };
    let door = Door::open(wiring.core, &settings, UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr, auth)
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
            .expect("csrf")
            + 25;
        let rest = &self.body[at..];
        rest[..rest.find('"').expect("end")].to_owned()
    }

    /// The JSON string value of `key` (the first one).
    fn json(&self, key: &str) -> Option<String> {
        let at = self.body.find(&format!("\"{key}\":\""))? + key.len() + 4;
        let rest = &self.body[at..];
        Some(rest[..rest.find('"')?].to_owned())
    }

    fn is_json(&self) -> bool {
        self.field("content-type") == Some("application/json")
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

/// A request with `method`, `fields` (whole lines, `Name: value`) and a
/// form `body` when it is not empty.
fn call(addr: SocketAddr, method: &str, target: &str, fields: &[String], body: &str) -> Got {
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {HOST}\r\n");
    for f in fields {
        head.push_str(f);
        head.push_str("\r\n");
    }
    if !body.is_empty() || method == "POST" {
        head.push_str(&format!(
            "Sec-Fetch-Site: same-origin\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    send(addr, &format!("{head}Connection: close\r\n\r\n{body}"))
}

fn cookie(c: &str) -> Vec<String> {
    vec![format!("Cookie: {c}")]
}

fn bearer(key: &str) -> Vec<String> {
    vec![format!("Authorization: Bearer {key}")]
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

fn sign_in(addr: SocketAddr) -> String {
    sign_in_as(addr, EDITOR)
}

fn sign_in_as(addr: SocketAddr, email: &str) -> String {
    let first = call(addr, "GET", "/sign-in", &[], "");
    assert_eq!(first.status, 303, "{first:?}");
    let pre = first.cookie("__Host-nexpre").expect("pre");
    let page = call(addr, "GET", "/sign-in", &cookie(&pre), "");
    let done = call(
        addr,
        "POST",
        "/sign-in",
        &cookie(&pre),
        &format!(
            "email={}&password={}&csrf_token={}",
            encode(email),
            encode(PASSWORD),
            encode(&page.csrf())
        ),
    );
    assert_eq!(done.status, 303, "{done:?}");
    done.cookie("__Host-nex").expect("session")
}

/// Makes a key on the account page with `scopes`: its text.
fn make_key(addr: SocketAddr, session: &str, label: &str, scopes: &[&str]) -> String {
    let page = call(addr, "GET", "/account/security", &cookie(session), "");
    assert_eq!(page.status, 200, "{page:?}");
    let mut form = format!(
        "label={}&days=30&password={}&csrf_token={}",
        encode(label),
        encode(PASSWORD),
        encode(&page.csrf())
    );
    for s in scopes {
        form.push_str(&format!("&scope={}", encode(s)));
    }
    let made = call(addr, "POST", "/account/keys", &cookie(session), &form);
    assert_eq!(made.status, 200, "{made:?}");
    let at = made
        .body
        .find("class=\"key\">")
        .expect("the key, shown once")
        + 12;
    let rest = &made.body[at..];
    rest[..rest.find('<').expect("end")].to_owned()
}

#[test]
fn a_key_reads_what_its_scopes_allow_and_never_the_account_pages() {
    let data = temp_dir("keys");
    let conf = config(&data.0, "");
    let (door, addr, _) = open(&conf, false);
    let session = sign_in(addr);

    // A browser, by its cookie.
    let me = call(addr, "GET", "/api/v1/me", &cookie(&session), "");
    assert_eq!(me.status, 200, "{me:?}");
    assert!(me.is_json(), "{me:?}");
    assert_eq!(me.json("email").as_deref(), Some(EDITOR));
    assert_eq!(me.json("signed_in_with").as_deref(), Some("session"));
    assert!(
        me.body.contains("\"roles\":[") && me.body.contains("\"editor\""),
        "{}",
        me.body
    );
    // No one.
    let guest = call(addr, "GET", "/api/v1/me", &[], "");
    assert_eq!(guest.status, 401, "{guest:?}");
    assert_eq!(guest.json("code").as_deref(), Some("api.sign_in"));
    assert_eq!(guest.field("www-authenticate"), Some("Bearer"));

    let reader = make_key(addr, &session, "reader", &["account:read"]);
    let bare = make_key(addr, &session, "no scopes", &[]);
    assert!(reader.len() >= 32 && reader != bare, "{reader}");

    // The key's own account, with its scopes.
    let me = call(addr, "GET", "/api/v1/me", &bearer(&reader), "");
    assert_eq!(me.status, 200, "{me:?}");
    assert_eq!(me.json("email").as_deref(), Some(EDITOR));
    assert_eq!(me.json("signed_in_with").as_deref(), Some("key"));
    assert!(
        me.body.contains("\"scopes\":[\"account:read\"]"),
        "{}",
        me.body
    );
    // Without the scope: refused, but public content reads.
    let refused = call(addr, "GET", "/api/v1/me", &bearer(&bare), "");
    assert_eq!(refused.status, 403, "{refused:?}");
    assert_eq!(refused.json("code").as_deref(), Some("api.scope"));
    let posts = call(addr, "GET", "/api/v1/posts", &bearer(&bare), "");
    assert_eq!(posts.status, 200, "{posts:?}");

    // A key never reaches the account pages, the editor or the admin, even
    // though its account is an editor; it cannot make keys or sign out.
    for path in ["/account/security", "/account", "/admin", "/admin/accounts"] {
        let got = call(addr, "GET", path, &bearer(&reader), "");
        assert!(
            got.status == 403 || got.status == 404,
            "{path}: {}",
            got.status
        );
        assert!(!got.body.contains("API keys"), "{path}");
    }
    let more = call(
        addr,
        "POST",
        "/account/keys",
        &bearer(&reader),
        "label=more&days=30",
    );
    assert_eq!(more.status, 403, "{more:?}");
    // The cookie is ignored when a key is sent.
    let both = [bearer(&bare), cookie(&session)].concat();
    let page = call(addr, "GET", "/account/security", &both, "");
    assert_eq!(page.status, 403, "{page:?}");

    // The list shows both keys, never a key's text.
    let page = call(addr, "GET", "/account/security", &cookie(&session), "");
    assert!(page.body.contains("reader") && page.body.contains("no scopes"));
    assert!(!page.body.contains(&reader) && !page.body.contains(&bare));

    // Revoked: every API request with it is 401, telling the program why.
    let id = {
        let at = page.body.find("name=\"key\" value=\"").expect("a key id") + 18;
        page.body[at..at + 32].to_owned()
    };
    let gone = call(
        addr,
        "POST",
        "/account/keys/revoke",
        &cookie(&session),
        &format!("key={id}&csrf_token={}", encode(&page.csrf())),
    );
    assert_eq!(gone.status, 200, "{gone:?}");
    assert!(gone.body.contains("Revoked the key"), "{}", gone.body);
    let again = call(
        addr,
        "POST",
        "/account/keys/revoke",
        &cookie(&session),
        &format!("key={id}&csrf_token={}", encode(&page.csrf())),
    );
    assert_eq!(again.status, 404, "{again:?}");
    let alive = [&reader, &bare]
        .iter()
        .filter(|k| call(addr, "GET", "/api/v1/posts", &bearer(k), "").status == 200)
        .count();
    assert_eq!(alive, 1, "one key revoked, one left");

    // Not a key at all, and another scheme (ignored: a guest).
    let bad = call(addr, "GET", "/api/v1/posts", &bearer("nope"), "");
    assert_eq!(bad.status, 401, "{bad:?}");
    assert_eq!(bad.json("code").as_deref(), Some("api.bad_key"));
    assert_eq!(
        bad.field("www-authenticate"),
        Some("Bearer error=\"invalid_token\"")
    );
    let basic = call(
        addr,
        "GET",
        "/api/v1/posts",
        &["Authorization: Basic dTpw".to_owned()],
        "",
    );
    assert_eq!(basic.status, 200, "{basic:?}");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_key_form_breaking_a_rule_makes_no_key() {
    let data = temp_dir("rules");
    let conf = config(&data.0, "");
    let (door, addr, _) = open(&conf, false);
    let session = sign_in(addr);
    let page = call(addr, "GET", "/account/security", &cookie(&session), "");
    let csrf = format!("{}&password={}", encode(&page.csrf()), encode(PASSWORD));
    for (form, why) in [
        (
            format!("label=&days=30&csrf_token={csrf}"),
            "Give the key a label",
        ),
        (
            format!("label=x&days=7&csrf_token={csrf}"),
            "Choose how long",
        ),
        (
            format!(
                "label=x&days=30&password=wrong&csrf_token={}",
                encode(&page.csrf())
            ),
            "The password is not right.",
        ),
        (
            format!("label=x&days=30&csrf_token={}", encode(&page.csrf())),
            "The password is not right.",
        ),
        (
            format!("label=x&days=30&scope=account%3Awrite&csrf_token={csrf}"),
            "There is no scope",
        ),
        (
            format!("label={}&days=30&csrf_token={csrf}", "x".repeat(65)),
            "at most 64",
        ),
    ] {
        let got = call(addr, "POST", "/account/keys", &cookie(&session), &form);
        assert_eq!(got.status, 422, "{form}: {got:?}");
        assert!(got.body.contains(why), "{form}: {}", got.body);
        assert!(!got.body.contains("class=\"key\""), "{form}");
    }
    // Without the CSRF token: refused before anything is made.
    let forged = call(
        addr,
        "POST",
        "/account/keys",
        &cookie(&session),
        "label=x&days=30",
    );
    assert_eq!(forged.status, 403, "{forged:?}");
    let page = call(addr, "GET", "/account/security", &cookie(&session), "");
    assert!(page.body.contains("No keys yet."), "{}", page.body);
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn content_reads_and_errors_are_json() {
    let data = temp_dir("content");
    let conf = config(&data.0, "");
    let (door, addr, _) = open(&conf, false);

    let posts = call(addr, "GET", "/api/v1/posts", &[], "");
    assert_eq!(posts.status, 200, "{posts:?}");
    assert!(posts.is_json());
    assert_eq!(posts.field("cache-control"), Some("no-store"));
    assert!(
        posts.body.starts_with("{\"posts\":[{\"slug\":"),
        "{}",
        posts.body
    );
    assert!(posts.body.contains("\"total\":3"), "{}", posts.body);
    let slug = posts.json("slug").expect("a post");
    let one = call(addr, "GET", "/api/v1/posts?limit=1&offset=1", &[], "");
    assert_eq!(one.body.matches("\"slug\":").count(), 1, "{}", one.body);
    assert_ne!(one.json("slug"), Some(slug.clone()));

    let post = call(addr, "GET", &format!("/api/v1/posts/{slug}"), &[], "");
    assert_eq!(post.status, 200, "{post:?}");
    assert_eq!(post.json("kind").as_deref(), Some("post"));
    for key in [
        "\"body\":",
        "\"text\":",
        "\"meta\":{\"seo_title\":",
        "\"fields\":[",
    ] {
        assert!(post.body.contains(key), "{key}: {}", post.body);
    }
    let about = call(addr, "GET", "/api/v1/pages/about", &[], "");
    assert_eq!(about.status, 200, "{about:?}");
    assert_eq!(about.json("kind").as_deref(), Some("page"));

    // Errors: the status, the code, a message and the reference.
    for (target, status, code) in [
        ("/api/v1/posts/no-such-post", 404, "post.unknown"),
        ("/api/v1/pages/no-such-page", 404, "page.unknown"),
        ("/api/v1/posts?limit=0", 400, "api.bad_query"),
        ("/api/v1/posts?limit=many", 400, "api.bad_query"),
        ("/api/v1/nothing/here", 404, "api.not_found"),
        ("/api/v1", 404, "api.not_found"),
    ] {
        let got = call(addr, "GET", target, &[], "");
        assert_eq!(got.status, status, "{target}: {got:?}");
        assert!(got.is_json(), "{target}: {got:?}");
        assert!(
            got.body.starts_with(&format!(
                "{{\"status\":{status},\"code\":\"{code}\",\"message\":\""
            )),
            "{target}: {}",
            got.body
        );
        assert!(
            !got.json("reference").unwrap_or_default().is_empty(),
            "{target}"
        );
    }
    // Any other method: JSON too, never a page.
    let wrong = call(addr, "POST", "/api/v1/posts", &[], "");
    assert_eq!(wrong.status, 405, "{wrong:?}");
    assert_eq!(wrong.json("code").as_deref(), Some("api.method"));
    assert_eq!(wrong.field("allow"), Some("GET, HEAD"));
    let wrong = call(addr, "DELETE", "/api/v1/whatever", &[], "");
    assert_eq!(wrong.status, 404, "{wrong:?}");
    assert!(wrong.is_json());
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn the_api_moves_or_goes_with_its_settings() {
    let data = temp_dir("settings");
    let conf = config(&data.0, "[api]\nprefix = \"/json\"\n");
    let (door, addr, _) = open(&conf, false);
    assert_eq!(call(addr, "GET", "/json/posts", &[], "").status, 200);
    let old = call(addr, "GET", "/api/v1/posts", &[], "");
    assert_eq!(old.status, 404, "{old:?}");
    assert!(!old.is_json());
    let _ = door.close(Duration::from_secs(2));
    drop(data);

    let data = temp_dir("off");
    let conf = config(&data.0, "[api]\nenabled = false\n");
    let (door, addr, _) = open(&conf, false);
    assert!(!call(addr, "GET", "/api/v1/posts", &[], "").is_json());
    let session = sign_in(addr);
    let page = call(addr, "GET", "/account/security", &cookie(&session), "");
    assert!(!page.body.contains("API keys"), "{}", page.body);
    let made = call(
        addr,
        "POST",
        "/account/keys",
        &cookie(&session),
        &format!("label=x&days=30&csrf_token={}", encode(&page.csrf())),
    );
    assert_ne!(made.status, 200, "{made:?}");
    let _ = door.close(Duration::from_secs(2));

    for bad in [
        "[api]\nprefix = \"/admin/api\"\n",
        "[api]\nprefix = \"api\"\n",
        "[api]\nrate = 5\nburst = 1\n",
        "[api]\nspeed = 1\n",
    ] {
        let data = temp_dir("bad");
        let e = wasp::wire(&config(&data.0, bad)).expect_err(bad);
        assert!(e.contains("api."), "{bad}: {e}");
    }
    // With the gatekeeper there is no API to turn on.
    let e = wasp::wire(
        &Config::from_text("[auth]\nstore = \"gatekeeper\"\n[api]\nenabled = true\n")
            .expect("config"),
    );
    assert!(e.is_err());
}

#[test]
fn each_account_has_one_budget_for_all_its_keys() {
    let data = temp_dir("budget");
    let conf = config(&data.0, "[api]\nrate = 1\nburst = 2\n");
    let (door, addr, _) = open(&conf, true);
    let session = sign_in(addr);
    let a = make_key(addr, &session, "a", &[]);
    let b = make_key(addr, &session, "b", &[]);
    let theirs = make_key(addr, &sign_in_as(addr, OTHER), "theirs", &[]);

    // Key a spends the account's burst: a 429 with Retry-After, well
    // inside ten quick requests (one more a second comes back).
    let mut refused = None;
    for _ in 0..10 {
        let got = call(addr, "GET", "/api/v1/posts", &bearer(&a), "");
        if got.status == 429 {
            refused = Some(got);
            break;
        }
        assert_eq!(got.status, 200, "{got:?}");
    }
    let refused = refused.expect("the account over its budget");
    assert!(refused.field("retry-after").is_some(), "{refused:?}");
    // Another key of the same account, or its browser, gets no more.
    let got = call(addr, "GET", "/api/v1/posts", &bearer(&b), "");
    assert_eq!(got.status, 429, "{got:?}");
    let got = call(addr, "GET", "/api/v1/posts", &cookie(&session), "");
    assert_eq!(got.status, 429, "{got:?}");
    // Another account, a guest and page views are each on their own.
    let got = call(addr, "GET", "/api/v1/posts", &bearer(&theirs), "");
    assert_eq!(got.status, 200, "{got:?}");
    let got = call(addr, "GET", "/api/v1/posts", &[], "");
    assert_eq!(got.status, 200, "{got:?}");
    for _ in 0..5 {
        assert_eq!(call(addr, "GET", "/", &[], "").status, 200);
    }
    let _ = door.close(Duration::from_secs(2));
}

/// The account id `/api/v1/me` gives for `key`.
fn user_of(addr: SocketAddr, key: &str) -> wasp_core::UserId {
    let me = call(addr, "GET", "/api/v1/me", &bearer(key), "");
    let id = me.json("id").expect("id");
    wasp_core::UserId(u128::from_str_radix(&id, 16).expect("hex"))
}

#[test]
fn a_ban_or_a_disable_stops_keys_at_once_and_a_lockout_does_not() {
    let data = temp_dir("standing");
    let conf = config(&data.0, "");
    let (door, addr, auth) = open(&conf, false);
    let session = sign_in(addr);
    let key = make_key(addr, &session, "standing", &["account:read"]);
    let me = |k: &str| call(addr, "GET", "/api/v1/me", &bearer(k), "");
    let user = user_of(addr, &key);

    // Wrong sign-in codes (ten, the default) lock the account, not its
    // programs.
    for _ in 0..10 {
        let _ = auth.check_code(user, "000000").expect("code");
    }
    assert!(!auth.may_sign_in(user).expect("standing"), "locked out");
    assert_eq!(me(&key).status, 200, "a lockout leaves keys working");

    // A disable stops the key on the next request, with no wait.
    auth.disable(user, user).expect("disable");
    let got = me(&key);
    assert_eq!(got.status, 403, "{got:?}");
    assert_eq!(got.json("code").as_deref(), Some("api.account_disabled"));
    assert!(auth.enable(user, user).expect("enable"));
    assert_eq!(me(&key).status, 200);
    // So does a ban.
    auth.ban(user).expect("ban");
    assert_eq!(me(&key).status, 403);
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_password_change_or_signing_out_everywhere_revokes_every_key() {
    let data = temp_dir("revoke-all");
    let conf = config(&data.0, "");
    let (door, addr, _) = open(&conf, false);
    let session = sign_in(addr);
    let one = make_key(addr, &session, "one", &[]);
    let two = make_key(addr, &session, "two", &[]);
    let theirs = make_key(addr, &sign_in_as(addr, OTHER), "theirs", &[]);
    let posts = |k: &str| call(addr, "GET", "/api/v1/posts", &bearer(k), "").status;
    assert_eq!((posts(&one), posts(&two)), (200, 200));

    const NEW: &str = "a new and longer password";
    let page = call(addr, "GET", "/account/security", &cookie(&session), "");
    assert!(page.body.contains("revokes your API keys"), "{}", page.body);
    let changed = call(
        addr,
        "POST",
        "/account/password",
        &cookie(&session),
        &format!(
            "current={}&new={}&again={}&csrf_token={}",
            encode(PASSWORD),
            encode(NEW),
            encode(NEW),
            encode(&page.csrf())
        ),
    );
    assert_eq!(changed.status, 200, "{changed:?}");
    assert!(
        changed.body.contains("your API keys are revoked"),
        "{}",
        changed.body
    );
    assert_eq!((posts(&one), posts(&two)), (401, 401));
    assert!(changed.body.contains("No keys yet."), "{}", changed.body);
    assert_eq!(posts(&theirs), 200, "another account's keys stay");

    // Signing out everywhere too.
    let session = changed.cookie("__Host-nex").expect("the new session");
    let page = call(addr, "GET", "/account/security", &cookie(&session), "");
    let made = call(
        addr,
        "POST",
        "/account/keys",
        &cookie(&session),
        &format!(
            "label=three&days=30&password={}&csrf_token={}",
            encode(NEW),
            encode(&page.csrf())
        ),
    );
    assert_eq!(made.status, 200, "{made:?}");
    let three = {
        let at = made.body.find("class=\"key\">").expect("the key") + 12;
        let rest = &made.body[at..];
        rest[..rest.find('<').expect("end")].to_owned()
    };
    assert_eq!(posts(&three), 200);
    let out = call(
        addr,
        "POST",
        "/account/sign-out-everywhere",
        &cookie(&session),
        &format!("csrf_token={}", encode(&page.csrf())),
    );
    assert_eq!(out.status, 303, "{out:?}");
    assert_eq!(posts(&three), 401);
    assert_eq!(posts(&theirs), 200);
    let _ = door.close(Duration::from_secs(2));
}
