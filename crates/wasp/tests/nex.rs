//! nex-db as the durable store: content through the wiring, the core's
//! authenticator over nex-db sessions, one database per data folder.

#![cfg(feature = "store-nex")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::content::{ContentStore, Stored};
use wasp::nex::{NexAuth, NexDb, NexStore, SESSION, SESSION_COOKIE};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{Core, Exit, Identified, Passport, Rule, Service, ServiceCtx, Subject};

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("wasp-nex-{name}-{}", std::process::id()));
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
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[content]\nstore = \"nex\"\n\n[nex]\npath = \"{}\"\nlock_wait = \"0s\"\n",
        slash(&theme),
        slash(&data.join("nex"))
    ))
    .expect("config")
}

fn settings() -> Settings {
    Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 4,
        ..Settings::default()
    }
}

fn open_site(conf: &Config) -> (Door, SocketAddr) {
    let wiring = wasp::wire(conf).expect("wiring");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let door = Door::open(wiring.core, &settings(), UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

/// Status, the whole response.
fn send(addr: SocketAddr, target: &str, cookie: Option<&str>) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let c = cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    s.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n{c}Connection: close\r\n\r\n")
            .as_bytes(),
    )
    .expect("request");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    (
        text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0),
        text,
    )
}

/// Opens the database a closed door held (its threads let go a moment later).
fn reopen(dir: &Path) -> NexDb {
    let t = Instant::now();
    loop {
        match NexDb::open(dir) {
            Ok(db) => return db,
            Err(_) if t.elapsed() < Duration::from_secs(5) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("reopen: {e:?}"),
        }
    }
}

#[test]
fn content_in_nex_db_is_served_and_kept() {
    let data = temp_dir("content");
    let conf = config(&data.0);
    let (door, addr) = open_site(&conf);
    assert_eq!(send(addr, "/posts/hello-world", None).0, 200, "seeded");
    assert_eq!(send(addr, "/ready", None).0, 200, "the database is ready");
    // One database per folder: a second instance is refused (at once with
    // `lock_wait = "0s"`), naming the lock it found.
    let t = Instant::now();
    let err = wasp::wire(&conf).expect_err("second instance");
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "refused without waiting"
    );
    assert!(err.contains("in use by another process"), "{err}");
    assert!(err.contains("probably still running"), "{err}");
    assert!(err.contains("LOCK"), "names the lock file: {err}");
    door.close(Duration::from_secs(2));

    {
        let store = NexStore::new(reopen(&data.0.join("nex")));
        assert_eq!(store.load().expect("load").len(), 4, "seeded once");
        store
            .put(&Stored {
                kind: "post".into(),
                slug: "kept".into(),
                title: "Kept in nex-db".into(),
                summary: String::new(),
                body: "Through a restart.".into(),
                date: "2026-11-18".into(),
                meta: wasp::content::Meta::default(),
                fields: Vec::new(),
            })
            .expect("put");
        // A put on a known slug updates the entity at that route.
        store
            .put(&Stored {
                kind: "post".into(),
                slug: "kept".into(),
                title: "Kept in nex-db, edited".into(),
                summary: String::new(),
                body: "Through a restart.".into(),
                date: "2026-11-18".into(),
                meta: wasp::content::Meta::default(),
                fields: Vec::new(),
            })
            .expect("update");
        assert_eq!(store.load().expect("load").len(), 5, "updated, not added");
        assert!(store.remove("about").expect("remove"), "a page removed");
    }

    let (door, addr) = open_site(&conf);
    let (status, body) = send(addr, "/posts/kept", None);
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("Kept in nex-db, edited"), "{body}");
    assert!(body.contains("<p>Through a restart.</p>"), "{body}");
    assert_eq!(
        send(addr, "/about", None).0,
        200,
        "about falls back to its message"
    );
    door.close(Duration::from_secs(2));
}

/// Answers with who the core says the request is from.
struct WhoAmI(ServiceCtx);

impl Service for WhoAmI {
    fn name(&self) -> &str {
        "whoami"
    }

    fn handle(&self, p: Passport<Identified>) -> Exit {
        let who = match p.identity().subject() {
            Subject::Guest => "guest".to_owned(),
            Subject::User(u) => format!("user {:032x} perms {}", u.0, p.identity().perms().0),
        };
        let mut p = match self.0.access().authorize(p, &Rule::public(1)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        p.reply().text(200, &who);
        p.answer()
    }
}

#[test]
fn the_core_authenticates_nex_db_sessions() {
    let data = temp_dir("auth");
    let db = NexDb::open(&data.0.join("nex")).expect("open");
    let auth = NexAuth::with_roles(db.clone(), &[("member", 1), ("editor", 4)]);
    let user = auth
        .ensure_account(
            "ann@example.com",
            "correct horse battery staple",
            &["member", "editor"],
        )
        .expect("account")
        .expect("new");
    assert_eq!(
        auth.ensure_account("ann@example.com", "another password", &["member"])
            .expect("again"),
        None,
        "an existing account is left as it is"
    );
    let core = Arc::new(
        Core::builder()
            .authenticator(auth.clone())
            .provider(Arc::new(db.clone()))
            .service("whoami", WhoAmI)
            .profile("site", "whoami", |_| {})
            .load()
            .expect("core"),
    );
    let door = Door::open(
        core,
        &settings(),
        UrgentLine::detached(),
        WebServices::new(),
    )
    .expect("opens");
    let addr = door.local_addr().expect("addr");

    let (_, body) = send(addr, "/", None);
    assert!(body.ends_with("guest"), "{body}");

    assert!(
        auth.sign_in("ann@example.com", "wrong")
            .expect("sign in")
            .is_none(),
        "a wrong password"
    );
    let set = auth
        .sign_in("ann@example.com", "correct horse battery staple")
        .expect("sign in")
        .expect("signed in");
    assert!(set.contains("Secure") && set.contains("HttpOnly"), "{set}");
    let cookie = set.split(';').next().expect("pair").to_owned();
    let token = cookie
        .strip_prefix(&format!("{SESSION_COOKIE}="))
        .expect("token")
        .to_owned();

    let (status, body) = send(addr, "/", Some(&cookie));
    assert_eq!(status, 200);
    // The roles' bits, and the one only a session cookie carries.
    let want = format!("user {:032x} perms {}", user.0, 5 | SESSION.0);
    assert!(body.ends_with(&want), "{body}");

    // Signed out: the session is gone, and its cookie is cleared.
    let clear = auth.sign_out(&token).expect("sign out");
    assert!(clear.contains("Max-Age=0"));
    let (_, body) = send(addr, "/", Some(&cookie));
    assert!(body.ends_with("guest"), "{body}");
    assert!(
        body.contains(&format!("{SESSION_COOKIE}=;")),
        "cleared: {body}"
    );

    // A ban ends every session at once.
    let again = auth
        .sign_in("ann@example.com", "correct horse battery staple")
        .expect("sign in")
        .expect("signed in");
    let again = again.split(';').next().expect("pair").to_owned();
    assert!(
        send(addr, "/", Some(&again))
            .1
            .contains(&format!("perms {}", 5 | SESSION.0))
    );
    auth.ban(user).expect("ban");
    let (_, body) = send(addr, "/", Some(&again));
    assert!(body.ends_with("guest"), "{body}");

    // A token planted twice, or one that is not a token: a guest.
    let twice = format!("{again}; {again}");
    assert!(send(addr, "/", Some(&twice)).1.ends_with("guest"));
    assert!(
        send(addr, "/", Some(&format!("{SESSION_COOKIE}=forged")))
            .1
            .ends_with("guest")
    );
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_cookie_without_a_value_does_not_hide_the_session() {
    use wasp::nex::cookie;
    assert_eq!(
        cookie(b"flag; __Host-nex=abc; theme=dark", SESSION_COOKIE),
        Some("abc")
    );
    assert_eq!(cookie(b"__Host-nex=a; __Host-nex=b", SESSION_COOKIE), None);
}

#[test]
fn a_new_boot_account_needs_a_long_password() {
    let data = temp_dir("boot");
    let auth = NexAuth::new(NexDb::open(&data.0.join("nex")).expect("open"));
    let err = auth
        .ensure_account("boot@example.com", "short", &["member"])
        .expect_err("too short");
    assert!(err.to_string().contains("12"), "{err}");
    assert!(
        auth.ensure_account("boot@example.com", "a long enough password", &[])
            .expect("made")
            .is_some()
    );
    // Again with its password: kept, and the roles it lacks are given back.
    assert_eq!(
        auth.ensure_account(
            "boot@example.com",
            "a long enough password",
            &["member", "editor"]
        )
        .expect("again"),
        None
    );
}

#[test]
fn the_boot_account_needs_its_password_only_to_be_made() {
    let data = temp_dir("boot-once");
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    let conf = Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[auth]\nstore = \"nex\"\nadmin = \"Boot@Example.com\"\n\n[nex]\npath = \"{}\"\n",
        slash(&theme),
        slash(&data.0.join("nex"))
    ))
    .expect("config");
    // No account yet and no password: refused, saying what to do.
    let err = wasp::wire(&conf).expect_err("no account, no password");
    assert!(err.contains("has no account yet"), "{err}");
    {
        let auth = NexAuth::new(reopen(&data.0.join("nex")));
        assert!(auth.known("boot@example.com").expect("known").is_none());
        auth.ensure_account(
            "Boot@Example.com",
            "a long enough password",
            &["member", "editor"],
        )
        .expect("made");
        assert!(auth.known(" boot@example.COM ").expect("known").is_some());
        assert_eq!(auth.accounts().expect("accounts").len(), 1);
    }
    // Made: every later boot starts without the password.
    let t = Instant::now();
    loop {
        match wasp::wire(&conf) {
            Ok(_) => break,
            Err(e)
                if e.contains("in use by another process")
                    && t.elapsed() < Duration::from_secs(5) =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("boot without the password: {e}"),
        }
    }
}

#[test]
fn a_kind_change_survives_a_restart() {
    let data = temp_dir("kind");
    let dir = data.0.join("nex");
    let entry = |kind: &str| Stored {
        kind: kind.into(),
        slug: "flip".into(),
        title: "Flip".into(),
        summary: String::new(),
        body: "Body.".into(),
        date: if kind == "post" {
            "2026-11-19".into()
        } else {
            String::new()
        },
        meta: wasp::content::Meta::default(),
        fields: Vec::new(),
    };
    {
        let store = NexStore::new(NexDb::open(&dir).expect("open"));
        store.put(&entry("page")).expect("page");
        store.put(&entry("post")).expect("now a post");
    }
    let store = NexStore::new(reopen(&dir));
    let flips: Vec<_> = store
        .load()
        .expect("load")
        .into_iter()
        .filter(|s| s.slug == "flip")
        .map(|s| s.kind)
        .collect();
    assert_eq!(flips, ["post"], "one entry, the post");
}
