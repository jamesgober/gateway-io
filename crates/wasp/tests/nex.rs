//! nex-db as the durable store: content through the wiring, the core's
//! authenticator over nex-db sessions, one database per data folder.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::content::{ContentStore, Stored};
use wasp::nex::{NexAuth, NexDb, NexStore, SESSION_COOKIE};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{Core, Exit, Identified, Passport, PermSet, Rule, Service, ServiceCtx, Subject};

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
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[content]\nstore = \"nex\"\npath = \"{}\"\n",
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
    // One database per folder: a second instance is refused.
    let err = wasp::wire(&conf).expect_err("second instance");
    assert!(err.contains("another instance"), "{err}");
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
    let account = db
        .db()
        .auth()
        .sign_up("ann@example.com", "correct horse battery staple")
        .expect("account");
    let auth = NexAuth::new(db.clone());
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
        auth.sign_in("ann@example.com", "wrong", PermSet(1))
            .expect("sign in")
            .is_none(),
        "a wrong password"
    );
    let set = auth
        .sign_in(
            "ann@example.com",
            "correct horse battery staple",
            PermSet(0b101),
        )
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
    let want = format!(
        "user {:032x} perms 5",
        u128::from_be_bytes(*account.as_bytes())
    );
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
        .sign_in(
            "ann@example.com",
            "correct horse battery staple",
            PermSet(1),
        )
        .expect("sign in")
        .expect("signed in");
    let again = again.split(';').next().expect("pair").to_owned();
    assert!(send(addr, "/", Some(&again)).1.contains("perms 1"));
    db.db()
        .auth()
        .set_standing(account, nex_db::Standing::Banned { reason: 1 }, None)
        .expect("ban");
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
