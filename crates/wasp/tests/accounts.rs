//! Accounts on the nex-db site: changing a password, signing out
//! everywhere, the session cap, the administrator's accounts page, and
//! two-step sign-in (with the `mfa` feature).

#![cfg(feature = "store-nex")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::nex::{ADMIN_ROLE, EDITOR_ROLE, MEMBER_ROLE, NexAuth};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

const MEMBER: &str = "ann@example.com";
const ADMIN: &str = "root@example.com";
const PASSWORD: &str = "correct horse battery staple";

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("wasp-accounts-{name}-{}", std::process::id()));
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
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[auth]\nstore = \"nex\"\n\n[content]\nstore = \"nex\"\n\n[nex]\npath = \"{}\"\n\n{extra}",
        slash(&theme),
        slash(&data.join("nex"))
    ))
    .expect("config")
}

/// Opens the site with a member and an administrator.
fn open(conf: &Config) -> (Door, SocketAddr) {
    let (door, addr, _) = open_with_auth(conf);
    (door, addr)
}

/// Opens the site, with a handle on its accounts.
fn open_with_auth(conf: &Config) -> (Door, SocketAddr, NexAuth) {
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
    auth.ensure_account(MEMBER, PASSWORD, &[MEMBER_ROLE])
        .expect("member");
    auth.ensure_account(ADMIN, PASSWORD, &[MEMBER_ROLE, EDITOR_ROLE, ADMIN_ROLE])
        .expect("admin");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        // These tests are about accounts, not the door's budgets: bursts of
        // sign-ins from one address are expected here.
        exempt: vec![std::net::IpAddr::from([127, 0, 0, 1])],
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
        self.between("name=\"csrf_token\" value=\"", "\"")
            .expect("csrf field")
    }

    fn between(&self, start: &str, end: &str) -> Option<String> {
        let at = self.body.find(start)? + start.len();
        let rest = &self.body[at..];
        Some(rest[..rest.find(end)?].to_owned())
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

fn post(addr: SocketAddr, target: &str, cookies: &[&str], body: &str) -> Got {
    let c = if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    };
    send(
        addr,
        &format!(
            "POST {target} HTTP/1.1\r\nHost: localhost\r\n{c}Sec-Fetch-Site: same-origin\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

/// A fresh visitor's pre-session cookie and the sign-in form's token.
fn form(addr: SocketAddr) -> (String, String) {
    let first = get(addr, "/sign-in", &[]);
    assert_eq!(first.status, 303, "{first:?}");
    let pre = first.cookie("__Host-nexpre").expect("pre-session cookie");
    let page = get(addr, "/sign-in", &[&pre]);
    assert_eq!(page.status, 200, "{page:?}");
    (pre, page.csrf())
}

/// The first step: the answer and the visitor's pre-session cookie.
fn password_step(addr: SocketAddr, email: &str, password: &str, cookies: &[&str]) -> (Got, String) {
    let (pre, csrf) = form(addr);
    let mut all = vec![pre.as_str()];
    all.extend_from_slice(cookies);
    let got = post(
        addr,
        "/sign-in",
        &all,
        &format!(
            "email={}&password={}&csrf_token={}",
            encode(email),
            encode(password),
            encode(&csrf)
        ),
    );
    (got, pre)
}

fn sign_in(addr: SocketAddr, email: &str, password: &str) -> String {
    let (done, _) = password_step(addr, email, password, &[]);
    assert_eq!(done.status, 303, "{done:?}");
    done.cookie("__Host-nex").expect("session")
}

fn signed_in(addr: SocketAddr, session: &str) -> bool {
    get(addr, "/account", &[session]).status == 200
}

/// The security page's token for this session.
fn token(addr: SocketAddr, session: &str) -> String {
    let page = get(addr, "/account/security", &[session]);
    assert_eq!(page.status, 200, "{page:?}");
    page.csrf()
}

#[test]
fn a_password_change_checks_the_rules_and_ends_every_other_session() {
    let data = temp_dir("password");
    let conf = config(
        &data.0,
        "[auth.password]\nmin_length = 14\nrequire_digit = true\n",
    );
    let (door, addr) = open(&conf);
    let here = sign_in(addr, MEMBER, PASSWORD);
    let there = sign_in(addr, MEMBER, PASSWORD);

    let page = get(addr, "/account/security", &[&here]);
    assert_eq!(page.status, 200);
    assert_eq!(page.field("cache-control"), Some("no-store"));
    assert!(
        page.field("content-security-policy")
            .is_some_and(|c| c.contains("default-src 'none'"))
    );
    assert!(
        page.body.contains("At least 14 characters"),
        "{}",
        page.body
    );

    let change = |current: &str, new: &str, again: &str| {
        post(
            addr,
            "/account/password",
            &[&here],
            &format!(
                "current={}&new={}&again={}&csrf_token={}",
                encode(current),
                encode(new),
                encode(again),
                encode(&token(addr, &here))
            ),
        )
    };
    let wrong = change("not it", "a new password 1", "a new password 1");
    assert_eq!(wrong.status, 422);
    assert!(wrong.body.contains("current password is not right"));
    let differ = change(PASSWORD, "a new password 1", "a new password 2");
    assert_eq!(differ.status, 422);
    let short = change(PASSWORD, "short 1", "short 1");
    assert!(short.body.contains("at least 14"), "{}", short.body);
    let no_digit = change(PASSWORD, "no digits in here", "no digits in here");
    assert!(no_digit.body.contains("a digit"), "{}", no_digit.body);
    assert!(
        signed_in(addr, &here) && signed_in(addr, &there),
        "nothing changed yet"
    );

    let done = change(PASSWORD, "a new password 1", "a new password 1");
    assert_eq!(done.status, 200, "{done:?}");
    let fresh = done.cookie("__Host-nex").expect("a new session here");
    assert!(signed_in(addr, &fresh));
    assert!(!signed_in(addr, &here), "the old session here ended");
    assert!(!signed_in(addr, &there), "the session elsewhere ended");
    let (old, _) = password_step(addr, MEMBER, PASSWORD, &[]);
    assert_eq!(old.status, 401, "the old password is refused");
    sign_in(addr, MEMBER, "a new password 1");
    drop(door);
}

#[test]
fn sign_out_everywhere_and_the_session_cap() {
    let data = temp_dir("sessions");
    let conf = config(&data.0, "[auth.session]\nmax_concurrent = 2\n");
    let (door, addr) = open(&conf);
    let first = sign_in(addr, MEMBER, PASSWORD);
    let second = sign_in(addr, MEMBER, PASSWORD);
    assert!(signed_in(addr, &first));
    let third = sign_in(addr, MEMBER, PASSWORD);
    assert!(!signed_in(addr, &first), "past the cap the oldest ends");
    assert!(signed_in(addr, &second) && signed_in(addr, &third));

    let out = post(
        addr,
        "/account/sign-out-everywhere",
        &[&third],
        &format!("csrf_token={}", encode(&token(addr, &third))),
    );
    assert_eq!(out.status, 303, "{out:?}");
    assert!(!signed_in(addr, &second) && !signed_in(addr, &third));
    drop(door);
}

/// The session ids a session's page offers to sign out (every one but its
/// own).
fn other_ids(addr: SocketAddr, session: &str) -> Vec<String> {
    let page = get(addr, "/account/security", &[session]);
    assert_eq!(page.status, 200, "{page:?}");
    assert_eq!(page.body.matches("(this one)").count(), 1, "{}", page.body);
    page.body
        .split("name=\"session\" value=\"")
        .skip(1)
        .filter_map(|s| s.get(..32))
        .map(str::to_owned)
        .collect()
}

#[test]
fn sessions_are_listed_and_signed_out_one_by_one() {
    let data = temp_dir("session-list");
    let conf = config(&data.0, "[auth.lockout]\naddress_attempts = 100\n");
    let (door, addr) = open(&conf);
    let a = sign_in(addr, MEMBER, PASSWORD);
    let b = sign_in(addr, MEMBER, PASSWORD);
    let c = sign_in(addr, MEMBER, PASSWORD);
    let page = get(addr, "/account/security", &[&a]);
    assert!(page.body.contains("<td>127.0.0.1</td>"), "{}", page.body);
    assert!(page.body.contains(" UTC</td>"), "{}", page.body);
    let others = other_ids(addr, &a);
    assert_eq!(others.len(), 2, "{others:?}");
    // b's own id is the one of a's others that b's page does not offer.
    let b_others = other_ids(addr, &b);
    let b_id = others
        .iter()
        .find(|id| !b_others.contains(id))
        .expect("b's id")
        .clone();
    let revoke = post(
        addr,
        "/account/sessions/revoke",
        &[&a],
        &format!("session={b_id}&csrf_token={}", encode(&token(addr, &a))),
    );
    assert_eq!(revoke.status, 200, "{revoke:?}");
    assert!(!signed_in(addr, &b), "b ended");
    assert!(signed_in(addr, &a) && signed_in(addr, &c), "only b");
    let again = post(
        addr,
        "/account/sessions/revoke",
        &[&a],
        &format!("session={b_id}&csrf_token={}", encode(&token(addr, &a))),
    );
    assert_eq!(again.status, 404, "already ended");

    let rest = post(
        addr,
        "/account/sessions/revoke-others",
        &[&a],
        &format!("csrf_token={}", encode(&token(addr, &a))),
    );
    assert_eq!(rest.status, 200);
    assert!(
        rest.body.contains("One other session is signed out."),
        "{}",
        rest.body
    );
    assert!(signed_in(addr, &a) && !signed_in(addr, &c));
    drop(door);
}

#[test]
fn sign_ins_at_the_same_moment_each_get_their_own_session_record() {
    let data = temp_dir("session-race");
    let conf = config(&data.0, "[auth.lockout]\naddress_attempts = 1000\n");
    let (door, addr) = open(&conf);
    let mut sessions = Vec::new();
    // Two at a time: as many passwords as are hashed at once.
    for _ in 0..4 {
        let gate = Arc::new(std::sync::Barrier::new(2));
        let both: Vec<_> = (0..2)
            .map(|_| {
                let gate = gate.clone();
                std::thread::spawn(move || {
                    let (pre, csrf) = form(addr);
                    gate.wait();
                    let done = post(
                        addr,
                        "/sign-in",
                        &[&pre],
                        &format!(
                            "email={}&password={}&csrf_token={}",
                            encode(MEMBER),
                            encode(PASSWORD),
                            encode(&csrf)
                        ),
                    );
                    assert_eq!(done.status, 303, "{done:?}");
                    done.cookie("__Host-nex").expect("session")
                })
            })
            .collect();
        for t in both {
            sessions.push(t.join().expect("sign-in"));
        }
    }
    // Every session sees itself once and the others as others.
    let all: Vec<Vec<String>> = sessions.iter().map(|s| other_ids(addr, s)).collect();
    let mut every: Vec<String> = all.iter().flatten().cloned().collect();
    every.sort();
    every.dedup();
    assert_eq!(every.len(), sessions.len(), "one id per session: {every:?}");
    let own: Vec<String> = all
        .iter()
        .map(|others| {
            let mine: Vec<&String> = every.iter().filter(|id| !others.contains(id)).collect();
            assert_eq!(mine.len(), 1, "{others:?}");
            mine[0].clone()
        })
        .collect();
    // Signing out one session's id from another ends that one only.
    for (k, id) in own.iter().enumerate().skip(1) {
        let by = &sessions[0];
        let r = post(
            addr,
            "/account/sessions/revoke",
            &[by],
            &format!("session={id}&csrf_token={}", encode(&token(addr, by))),
        );
        assert_eq!(r.status, 200, "{r:?}");
        assert!(!signed_in(addr, &sessions[k]), "session {k} ended");
        for (j, s) in sessions.iter().enumerate().skip(k + 1) {
            assert!(signed_in(addr, s), "session {j} still in after {k}");
        }
        assert!(signed_in(addr, by));
    }
    drop(door);
}

#[test]
fn an_administrator_disables_enables_and_removes_accounts() {
    let data = temp_dir("admin");
    let conf = config(&data.0, "");
    let (door, addr) = open(&conf);
    let member = sign_in(addr, MEMBER, PASSWORD);
    assert_eq!(
        get(addr, "/admin/accounts", &[&member]).status,
        403,
        "a member is not an administrator"
    );
    let admin = sign_in(addr, ADMIN, PASSWORD);
    let list = get(addr, "/admin/accounts", &[&admin]);
    assert_eq!(list.status, 200, "{list:?}");
    assert!(list.body.contains(MEMBER) && list.body.contains(ADMIN));
    let id_of = |page: &Got, email: &str| {
        let row = &page.body[page.body.find(&format!("<td>{email}</td>")).expect("row")..];
        let at = row.find("name=\"account\" value=\"").map(|i| i + 22);
        at.map(|i| row[i..i + 32].to_owned())
    };
    assert_eq!(
        id_of(&list, ADMIN),
        None,
        "no buttons on the viewer's own row"
    );
    let member_id = id_of(&list, MEMBER).expect("member's buttons");
    let act = |path: &str, extra: &str| {
        let csrf = get(addr, "/admin/accounts", &[&admin]).csrf();
        post(
            addr,
            path,
            &[&admin],
            &format!("account={member_id}{extra}&csrf_token={}", encode(&csrf)),
        )
    };

    let not_disabled = act("/admin/accounts/enable", "");
    assert_eq!(
        not_disabled.status, 422,
        "only a disabled or locked account"
    );
    assert!(
        not_disabled
            .body
            .contains("Only a disabled or locked account")
    );
    assert_eq!(act("/admin/accounts/disable", "").status, 303);
    assert!(!signed_in(addr, &member), "a disable ends the sessions");
    let (refused, _) = password_step(addr, MEMBER, PASSWORD, &[]);
    assert_eq!(refused.status, 401, "a disabled account cannot sign in");
    assert!(
        get(addr, "/admin/accounts", &[&admin])
            .body
            .contains("disabled")
    );

    assert_eq!(act("/admin/accounts/enable", "").status, 303);
    sign_in(addr, MEMBER, PASSWORD);

    let unconfirmed = act("/admin/accounts/remove", "");
    assert_eq!(unconfirmed.status, 422, "a removal is confirmed");
    assert_eq!(act("/admin/accounts/remove", "&confirm=on").status, 303);
    let (gone, _) = password_step(addr, MEMBER, PASSWORD, &[]);
    assert_eq!(gone.status, 401);
    assert!(
        !get(addr, "/admin/accounts", &[&admin])
            .body
            .contains(MEMBER)
    );
    drop(door);
}

#[test]
fn floors_refuse_the_boot() {
    let data = temp_dir("floors");
    for (extra, says) in [
        (
            "[auth.lockout]\nattempts = 0\n",
            "never left without a lockout",
        ),
        ("[auth.password]\nmin_length = 6\n", "at least 8"),
        ("[auth.passwrd]\nmin_length = 16\n", "auth.passwrd"),
    ] {
        let e = wasp::wire(&config(&data.0, extra)).expect_err(extra);
        assert!(e.contains(says), "{extra}: {e}");
    }
}

#[test]
fn a_reload_swaps_the_settings_and_refuses_a_floor() {
    use gateway_io::Gateway;
    use wasp_core::CoreSubsystem;
    use wasp_core::suite::{Member, System};

    let data = temp_dir("reload");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("port")
        .port();
    let file = data.0.join("wasp.conf");
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    let write = |extra: &str| {
        std::fs::write(
            &file,
            format!(
                "[log]
level = \"warn\"
stderr = false
file = false

[gateway]
listen = \"127.0.0.1:{port}\"
workers = 2
passports = 8

[site]
theme = \"{}\"
theme_poll = \"0s\"

[auth]
store = \"nex\"

[content]
store = \"nex\"

[nex]
path = \"{}\"

{extra}",
                slash(&theme),
                slash(&data.0.join("nex"))
            ),
        )
        .expect("config written");
    };
    write("");
    private(&file);
    let mut boot = System::builder("wasp-accounts-reload")
        .portable(data.0.join("root"))
        .config_file(&file)
        .process_wide(false)
        .crash_capture(false)
        .disable(Member::Signals)
        .boot()
        .expect("phase 0");
    let wiring = wasp::wire(&boot.foundation().config()).expect("wiring");
    NexAuth::new(wiring.nex.clone().expect("nex-db"))
        .ensure_account(MEMBER, PASSWORD, &[MEMBER_ROLE])
        .expect("member");
    boot.start(CoreSubsystem::new(wiring.core.clone()))
        .expect("core");
    boot.start(wiring.auth_policy.expect("auth policy"))
        .expect("auth policy");
    boot.start(Gateway::new(wiring.core).web("web", wiring.site))
        .expect("gateway");
    let system = boot.ready().expect("ready");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let session = sign_in(addr, MEMBER, PASSWORD);
    let change = |session: &str, new: &str| {
        post(
            addr,
            "/account/password",
            &[session],
            &format!(
                "current={}&new={}&again={}&csrf_token={}",
                encode(PASSWORD),
                encode(new),
                encode(new),
                encode(&token(addr, session))
            ),
        )
    };

    write(
        "[auth.lockout]
attempts = 0
",
    );
    assert!(system.reload().is_err(), "a floor refuses the reload");
    write(
        "[auth.password]
min_length = 20
",
    );
    system.reload().expect("reload");
    let refused = change(&session, "sixteen chars ok");
    assert_eq!(refused.status, 422, "{refused:?}");
    assert!(refused.body.contains("at least 20"), "{}", refused.body);
    let _ = system.shutdown();
}

/// Makes `path` this account's own on Windows, where a configuration file
/// other accounts can change is refused and a temporary folder can let them
/// (one some machines share with another group). Unix files here are made
/// owner-writable already.
fn private(path: &Path) {
    #[cfg(windows)]
    {
        let me = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
            (Ok(domain), Ok(user)) => format!("{domain}\\{user}"),
            (_, Ok(user)) => user,
            _ => return,
        };
        let _ = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{me}:F"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    let _ = path;
}

/// RFC 4648 base32 (no padding), as an authenticator app reads the key.
#[cfg(feature = "mfa")]
fn base32(text: &str) -> Vec<u8> {
    let mut bits = 0u64;
    let mut n = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => continue,
        };
        bits = (bits << 5) | u64::from(v);
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out
}

#[cfg(feature = "mfa")]
fn code_for(secret: &[u8], skew: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let at = now.saturating_add_signed(skew * 30);
    format!("{:06}", crypt_io::otp::totp(secret, at, 6).expect("totp"))
}

/// Turns two-step sign-in on for the session's account: its key and its
/// recovery codes.
#[cfg(feature = "mfa")]
fn turn_on(addr: SocketAddr, session: &str) -> (Vec<u8>, Vec<String>) {
    let start = get(addr, "/account/two-factor", &[session]);
    assert_eq!(start.status, 200, "{start:?}");
    let key = base32(
        &start
            .between("<code class=\"secret\">", "</code>")
            .expect("the key"),
    );
    assert!(start.body.contains("otpauth://totp/"), "{}", start.body);
    assert!(
        start.body.contains("name=\"password\""),
        "the password is asked"
    );
    let enroll = |code: &str, password: &str, csrf: &str| {
        post(
            addr,
            "/account/two-factor",
            &[session],
            &format!(
                "code={code}&password={}&csrf_token={}",
                encode(password),
                encode(csrf)
            ),
        )
    };
    // A borrowed session cannot turn it on: the password is needed.
    let no_password = enroll(&code_for(&key, 0), "not it", &start.csrf());
    assert_eq!(no_password.status, 422);
    assert!(no_password.body.contains("password is not right"));
    let wrong = enroll("000000", PASSWORD, &no_password.csrf());
    assert_eq!(wrong.status, 422);
    let done = enroll(&code_for(&key, 0), PASSWORD, &wrong.csrf());
    assert_eq!(done.status, 200, "{done:?}");
    let codes: Vec<String> = done
        .body
        .split("<li><code>")
        .skip(1)
        .filter_map(|s| s.split("</code>").next())
        .map(str::to_owned)
        .collect();
    (key, codes)
}

#[cfg(feature = "mfa")]
#[test]
fn two_step_sign_in_with_a_code_a_recovery_code_and_a_remembered_device() {
    let data = temp_dir("mfa");
    let conf = config(
        &data.0,
        "[auth.mfa]\nenabled = true\nrecovery_codes = 4\nremember_device = \"30d\"\n[auth.lockout]\naddress_attempts = 100\n",
    );
    let (door, addr) = open(&conf);
    let session = sign_in(addr, MEMBER, PASSWORD);
    let (key, codes) = turn_on(addr, &session);
    assert_eq!(codes.len(), 4, "recovery_codes of them: {codes:?}");
    assert!(
        get(addr, "/account/security", &[&session])
            .body
            .contains("On: signing in asks for a code")
    );

    // The password alone now leads to the second step.
    let (first, pre) = password_step(addr, MEMBER, PASSWORD, &[]);
    assert_eq!(first.status, 303, "{first:?}");
    assert!(first.cookie("__Host-nex").is_none(), "no session yet");
    assert!(
        first
            .field("location")
            .is_some_and(|l| l.starts_with("/sign-in/code"))
    );
    let step = first
        .cookie("__Host-nexstep")
        .expect("the half-done sign-in");
    let page = get(addr, "/sign-in/code", &[&pre, &step]);
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains("30 days"), "remembering is offered");
    // Bound to this visitor: another pre-session cookie does not carry it.
    let (other_pre, _) = form(addr);
    assert_eq!(get(addr, "/sign-in/code", &[&other_pre, &step]).status, 303);

    let wrong = post(
        addr,
        "/sign-in/code",
        &[&pre, &step],
        &format!("code=000000&csrf_token={}", encode(&page.csrf())),
    );
    assert_eq!(wrong.status, 401);
    let done = post(
        addr,
        "/sign-in/code",
        &[&pre, &step],
        &format!(
            "code={}&remember=on&csrf_token={}",
            code_for(&key, 1),
            encode(&wrong.csrf())
        ),
    );
    assert_eq!(done.status, 303, "{done:?}");
    let signed = done.cookie("__Host-nex").expect("session");
    assert!(signed_in(addr, &signed));
    let device = done.cookie("__Host-nexdev").expect("remembered");
    // The same half-done sign-in cannot be finished a second time.
    let again = post(
        addr,
        "/sign-in/code",
        &[&pre, &step],
        &format!(
            "code={}&csrf_token={}",
            code_for(&key, 0),
            encode(&page.csrf())
        ),
    );
    assert_eq!(again.status, 303, "{again:?}");
    assert_eq!(again.field("location"), Some("/sign-in"));
    assert!(again.cookie("__Host-nex").is_none(), "no second session");

    // The remembered device skips the code.
    let (skip, _) = password_step(addr, MEMBER, PASSWORD, &[&device]);
    assert_eq!(skip.status, 303);
    assert!(skip.cookie("__Host-nex").is_some(), "{skip:?}");

    // A recovery code signs in once.
    let recover = |code: &str| {
        let (first, pre) = password_step(addr, MEMBER, PASSWORD, &[]);
        let step = first.cookie("__Host-nexstep").expect("step");
        let page = get(addr, "/sign-in/code", &[&pre, &step]);
        post(
            addr,
            "/sign-in/code",
            &[&pre, &step],
            &format!("code={}&csrf_token={}", encode(code), encode(&page.csrf())),
        )
    };
    let used = recover(&codes[0]);
    assert_eq!(used.status, 303, "{used:?}");
    assert_eq!(
        used.field("location"),
        Some("/account/security?used=recovery")
    );
    assert_eq!(recover(&codes[0]).status, 401, "used up");

    // Forgetting the devices brings the code back.
    let forget = post(
        addr,
        "/account/forget-devices",
        &[&signed],
        &format!("csrf_token={}", encode(&token(addr, &signed))),
    );
    assert_eq!(forget.status, 200);
    let (asked, _) = password_step(addr, MEMBER, PASSWORD, &[&device]);
    assert!(asked.cookie("__Host-nex").is_none(), "{asked:?}");

    // Off, with the password.
    let off = post(
        addr,
        "/account/two-factor/off",
        &[&signed],
        &format!(
            "password={}&csrf_token={}",
            encode(PASSWORD),
            encode(&token(addr, &signed))
        ),
    );
    assert_eq!(off.status, 200, "{off:?}");
    sign_in(addr, MEMBER, PASSWORD);
    drop(door);
}

#[cfg(feature = "mfa")]
#[test]
fn a_role_that_requires_two_step_sets_it_up_at_sign_in() {
    let data = temp_dir("required");
    let conf = config(
        &data.0,
        "[auth.mfa]\nenabled = true\n[auth.role.admin.mfa]\nmode = \"required\"\n",
    );
    let (door, addr) = open(&conf);
    // A member is not asked.
    sign_in(addr, MEMBER, PASSWORD);
    let (first, pre) = password_step(addr, ADMIN, PASSWORD, &[]);
    assert_eq!(first.status, 303);
    assert!(first.cookie("__Host-nex").is_none());
    assert!(
        first
            .field("location")
            .is_some_and(|l| l.starts_with("/sign-in/setup"))
    );
    let step = first.cookie("__Host-nexstep").expect("step");
    let page = get(addr, "/sign-in/setup", &[&pre, &step]);
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains("needs two-step sign-in"));
    let key = base32(
        &page
            .between("<code class=\"secret\">", "</code>")
            .expect("key"),
    );
    let done = post(
        addr,
        "/sign-in/setup",
        &[&pre, &step],
        &format!(
            "code={}&csrf_token={}",
            code_for(&key, 0),
            encode(&page.csrf())
        ),
    );
    assert_eq!(done.status, 200, "{done:?}");
    assert!(done.body.contains("<li><code>"), "the recovery codes");
    let session = done.cookie("__Host-nex").expect("signed in");
    assert!(signed_in(addr, &session));
    // Required: it cannot be turned off.
    let off = post(
        addr,
        "/account/two-factor/off",
        &[&session],
        &format!(
            "password={}&csrf_token={}",
            encode(PASSWORD),
            encode(&token(addr, &session))
        ),
    );
    assert_eq!(off.status, 403);
    drop(door);
}

#[cfg(feature = "mfa")]
#[test]
fn sign_out_everywhere_forgets_remembered_devices() {
    let data = temp_dir("everywhere-devices");
    let conf = config(
        &data.0,
        "[auth.mfa]\nenabled = true\n[auth.lockout]\naddress_attempts = 100\n",
    );
    let (door, addr) = open(&conf);
    let session = sign_in(addr, MEMBER, PASSWORD);
    let (key, _) = turn_on(addr, &session);
    let (first, pre) = password_step(addr, MEMBER, PASSWORD, &[]);
    let step = first.cookie("__Host-nexstep").expect("step");
    let page = get(addr, "/sign-in/code", &[&pre, &step]);
    let done = post(
        addr,
        "/sign-in/code",
        &[&pre, &step],
        &format!(
            "code={}&remember=on&csrf_token={}",
            code_for(&key, 1),
            encode(&page.csrf())
        ),
    );
    let signed = done.cookie("__Host-nex").expect("session");
    let device = done.cookie("__Host-nexdev").expect("remembered");
    let (skip, _) = password_step(addr, MEMBER, PASSWORD, &[&device]);
    assert!(skip.cookie("__Host-nex").is_some(), "remembered");

    let out = post(
        addr,
        "/account/sign-out-everywhere",
        &[&signed],
        &format!("csrf_token={}", encode(&token(addr, &signed))),
    );
    assert_eq!(out.status, 303);
    let (asked, _) = password_step(addr, MEMBER, PASSWORD, &[&device]);
    assert!(
        asked.cookie("__Host-nex").is_none(),
        "the code again: {asked:?}"
    );
    drop(door);
}

#[cfg(feature = "mfa")]
#[test]
fn the_setup_step_refuses_a_disabled_account_and_is_good_once() {
    let data = temp_dir("setup-once");
    let conf = config(
        &data.0,
        "[auth.mfa]\nenabled = true\n[auth.role.admin.mfa]\nmode = \"required\"\n[auth.lockout]\naddress_attempts = 100\n",
    );
    let (door, addr, auth) = open_with_auth(&conf);
    let admin = auth.known(ADMIN).expect("directory").expect("admin");
    let member = auth.known(MEMBER).expect("directory").expect("member");

    // Disabled between the two steps: the set-up is refused.
    let (first, pre) = password_step(addr, ADMIN, PASSWORD, &[]);
    let step = first.cookie("__Host-nexstep").expect("step");
    auth.disable(admin, member).expect("disable");
    let refused = get(addr, "/sign-in/setup", &[&pre, &step]);
    assert_eq!(refused.status, 303, "{refused:?}");
    assert_eq!(refused.field("location"), Some("/sign-in"));
    assert!(auth.enable(admin, member).expect("enable"));

    // Set up once; the same cookies cannot enroll another key afterwards.
    let (first, pre) = password_step(addr, ADMIN, PASSWORD, &[]);
    let step = first.cookie("__Host-nexstep").expect("step");
    let page = get(addr, "/sign-in/setup", &[&pre, &step]);
    assert_eq!(page.status, 200, "{page:?}");
    let key = base32(
        &page
            .between("<code class=\"secret\">", "</code>")
            .expect("key"),
    );
    let done = post(
        addr,
        "/sign-in/setup",
        &[&pre, &step],
        &format!(
            "code={}&csrf_token={}",
            code_for(&key, 0),
            encode(&page.csrf())
        ),
    );
    assert_eq!(done.status, 200, "{done:?}");
    assert!(done.cookie("__Host-nex").is_some());
    let replay = get(addr, "/sign-in/setup", &[&pre, &step]);
    assert_eq!(replay.status, 303, "two-step is on now: {replay:?}");
    let replay = post(
        addr,
        "/sign-in/setup",
        &[&pre, &step],
        &format!(
            "code={}&csrf_token={}",
            code_for(&key, 1),
            encode(&page.csrf())
        ),
    );
    assert_eq!(replay.status, 303, "{replay:?}");
    assert!(replay.cookie("__Host-nex").is_none(), "no second session");
    drop(door);
}
