//! Step 7 end to end over loopback: the gatekeeper authenticates in the
//! core, authorizes in the site, and signs in and out with its own CSRF
//! tokens.
#![cfg(feature = "gatekeeper")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use gateway_io::gatekeeper::gatekeeper_io::Standing;
use gateway_io::{Door, Settings, WebServices};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse battery staple";

fn open() -> (Door, SocketAddr) {
    let theme = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../themes/default")
        .display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/");
    let config = Config::from_text(&format!(
        "[site]\ntheme = \"{theme}\"\ntheme_poll = \"0s\"\n"
    ))
    .expect("config");
    let wiring = wasp::wire(&config).expect("wiring");
    wiring
        .gatekeeper
        .as_ref()
        .expect("the gatekeeper")
        .create_account(EMAIL, PASSWORD, Standing::Active, &["member"])
        .expect("account");
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
    (door, addr)
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

    fn cookies(&self) -> Vec<&str> {
        self.fields
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The `name=value` pair of the last cookie set under `name`.
    fn cookie(&self, name: &str) -> Option<String> {
        self.cookies()
            .into_iter()
            .rev()
            .find(|c| c.starts_with(&format!("{name}=")))
            .map(|c| c.split(';').next().unwrap_or_default().to_owned())
    }

    /// The value of the hidden `csrf` field on the page.
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

/// Signs in; the session cookie (`__Host-sid=...`).
fn sign_in(addr: SocketAddr) -> String {
    let form = get(addr, "/sign-in", &[]);
    let pre = form.cookie("__Host-pre").expect("pre-session cookie");
    let done = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, &form.csrf()),
    );
    assert_eq!(done.status, 303, "{done:?}");
    done.cookie("__Host-sid").expect("session cookie")
}

#[test]
fn sign_in_account_and_sign_out() {
    let (door, addr) = open();

    // A guest is sent to the sign-in page, with the way back.
    let account = get(addr, "/account", &[]);
    assert_eq!(account.status, 303);
    assert_eq!(account.field("location"), Some("/sign-in?next=/account"));

    // The form: a pre-session cookie and a token bound to it.
    let form = get(addr, "/sign-in?next=/account", &[]);
    assert_eq!(form.status, 200, "{form:?}");
    let pre = form.cookie("__Host-pre").expect("pre-session cookie");
    assert!(
        form.body.contains("action=\"/sign-in?next=/account\""),
        "{}",
        form.body
    );

    // Signing in: 303 back, the session cookie set, the pre-session cleared.
    let done = post(
        addr,
        "/sign-in?next=/account",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, &form.csrf()),
    );
    assert_eq!(done.status, 303, "{done:?}");
    assert_eq!(done.field("location"), Some("/account"));
    let sid = done.cookie("__Host-sid").expect("session cookie");
    assert!(sid.len() > "__Host-sid=".len() + 20, "{sid}");
    assert_eq!(done.cookie("__Host-pre").as_deref(), Some("__Host-pre="));
    let set = done
        .cookies()
        .into_iter()
        .find(|c| c.starts_with("__Host-sid="))
        .expect("set");
    for attr in ["HttpOnly", "Secure", "Path=/", "SameSite="] {
        assert!(set.contains(attr), "{attr} in {set}");
    }

    // Signed in: the account page, with a sign-out button.
    let page = get(addr, "/account", &[&sid]);
    assert_eq!(page.status, 200, "{page:?}");
    assert!(page.body.contains("Signed in as"), "{}", page.body);
    assert!(page.cookies().is_empty(), "{page:?}");
    let csrf = page.csrf();

    // Signed in, the sign-in page sends the visitor on.
    let again = get(addr, "/sign-in", &[&sid]);
    assert_eq!(again.status, 303);
    assert_eq!(again.field("location"), Some("/account"));

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

    // Signing out: 303 home, the cookie cleared, the session gone on the server.
    let out = post(
        addr,
        "/sign-out",
        &[&sid],
        "same-origin",
        &format!("csrf_token={}", encode(&csrf)),
    );
    assert_eq!(out.status, 303, "{out:?}");
    assert_eq!(out.field("location"), Some("/"));
    assert_eq!(out.cookie("__Host-sid").as_deref(), Some("__Host-sid="));
    let after = get(addr, "/account", &[&sid]);
    assert_eq!(after.status, 303, "the old cookie no longer signs in");
    assert_eq!(after.cookie("__Host-sid").as_deref(), Some("__Host-sid="));
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn refused_sign_ins_say_the_same_thing() {
    let (door, addr) = open();
    let form = get(addr, "/sign-in", &[]);
    let pre = form.cookie("__Host-pre").expect("pre");

    let wrong = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, "not the password", &form.csrf()),
    );
    assert_eq!(wrong.status, 401, "{wrong:?}");
    assert!(wrong.cookie("__Host-sid").is_none());
    // The form again, the email kept, a fresh token.
    assert!(
        wrong.body.contains(&format!("value=\"{EMAIL}\"")),
        "{}",
        wrong.body
    );
    let message = |g: &Got| {
        let at = g.body.find("role=\"alert\">").expect("message") + 13;
        g.body[at..at + g.body[at..].find('<').expect("end")].to_owned()
    };

    let unknown = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body("nobody@example.com", PASSWORD, &form.csrf()),
    );
    assert_eq!(unknown.status, 401);
    assert_eq!(message(&unknown), message(&wrong), "no account enumeration");

    // A token not bound to this visitor's pre-session cookie.
    let other = get(addr, "/sign-in", &[]);
    let stolen = post(
        addr,
        "/sign-in",
        &[&pre],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, &other.csrf()),
    );
    assert_eq!(stolen.status, 401, "{stolen:?}");
    assert!(stolen.cookie("__Host-sid").is_none());

    // No pre-session cookie at all.
    let bare = post(
        addr,
        "/sign-in",
        &[],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, &form.csrf()),
    );
    assert_eq!(bare.status, 401);
    assert!(bare.cookie("__Host-sid").is_none());

    // From another site.
    let cross = post(
        addr,
        "/sign-in",
        &[&pre],
        "cross-site",
        &sign_in_body(EMAIL, PASSWORD, &form.csrf()),
    );
    assert_eq!(cross.status, 401);
    assert!(cross.cookie("__Host-sid").is_none());
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn signing_in_over_a_dead_session_keeps_the_new_one() {
    let (door, addr) = open();
    let old = sign_in(addr);
    let page = get(addr, "/account", &[&old]);
    let out = post(
        addr,
        "/sign-out",
        &[&old],
        "same-origin",
        &format!("csrf_token={}", encode(&page.csrf())),
    );
    assert_eq!(out.status, 303);

    // The browser still sends the dead cookie while signing in again.
    let form = get(addr, "/sign-in", &[&old]);
    assert_eq!(form.status, 200, "{form:?}");
    let pre = form.cookie("__Host-pre").expect("pre");
    let done = post(
        addr,
        "/sign-in",
        &[&old, &pre],
        "same-origin",
        &sign_in_body(EMAIL, PASSWORD, &form.csrf()),
    );
    assert_eq!(done.status, 303, "{done:?}");
    // The gate's clearing cookie comes first, the new session last: a
    // browser keeps the last one.
    let sids: Vec<&str> = done
        .cookies()
        .into_iter()
        .filter(|c| c.starts_with("__Host-sid="))
        .collect();
    assert_eq!(sids.len(), 2, "{done:?}");
    assert!(sids[0].starts_with("__Host-sid=;"), "{sids:?}");
    let new = done.cookie("__Host-sid").expect("new");
    assert_ne!(new, "__Host-sid=");
    assert_eq!(get(addr, "/account", &[&new]).status, 200);
    let _ = door.close(Duration::from_secs(1));
}
