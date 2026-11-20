//! Host profiles: each `[host.<name>]` is its own site, chosen by `Host`,
//! with its own name, theme, content and error pages; a host no profile
//! names gets 421 (or the default profile), never another site's content.

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

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("wasp-hosts-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    TempDir(dir)
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
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

fn open(conf: &Config) -> (Door, SocketAddr) {
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
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        exempt: vec![std::net::IpAddr::from([127, 0, 0, 1])],
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

fn get(addr: SocketAddr, host: &str, target: &str, cookies: &[&str]) -> Got {
    let c = if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    };
    send(
        addr,
        &format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n{c}Connection: close\r\n\r\n"),
    )
}

fn post(addr: SocketAddr, host: &str, target: &str, cookies: &[&str], body: &str) -> Got {
    let c = if cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookies.join("; "))
    };
    send(
        addr,
        &format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\n{c}Sec-Fetch-Site: same-origin\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

fn sign_in(addr: SocketAddr, host: &str) -> String {
    let first = get(addr, host, "/sign-in", &[]);
    assert_eq!(first.status, 303, "{first:?}");
    let pre = first.cookie("__Host-nexpre").expect("pre");
    let page = get(addr, host, "/sign-in", &[&pre]);
    let done = post(
        addr,
        host,
        "/sign-in",
        &[&pre],
        &format!(
            "email={}&password={}&csrf_token={}",
            encode(EDITOR),
            encode(PASSWORD),
            encode(&page.csrf())
        ),
    );
    assert_eq!(done.status, 303, "{done:?}");
    done.cookie("__Host-nex").expect("session")
}

fn config(data: &Path, extra: &str) -> Config {
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    let blog = data.join("blog-theme");
    copy_dir(&theme, &blog);
    // The blog's theme says whose page it is.
    let base = blog.join("pages/base.html");
    let text = std::fs::read_to_string(&base).expect("base");
    std::fs::write(&base, text.replace("<main>", "<main><p>blog theme</p>")).expect("write");
    Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n[auth]\nstore = \"nex\"\n[content]\nstore = \"nex\"\n[nex]\npath = \"{}\"\n\
         [errors.404]\nmessage = \"Nothing at this address.\"\n\
         [host.main]\nhosts = [\"main.test\"]\ncontent = \"default\"\n\
         [host.blog]\nhosts = [\"blog.test\", \"*.blog.test\"]\nname = \"The Blog\"\ntheme = \"{}\"\ncontent = \"blog\"\n\
         [host.blog.errors.404]\nmessage = \"No such post.\"\n{extra}",
        slash(&theme),
        slash(&data.join("nex")),
        slash(&blog)
    ))
    .expect("config")
}

#[test]
fn each_host_gets_its_own_site_and_an_unknown_host_none() {
    let data = temp_dir("profiles");
    let conf = config(&data.0, "");
    let (door, addr) = open(&conf);

    let main = get(addr, "main.test", "/", &[]);
    assert_eq!(main.status, 200, "{main:?}");
    assert!(!main.body.contains("blog theme"), "{}", main.body);
    let blog = get(addr, "blog.test", "/", &[]);
    assert_eq!(blog.status, 200, "{blog:?}");
    assert!(blog.body.contains("blog theme"), "{}", blog.body);
    assert!(blog.body.contains("The Blog"), "{}", blog.body);
    // A wildcard: one more label.
    let ann = get(addr, "ann.blog.test:8080", "/", &[]);
    assert!(ann.body.contains("blog theme"), "{}", ann.body);
    // The guest cache never hands one host's page to another.
    let again = get(addr, "main.test", "/", &[]);
    assert!(!again.body.contains("blog theme"));

    for host in ["other.test", "a.b.blog.test", "blog.test.evil.test"] {
        let none = get(addr, host, "/", &[]);
        assert_eq!(none.status, 421, "{host}: {none:?}");
        assert!(!none.body.contains("blog") && !none.body.contains("WASP"));
    }

    // Content is the profile's own: a post on main is not on the blog.
    let ed = sign_in(addr, "main.test");
    let form = get(addr, "main.test", "/admin/new/post", &[&ed]);
    let saved = post(
        addr,
        "main.test",
        "/admin/save",
        &[&ed],
        &format!(
            "kind=post&slug=only-on-main&was=&title=Main+only&summary=&date=2026-11-20&body=Hi.&csrf_token={}",
            encode(&form.csrf())
        ),
    );
    assert_eq!(saved.status, 303, "{saved:?}");
    assert_eq!(
        get(addr, "main.test", "/posts/only-on-main", &[]).status,
        200
    );
    let missing = get(addr, "blog.test", "/posts/only-on-main", &[]);
    assert_eq!(missing.status, 404);
    // The blog's own error message; main falls back to [errors].
    assert!(missing.body.contains("No such post."), "{}", missing.body);
    let main_missing = get(addr, "main.test", "/posts/nothing", &[]);
    assert!(
        main_missing.body.contains("Nothing at this address."),
        "{}",
        main_missing.body
    );
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn a_default_profile_takes_the_hosts_no_profile_names() {
    let data = temp_dir("default");
    let conf = config(&data.0, "[host]\ndefault = \"main\"\n");
    let (door, addr) = open(&conf);
    let other = get(addr, "other.test", "/", &[]);
    assert_eq!(other.status, 200, "{other:?}");
    assert!(!other.body.contains("blog theme"));
    let _ = door.close(Duration::from_secs(2));
}
