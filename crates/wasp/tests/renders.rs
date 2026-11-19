//! Every request renders at most once: a page once, a guest's cached page
//! never, an error page once, and a reply in parts never again for its
//! later parts. Counted at the site's render engine, through the whole path.

// A site needs a sign-in store: the gatekeeper or nex-db.
#![cfg(any(feature = "gatekeeper", feature = "store-nex"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::theme::RenderCounts;
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

/// The large file a reply in parts carries: web-net sends a file over 1 MiB
/// in parts of 256 KiB, so this one goes out in 16.
const FILE_BYTES: usize = 4 * 1024 * 1024;

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

struct Site {
    door: Door,
    addr: SocketAddr,
    renders: Arc<RenderCounts>,
    file: Vec<u8>,
    _assets: Folder,
}

/// The site, with its own assets folder (`tag` keeps parallel tests apart).
fn open(tag: &str) -> Site {
    let assets =
        Folder(std::env::temp_dir().join(format!("wasp-renders-{tag}-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&assets.0);
    std::fs::create_dir_all(&assets.0).expect("dir");
    let file: Vec<u8> = (0..FILE_BYTES).map(|i| (i % 251) as u8).collect();
    std::fs::write(assets.0.join("big.bin"), &file).expect("file");
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    let conf = format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\nassets = \"{}\"\n",
        slash(&theme),
        slash(&assets.0)
    );
    let wiring = wasp::wire(&Config::from_text(&conf).expect("config")).expect("wiring");
    let renders = wiring.renders.clone();
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 8,
        ..Settings::default()
    };
    let door = Door::open(wiring.core, &settings, UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    Site {
        door,
        addr,
        renders,
        file,
        _assets: assets,
    }
}

/// The status, the head, and the body (dechunked).
fn get(addr: SocketAddr, target: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(20)))
        .expect("timeout");
    s.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .expect("write");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("head") + 4;
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let status = head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    let chunked = head.lines().any(|l| {
        l.split_once(':').is_some_and(|(n, v)| {
            n.eq_ignore_ascii_case("transfer-encoding") && v.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let body = if chunked {
        dechunk(&buf[end..]).unwrap_or_else(|| {
            panic!(
                "chunked body cut: {} bytes after the head
{head}",
                buf.len() - end
            )
        })
    } else {
        buf[end..].to_vec()
    };
    (status, head, body)
}

fn dechunk(mut b: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = b.windows(2).position(|w| w == b"\r\n")?;
        let size =
            usize::from_str_radix(std::str::from_utf8(&b[..line_end]).ok()?.trim(), 16).ok()?;
        b = &b[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(b.get(..size)?);
        b = b.get(size + 2..)?;
    }
}

/// Renders (pages, error pages) a request caused.
fn renders_of(site: &Site, target: &str) -> ((u64, u64), (u16, String)) {
    let before = (site.renders.pages(), site.renders.error_pages());
    let (status, _, body) = get(site.addr, target);
    let after = (site.renders.pages(), site.renders.error_pages());
    (
        (after.0 - before.0, after.1 - before.1),
        (status, String::from_utf8_lossy(&body).into_owned()),
    )
}

/// One whole document: one doctype, one `<html>`, one `<body>`, one `</html>`.
fn one_document(page: &str) {
    for mark in ["<!doctype html>", "<html", "<body", "</body>", "</html>"] {
        assert_eq!(page.matches(mark).count(), 1, "{mark} in:\n{page}");
    }
}

#[test]
fn a_page_renders_once() {
    let site = open("page");
    // A query is never cached: every request is a fresh render.
    for _ in 0..3 {
        let (renders, (status, page)) = renders_of(&site, "/posts/the-passport?from=feed");
        assert_eq!((status, renders), (200, (1, 0)), "{page}");
        one_document(&page);
        assert_eq!(page.matches("<h1>The passport</h1>").count(), 1, "{page}");
    }
    let _ = site.door.close(Duration::from_secs(1));
}

#[test]
fn a_cached_guest_page_renders_once_and_never_again() {
    let site = open("cached");
    let (renders, (status, first)) = renders_of(&site, "/posts/the-passport");
    assert_eq!(
        (status, renders),
        (200, (1, 0)),
        "the first guest renders it"
    );
    one_document(&first);
    for _ in 0..3 {
        let (renders, (status, again)) = renders_of(&site, "/posts/the-passport");
        assert_eq!((status, renders), (200, (0, 0)), "from the cache");
        assert_eq!(again, first, "the same page, once");
    }
    let _ = site.door.close(Duration::from_secs(1));
}

#[test]
fn an_error_page_renders_once() {
    let site = open("error");
    for target in ["/posts/nope", "/no/such/page"] {
        let (renders, (status, page)) = renders_of(&site, target);
        assert_eq!((status, renders), (404, (0, 1)), "{target}: {page}");
        one_document(&page);
        assert_eq!(page.matches("<h1>").count(), 1, "{page}");
    }
    let _ = site.door.close(Duration::from_secs(1));
}

#[test]
fn a_reply_in_parts_renders_nothing_for_any_part() {
    let site = open("parts");
    let before = site.renders.total();
    let (status, head, body) = get(site.addr, "/static/big.bin");
    assert_eq!(status, 200, "{head}");
    assert_eq!(body.len(), site.file.len(), "{head}");
    assert!(body == site.file, "the file, whole and once");
    assert_eq!(site.renders.total(), before, "a file renders nothing");

    // The same file again while a page is served between its parts.
    let addr = site.addr;
    let download = std::thread::spawn(move || get(addr, "/static/big.bin"));
    let (renders, (status, _)) = renders_of(&site, "/posts/the-passport?between=parts");
    assert_eq!((status, renders), (200, (1, 0)));
    let (status, _, body) = download.join().expect("thread");
    assert_eq!((status, body.len()), (200, FILE_BYTES));
    assert_eq!(site.renders.total(), before + 1, "only the page rendered");

    let until = Instant::now() + Duration::from_secs(2);
    while site.door.tickets_held() != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(site.door.tickets_held(), 0);
    let _ = site.door.close(Duration::from_secs(1));
}
