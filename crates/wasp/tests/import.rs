//! Content import end to end: files into the bison store, then served by the
//! site after a boot.

// A site needs a sign-in store: the gatekeeper or nex-db.
#![cfg(any(feature = "gatekeeper", feature = "store-nex"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use gateway_io::{Door, Settings, WebServices};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(name: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("wasp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    TempDir(dir)
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn config(store: &str, data: &Path) -> Config {
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[content]\nstore = \"{store}\"\npath = \"{}\"\n",
        slash(&theme),
        slash(&data.join("content.bison"))
    ))
    .expect("config")
}

fn write(dir: &Path, rel: &str, text: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().expect("parent")).expect("dir");
    std::fs::write(p, text).expect("write");
}

fn get(addr: SocketAddr, target: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    s.write_all(
        format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
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

#[test]
fn imported_files_are_served_after_a_boot() {
    let data = temp_dir("import-data");
    let from = temp_dir("import-from");
    write(
        &from.0,
        "posts/from-a-file.md",
        "title: From a file\ndate: 2026-11-18\nsummary: Imported.\ndescription: Found by search.\nrobots: noindex\n\nFirst <b>paragraph</b>.\n\nSecond.\n",
    );
    write(
        &from.0,
        "pages/colophon.md",
        "title: Colophon\n\nSet in plain text.\n",
    );
    write(
        &from.0,
        "posts/Bad Slug.md",
        "title: Bad\ndate: 2026-11-18\n\nx\n",
    );
    write(&from.0, "posts/no-date.md", "title: No date\n\nx\n");
    write(&from.0, "posts/typo.md", "tilte: Typo\n\nx\n");
    write(
        &from.0,
        "posts/bad-robots.md",
        "title: Bad robots\ndate: 2026-11-18\nrobots: noarchive\n\nx\n",
    );
    let conf = config("bison", &data.0);

    let report = wasp::import(&conf, &data.0, &from.0).expect("import");
    assert_eq!(report.saved, ["from-a-file", "colophon"], "{report:?}");
    assert_eq!(report.refused.len(), 4, "{report:?}");

    // Imported again: replaced, not added twice.
    let again = wasp::import(&conf, &data.0, &from.0).expect("again");
    assert_eq!(again.saved.len(), 2);

    let wiring = wasp::wire(&conf).expect("wiring");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("web"), wiring.site);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 4,
        ..Settings::default()
    };
    let door = Door::open(wiring.core, &settings, UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    let (status, body) = get(addr, "/posts/from-a-file");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("From a file"), "{body}");
    assert!(
        body.contains("<p>First &lt;b&gt;paragraph&lt;/b&gt;.</p><p>Second.</p>"),
        "escaped, split into paragraphs: {body}"
    );
    assert!(
        body.contains("<meta name=\"description\" content=\"Found by search.\">"),
        "{body}"
    );
    assert!(
        body.contains("<meta name=\"robots\" content=\"noindex\">"),
        "{body}"
    );
    let (home, listing) = get(addr, "/");
    assert_eq!(home, 200);
    assert_eq!(listing.matches("From a file").count(), 1, "listed once");
    let _ = door.close(Duration::from_secs(2));
}

#[test]
fn an_import_needs_a_durable_store_nobody_holds() {
    let data = temp_dir("import-refused");
    let from = temp_dir("import-refused-from");
    write(&from.0, "posts/x.md", "title: X\ndate: 2026-11-18\n\nx\n");
    let err = wasp::import(&config("memory", &data.0), &data.0, &from.0).expect_err("memory");
    assert!(err.contains("memory"), "{err}");

    // A running instance holds the store: stop it first.
    let conf = config("bison", &data.0);
    let running = wasp::wire(&conf).expect("running");
    let err = wasp::import(&conf, &data.0, &from.0).expect_err("held");
    assert!(err.contains("another instance"), "{err}");
    drop(running);

    let err = wasp::import(&conf, &data.0, &data.0.join("missing")).expect_err("no folder");
    assert!(err.contains("not a folder"), "{err}");
}
