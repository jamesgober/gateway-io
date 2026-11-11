//! The content store through the process's own wiring: what is stored in
//! bison-db is served after a restart, and the core owns the store and the
//! job runner.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use gateway_io::{Door, Settings, WebServices};
use wasp::content::{BisonStore, ContentStore, Stored};
use wasp_core::Job;
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

fn forward(p: &std::path::Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn config(store: &str, data: &std::path::Path) -> Config {
    let theme = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    Config::from_text(&format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[content]\nstore = \"{store}\"\npath = \"{}\"\n",
        forward(&theme),
        forward(&data.join("content.bison"))
    ))
    .expect("config")
}

fn open(config: &Config) -> (Door, SocketAddr) {
    let wiring = wasp::wire(config).expect("wiring");
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
    (door, addr)
}

/// Status and body of `GET target`.
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
    let status = text.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0);
    (status, text)
}

#[test]
fn stored_content_is_served_after_a_restart() {
    let dir = temp_dir("content-restart");
    let conf = config("bison", &dir.0);

    // First run: an empty store is seeded with the sample.
    let (door, addr) = open(&conf);
    assert_eq!(get(addr, "/posts/hello-world").0, 200);
    assert_eq!(get(addr, "/posts/kept").0, 404);
    door.close(Duration::from_secs(5));

    // Between runs, something else writes to the store (later: the editor).
    {
        let store = BisonStore::open(dir.0.join("content.bison")).expect("reopen");
        assert_eq!(store.load().expect("load").len(), 4, "seeded once");
        store
            .put(&Stored {
                kind: "post".into(),
                slug: "kept".into(),
                title: "Kept across a restart".into(),
                summary: "Stored in bison-db.".into(),
                body: "<p>Still here.</p>".into(),
                date: "2026-11-11".into(),
            })
            .expect("put");
    }

    // Second run: the stored post is served, and the sample is not added again.
    let (door, addr) = open(&conf);
    let (status, body) = get(addr, "/posts/kept");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("Kept across a restart"), "{body}");
    assert!(body.contains("<p>Still here.</p>"), "{body}");
    door.close(Duration::from_secs(5));
    let store = BisonStore::open(dir.0.join("content.bison")).expect("reopen");
    assert_eq!(store.load().expect("load").len(), 5);
}

#[test]
fn the_core_owns_the_store_and_runs_jobs() {
    let dir = temp_dir("content-owned");
    let wiring = wasp::wire(&config("bison", &dir.0)).expect("wiring");
    let names: Vec<&str> = wiring.core.providers().iter().map(|p| p.name()).collect();
    assert_eq!(names, ["content-bison"]);
    assert!(wiring.core.providers().iter().all(|p| p.flush().is_ok()));

    let ran = Arc::new(AtomicUsize::new(0));
    let r = ran.clone();
    let jobs = wiring.core.jobs().clone();
    jobs.submit(Job::new("count", move || {
        r.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }))
    .expect("queued");
    let stats = jobs.stop(Instant::now() + Duration::from_secs(5));
    assert_eq!(ran.load(Ordering::Relaxed), 1);
    assert_eq!((stats.queued, stats.done), (1, 1));
}

#[test]
fn memory_is_the_default_store_and_unknown_stores_refuse() {
    let dir = temp_dir("content-kinds");
    let theme = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    let plain = Config::from_text(&format!(
        "[site]
theme = \"{}\"
theme_poll = \"0s\"
",
        forward(&theme)
    ))
    .expect("config");
    let w = wasp::wire(&plain).expect("wiring");
    let names: Vec<&str> = w.core.providers().iter().map(|p| p.name()).collect();
    assert_eq!(names, ["content-memory"]);
    let err = wasp::wire(&config("disk", &dir.0)).expect_err("refused");
    assert!(err.contains("content.store"), "{err}");
}
