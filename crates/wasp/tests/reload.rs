//! A configuration reload through the kernel, end to end: the door's bans
//! and allow list change while the gateway keeps serving.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use gateway_io::Gateway;
use wasp_core::CoreSubsystem;
use wasp_core::suite::{Member, System};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("a free port")
}

fn write_conf(path: &Path, port: u16, door: &str) {
    let text = format!(
        "[log]\nlevel = \"warn\"\nstderr = false\nfile = false\n\n[gateway]\nlisten = \"127.0.0.1:{port}\"\nworkers = 2\npassports = 8\n\n[door]\n{door}\n"
    );
    std::fs::write(path, text).expect("config written");
}

/// The status of `GET /`, or `None` when the connection got no response.
fn status(addr: SocketAddr) -> Option<u16> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    std::str::from_utf8(buf.get(9..12)?).ok()?.parse().ok()
}

struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_reload_bans_and_lifts_at_the_door() {
    let dir = TempDir(std::env::temp_dir().join(format!("wasp-reload-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).expect("dir");
    let conf = dir.0.join("wasp.conf");
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    write_conf(&conf, port, "ban = []");

    let mut boot = System::builder("wasp-reload-test")
        .portable(dir.0.join("root"))
        .config_file(&conf)
        .process_wide(false)
        .crash_capture(false)
        .disable(Member::Signals)
        .boot()
        .expect("phase 0");
    let wiring = wasp::wire(&boot.foundation().config()).expect("phases 1 to 3");
    boot.start(CoreSubsystem::new(wiring.core.clone()))
        .expect("core");
    boot.start(Gateway::new(wiring.core).web("web", wiring.site))
        .expect("gateway, last");
    let system = boot.ready().expect("ready");

    assert_eq!(status(addr), Some(200));

    // Ban ourselves through the configuration: the door refuses at once.
    write_conf(&conf, port, "ban = [\"127.0.0.1\"]");
    system.reload().expect("reload");
    assert_eq!(status(addr), None, "refused at the door after the reload");

    // A reload that fails validation changes nothing: still banned.
    let text = std::fs::read_to_string(&conf).expect("read");
    std::fs::write(&conf, text.replace("workers = 2", "workers = 0")).expect("bad config");
    assert!(system.reload().is_err(), "workers = 0 is refused");
    assert_eq!(
        status(addr),
        None,
        "the refused reload left the ban in force"
    );

    // Lift it: served again.
    write_conf(&conf, port, "ban = []");
    system.reload().expect("reload");
    assert_eq!(status(addr), Some(200));

    let _ = system.shutdown();
}
