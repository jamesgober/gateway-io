//! The process finds `wasp.conf` in its working directory, and says so when
//! it finds no file at all; a refused boot logs the exit code it returns.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn folder(tag: &str) -> Folder {
    let dir = std::env::temp_dir().join(format!("wasp-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    Folder(dir)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

/// The process in `dir`, with every folder it would make kept inside it
/// and no configuration named by the environment.
fn wasp(dir: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wasp"));
    c.current_dir(dir)
        .env_remove("WASP_CONFIG")
        .env_remove("PORT")
        .env_remove("WASP_ADMIN_PASSWORD")
        .stdin(Stdio::null());
    for kind in ["DATA", "CONFIG", "CACHE", "LOGS", "STATE", "RUNTIME"] {
        c.env(format!("WASP_{kind}_DIR"), dir.join("dirs").join(kind));
    }
    c
}

#[test]
fn wasp_conf_in_the_working_directory_is_read() {
    if wasp_core::suite::sys::process::is_elevated().unwrap_or(true) {
        // Running as root or administrator, the working directory's file
        // is not read on purpose: the next test covers what is logged.
        return;
    }
    let dir = folder("cwd");
    let port = free_port();
    let theme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    std::fs::write(
        dir.0.join("wasp.conf"),
        format!(
            "[log]\nfile = false\n\n[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[gateway]\nlisten = \"127.0.0.1:{port}\"\nworkers = 1\n",
            slash(&theme)
        ),
    )
    .expect("config");
    let mut child = wasp(&dir.0)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let t = Instant::now();
    let mut listening = false;
    while t.elapsed() < Duration::from_secs(30) {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            listening = true;
            break;
        }
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert!(listening, "the port wasp.conf names is listening");
}

#[test]
fn no_configuration_file_is_a_warning_and_a_refusal_logs_its_code() {
    let dir = folder("none");
    // Behind an application server with no file: no site.hosts, so the
    // boot is refused with 78.
    let out = wasp(&dir.0)
        .env("PORT", free_port().to_string())
        .output()
        .expect("run");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    if let Ok(files) = std::fs::read_dir(dir.0.join("dirs").join("LOGS")) {
        for f in files.flatten() {
            text.push_str(&std::fs::read_to_string(f.path()).unwrap_or_default());
        }
    }
    assert_eq!(out.status.code(), Some(78), "{text}");
    assert!(text.contains("no configuration file"), "{text}");
    assert!(text.contains("\"level\":\"warn\""), "{text}");
    assert!(text.contains("refused to load"), "{text}");
    assert!(text.contains("\"exit_code\":78"), "{text}");
}
