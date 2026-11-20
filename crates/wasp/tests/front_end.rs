//! Behind an application server (`PORT`), the process stops when its front
//! end lets go: standard input closing, or the parent process dying. A new
//! start on the same data folder comes up even while the old process is
//! still draining.

#![cfg(all(unix, feature = "store-nex"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Folder(PathBuf);

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn folder(tag: &str) -> Folder {
    let dir = std::env::temp_dir().join(format!("wasp-front-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let theme = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    std::fs::write(
        dir.join("wasp.conf"),
        format!(
            "[log]\nlevel = \"info\"\nfile = false\n\n[site]\nhosts = [\"localhost\"]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n\n[content]\nstore = \"nex\"\n\n[auth]\nstore = \"nex\"\n\n[nex]\npath = \"{}\"\n\n[gateway]\nworkers = 1\ndrain = \"3s\"\n",
            theme.display(),
            dir.join("data/nex").display()
        ),
    )
    .expect("config");
    Folder(dir)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// Keeps every folder the process makes (data, logs, ...) inside `dir`, so
/// tests running at once never share one, and nothing lands in the home
/// folder.
fn own_folders(c: &mut Command, dir: &Folder) {
    for kind in ["DATA", "CONFIG", "CACHE", "LOGS", "STATE", "RUNTIME"] {
        c.env(format!("WASP_{kind}_DIR"), dir.0.join("dirs").join(kind));
    }
}

/// Where a process's standard error goes.
fn log_of(dir: &Folder, port: u16) -> PathBuf {
    dir.0.join(format!("wasp-{port}.log"))
}

fn wasp(dir: &Folder, port: u16) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wasp"));
    c.current_dir(&dir.0)
        .env("PORT", port.to_string())
        .env("WASP_CONFIG", dir.0.join("wasp.conf"))
        .env_remove("WASP_ADMIN_PASSWORD")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(log_of(dir, port)).expect("log file"));
    own_folders(&mut c, dir);
    c
}

/// The end of a process's standard error, for a failure message.
fn tail(log: &Path) -> String {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(15)..].join("\n")
}

/// `/ready`'s status, through a front end that names the client.
fn ready(port: u16) -> Option<u16> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(200)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.write_all(
        b"GET /ready HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n",
    )
    .ok()?;
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    std::str::from_utf8(buf.get(9..12)?).ok()?.parse().ok()
}

fn wait_ready(port: u16, child: &mut Child, log: &Path) {
    let until = Instant::now() + Duration::from_secs(30);
    while Instant::now() < until {
        if let Ok(Some(status)) = child.try_wait() {
            panic!("wasp exited before it was ready: {status}\n{}", tail(log));
        }
        if ready(port) == Some(200) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("wasp was not ready within 30s\n{}", tail(log));
}

fn wait_exit(child: &mut Child, within: Duration) -> Option<std::process::ExitStatus> {
    let until = Instant::now() + within;
    while Instant::now() < until {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[test]
fn closing_standard_input_stops_it_cleanly_and_a_restart_overlapping_the_drain_comes_up() {
    let dir = folder("stdin");
    let port = free_port();
    let mut old = wasp(&dir, port)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn");
    wait_ready(port, &mut old, &log_of(&dir, port));

    // The front end lets go; a new process starts at once on the same data
    // folder (and a new port), while the old one is still stopping.
    drop(old.stdin.take());
    let port2 = free_port();
    let mut new = wasp(&dir, port2)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn");

    let status = wait_exit(&mut old, Duration::from_secs(20)).expect("the old process stops");
    assert!(
        status.success(),
        "a clean stop: {status}\n{}",
        tail(&log_of(&dir, port))
    );
    wait_ready(port2, &mut new, &log_of(&dir, port2));

    drop(new.stdin.take());
    let status = wait_exit(&mut new, Duration::from_secs(20)).expect("the new process stops");
    assert!(status.success(), "{status}");
}

#[test]
fn a_parent_that_dies_takes_it_down() {
    let dir = folder("parent");
    let port = free_port();
    // A stand-in front end: a shell that starts wasp (standard input from
    // /dev/null, so only the parent watch can stop it), prints its pid, and
    // waits. Killing the shell hands wasp to another parent.
    let log = log_of(&dir, port);
    let mut sh = Command::new("sh");
    sh.arg("-c")
        .arg("\"$0\" < /dev/null 2> \"$1\" & echo $!; wait")
        .arg(env!("CARGO_BIN_EXE_wasp"))
        .arg(&log)
        .current_dir(&dir.0)
        .env("PORT", port.to_string())
        .env("WASP_CONFIG", dir.0.join("wasp.conf"))
        .env_remove("WASP_ADMIN_PASSWORD")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    own_folders(&mut sh, &dir);
    let mut shell = sh.spawn().expect("spawn");
    let mut line = String::new();
    let mut out = shell.stdout.take().expect("stdout");
    let mut byte = [0u8; 1];
    while out.read(&mut byte).is_ok_and(|n| n == 1) && byte[0] != b'\n' {
        line.push(char::from(byte[0]));
    }
    let pid: u32 = line.trim().parse().expect("pid");
    let until = Instant::now() + Duration::from_secs(30);
    while ready(port) != Some(200) {
        assert!(Instant::now() < until, "wasp was not ready within 30s");
        assert!(
            alive(pid),
            "wasp exited before it was ready\n{}",
            tail(&log)
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    shell.kill().expect("kill the parent");
    let _ = shell.wait();
    let until = Instant::now() + Duration::from_secs(20);
    while alive(pid) {
        assert!(
            Instant::now() < until,
            "wasp {pid} still runs 20s after its parent died (state: {})\n{}",
            std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default(),
            tail(&log)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // The lock went with it: a new start on the same data folder comes up.
    let port2 = free_port();
    let mut next = wasp(&dir, port2)
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn");
    wait_ready(port2, &mut next, &log_of(&dir, port2));
    drop(next.stdin.take());
    assert!(wait_exit(&mut next, Duration::from_secs(20)).is_some());
}
