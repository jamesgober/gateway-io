//! Behind a reverse proxy the gateway sees each visitor, not the proxy: the
//! client named by a trusted proxy's `X-Forwarded-For` is the one the door
//! bans and charges (review F-14).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use gateway_io::{Door, IngressMode, Settings, WebServices};
use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;

const BANNED: &str = "203.0.113.9";

fn open(ingress: IngressMode) -> (Door, SocketAddr) {
    let core = Arc::new(
        Core::builder()
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core"),
    );
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 8,
        ban: vec![BANNED.parse().expect("ip")],
        ingress,
        ..Settings::default()
    };
    let door =
        Door::open(core, &settings, UrgentLine::detached(), WebServices::new()).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr)
}

/// The status of `GET /` with these extra fields; 0 when the connection
/// closed without one.
fn status(addr: SocketAddr, fields: &str) -> u16 {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let _ = s.write_all(
        format!("GET / HTTP/1.1\r\nHost: localhost\r\n{fields}Connection: close\r\n\r\n")
            .as_bytes(),
    );
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf)
        .get(9..12)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

#[test]
fn behind_a_proxy_the_door_judges_each_visitor() {
    let (door, addr) = open(IngressMode::Proxy {
        trusted: vec!["127.0.0.1".into()],
        forwarded_proto: true,
    });
    assert_eq!(
        status(addr, "X-Forwarded-For: 203.0.113.10\r\n"),
        200,
        "a visitor"
    );
    let banned = status(addr, &format!("X-Forwarded-For: {BANNED}\r\n"));
    assert_ne!(banned, 200, "the banned visitor, behind the same proxy");
    assert_eq!(
        status(addr, "X-Forwarded-For: 203.0.113.11\r\n"),
        200,
        "the proxy itself is never banned for one visitor"
    );
    assert_ne!(
        status(addr, ""),
        200,
        "a trusted proxy must name the client"
    );
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn direct_ingress_ignores_forwarded_headers() {
    let (door, addr) = open(IngressMode::Direct);
    assert_eq!(
        status(addr, &format!("X-Forwarded-For: {BANNED}\r\n")),
        200,
        "a client cannot name itself someone else"
    );
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn proxy_ingress_needs_a_trust_list() {
    let refused = |text: &str| Settings::from_config(&Config::from_text(text).expect("config"));
    assert!(refused("[gateway]\ningress = \"proxy\"\n").is_err());
    assert!(
        refused("[gateway]\ningress = \"proxy\"\ntrusted_proxies = [\"not an address\"]\n")
            .is_err()
    );
    assert!(refused("[gateway]\ningress = \"sideways\"\n").is_err());
    let ok = refused(
        "[gateway]\ningress = \"proxy\"\ntrusted_proxies = [\"127.0.0.1\", \"10.0.0.0/8\"]\n",
    )
    .expect("valid");
    assert_eq!(ok.ingress.trusted().len(), 2);
}

#[test]
fn shed_settings_are_checked() {
    let read = |text: &str| Settings::from_config(&Config::from_text(text).expect("config"));
    let d = read("").expect("defaults");
    assert_eq!(
        (d.shed_passports, d.shed_slow, d.shed_check),
        (90, Duration::from_secs(1), Duration::from_millis(250))
    );
    assert!(
        read(
            "[gateway]
shed_passports = 101
"
        )
        .is_err()
    );
    assert!(
        read(
            "[gateway]
shed_check = \"5ms\"
"
        )
        .is_err()
    );
    assert!(
        read(
            "[gateway]
shed_check = \"2m\"
"
        )
        .is_err()
    );
    let off = read(
        "[gateway]
shed_passports = 0
shed_slow = \"0s\"
",
    )
    .expect("off");
    assert!(!off.shed_marks().on());
}

#[test]
fn an_application_server_port_means_loopback_behind_its_front_end() {
    let config = Config::from_text("[gateway]\nlisten = \"0.0.0.0:8080\"\n").expect("config");
    let base = Settings::from_config(&config).expect("settings");
    let s = base.clone().with_port(Some("3007"), false).expect("port");
    assert_eq!(s.listen, "127.0.0.1:3007", "never a public address");
    assert_eq!(
        s.ingress.trusted().len(),
        2,
        "only the local front end is trusted"
    );
    let kept = base
        .clone()
        .with_port(Some("3007"), true)
        .expect("explicit ingress stays");
    assert_eq!(kept.ingress, IngressMode::Direct);
    assert!(base.clone().with_port(Some("web"), false).is_err());
    assert!(base.clone().with_port(Some("0"), false).is_err());
    assert_eq!(base.clone().with_port(None, false).expect("none"), base);
}

#[test]
fn unknown_keys_are_refused() {
    let read = |text: &str| Settings::from_config(&Config::from_text(text).expect("config"));
    let err = read(
        "[gateway]
acess_log = true
",
    )
    .expect_err("a typo");
    assert!(err.0.contains("gateway.acess_log"), "{err}");
    assert!(
        read(
            "[door]
banned = []
"
        )
        .is_err()
    );
    assert!(
        read(
            "[gateway]
access_log = true
[door]
ban = []
"
        )
        .is_ok()
    );
}

#[test]
fn a_start_shim_socket_takes_the_place_of_the_port() {
    let config = Config::from_text("[gateway]\nlisten = \"0.0.0.0:8080\"\n").expect("config");
    let base = Settings::from_config(&config).expect("settings");
    let sock = "/home/me/app/run/wasp.sock";
    let s = base.clone().with_front_end(Some("3007"), Some(sock), false);
    if cfg!(unix) {
        let s = s.expect("a socket");
        assert_eq!(
            s.listen,
            format!("unix:{sock}"),
            "the socket wins over PORT"
        );
        assert_eq!(s.ingress.trusted().len(), 2, "the shim names the client");
        let kept = base
            .clone()
            .with_front_end(None, Some(sock), true)
            .expect("explicit ingress stays");
        assert_eq!(kept.ingress, IngressMode::Direct);
    } else {
        assert!(s.is_err(), "no Unix sockets here");
    }
    assert!(base.clone().with_front_end(None, Some(""), false).is_err());
    assert_eq!(
        base.clone()
            .with_front_end(Some("3007"), None, false)
            .expect("port"),
        base.clone().with_port(Some("3007"), false).expect("port")
    );

    let read = |listen: &str| {
        Settings::from_config(
            &Config::from_text(&format!("[gateway]\nlisten = \"{listen}\"\n")).expect("config"),
        )
    };
    assert!(read("unix:").is_err(), "a socket needs its path");
    assert_eq!(read("unix:/run/wasp.sock").is_ok(), cfg!(unix));
}

#[cfg(unix)]
#[test]
fn behind_a_unix_socket_only_this_user_connects_and_names_the_client() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;

    let dir = std::env::temp_dir().join(format!("gw-unix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("wasp.sock");
    let core = Arc::new(
        Core::builder()
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core"),
    );
    let settings = Settings {
        workers: 1,
        passports: 8,
        ban: vec![BANNED.parse().expect("ip")],
        ..Settings::default()
    }
    .with_front_end(None, Some(sock.to_str().expect("path")), false)
    .expect("settings");
    let door =
        Door::open(core, &settings, UrgentLine::detached(), WebServices::new()).expect("opens");
    let mode = std::fs::metadata(&sock)
        .expect("socket")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "owner only: {mode:o}");

    let status = |fields: &str| -> u16 {
        let mut s = UnixStream::connect(&sock).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let _ = s.write_all(
            format!("GET / HTTP/1.1\r\nHost: localhost\r\n{fields}Connection: close\r\n\r\n")
                .as_bytes(),
        );
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf)
            .get(9..12)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    // This process runs as the socket's user: the shim's case.
    assert_eq!(
        status("X-Forwarded-For: 203.0.113.10\r\n"),
        200,
        "a visitor"
    );
    assert_ne!(
        status(&format!("X-Forwarded-For: {BANNED}\r\n")),
        200,
        "the banned visitor, named by the shim"
    );
    assert_ne!(status(""), 200, "the shim must name the client");
    let _ = door.close(Duration::from_secs(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
fn hello_core() -> Arc<Core> {
    Arc::new(
        Core::builder()
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core"),
    )
}

#[cfg(unix)]
fn socket_settings(sock: &std::path::Path) -> Settings {
    Settings {
        workers: 1,
        passports: 8,
        ..Settings::default()
    }
    .with_front_end(None, Some(sock.to_str().expect("path")), false)
    .expect("settings")
}

#[cfg(unix)]
#[test]
fn a_socket_path_holding_anything_else_is_refused_and_left_alone() {
    use std::os::unix::net::UnixListener;

    let dir = std::env::temp_dir().join(format!("gw-unix-path-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let sock = dir.join("wasp.sock");
    let open = || {
        Door::open(
            hello_core(),
            &socket_settings(&sock),
            UrgentLine::detached(),
            WebServices::new(),
        )
    };

    // A plain file: refused, and still there with its bytes.
    std::fs::write(&sock, b"not a socket").expect("file");
    let e = open().err().expect("a file is refused");
    assert!(e.to_string().contains("not a socket"), "{e}");
    assert_eq!(std::fs::read(&sock).expect("kept"), b"not a socket");
    std::fs::remove_file(&sock).expect("remove");

    // A live socket (something listens): refused, still listening.
    let live = UnixListener::bind(&sock).expect("live");
    assert!(open().is_err(), "a live socket is refused");
    assert!(
        std::os::unix::net::UnixStream::connect(&sock).is_ok(),
        "still listening"
    );
    drop(live);

    // A stale socket of this user (its listener gone, the file left): replaced.
    let door = open().expect("a stale socket of ours is replaced");
    let _ = door.close(Duration::from_secs(2));

    // No probe file is left behind.
    let left: Vec<_> = std::fs::read_dir(&dir)
        .expect("read")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".wasp-owner-"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Whether this machine lets the test run a command as `nobody` without a
/// password, and has curl to do it with.
#[cfg(unix)]
fn as_nobody_available() -> Result<(), String> {
    let ok = |cmd: &mut std::process::Command| {
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    if !ok(std::process::Command::new("curl").arg("--version")) {
        return Err("curl is not installed".into());
    }
    if !ok(std::process::Command::new("sudo").args(["-n", "-u", "nobody", "true"])) {
        return Err("sudo cannot run a command as nobody without a password here".into());
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn another_user_cannot_reach_the_socket() {
    use std::os::unix::fs::PermissionsExt;

    if let Err(why) = as_nobody_available() {
        // In CI it must run, so a green run there means it did.
        assert!(
            std::env::var_os("CI").is_none(),
            "another_user_cannot_reach_the_socket must run in CI: {why}"
        );
        eprintln!("skipped another_user_cannot_reach_the_socket: {why}");
        return;
    }
    // In /tmp, which every user can pass through (a per-user temporary
    // folder would keep `nobody` out before the socket is reached).
    let dir = std::path::Path::new("/tmp").join(format!("gw-unix-peer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    // The folder open to everyone, so only the socket stands in the way.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let sock = dir.join("wasp.sock");
    let door = Door::open(
        hello_core(),
        &socket_settings(&sock),
        UrgentLine::detached(),
        WebServices::new(),
    )
    .expect("opens");
    let curl = |user: Option<&str>| -> String {
        let mut cmd = match user {
            Some(u) => {
                let mut c = std::process::Command::new("sudo");
                c.args(["-n", "-u", u, "curl"]);
                c
            }
            None => std::process::Command::new("curl"),
        };
        let out = cmd
            .args([
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "5",
            ])
            .arg("--unix-socket")
            .arg(&sock)
            .args(["-H", "X-Forwarded-For: 203.0.113.10", "http://localhost/"])
            .output()
            .expect("curl");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert_eq!(curl(None), "200", "this user, the shim's case");
    // The socket's mode (0600) keeps another user out.
    assert_eq!(curl(Some("nobody")), "000", "refused by the socket's mode");
    // And with the mode opened up, the peer check still closes the
    // connection before a byte is read.
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).expect("chmod");
    assert_eq!(curl(Some("nobody")), "000", "refused by the peer check");
    assert_eq!(curl(None), "200");
    let _ = door.close(Duration::from_secs(2));
    let _ = std::fs::remove_dir_all(&dir);
}
