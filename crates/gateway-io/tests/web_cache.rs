//! A web reply that carries the gate's cookie is never cacheable by a shared
//! cache, whatever web-net decided without seeing it (review F-5).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use gateway_io::{Door, Settings, WaspGate, WebServices, Who};
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::{
    AuthOut, Authentication, Authenticator, Core, Identity, Profile, RequestView, Rule,
};
use web_net::{App, Assets, CachePolicy, Context, Route, get};

/// Sets a cookie on every request, as a session gate does for a guest.
struct SetsCookie;

impl Authenticator for SetsCookie {
    fn authenticate(
        &self,
        _request: RequestView<'_>,
        _profile: &Profile,
        out: &mut AuthOut,
    ) -> Authentication {
        out.set_cookie(b"__Host-pre=visitor-A; Path=/; Secure; HttpOnly");
        Authentication::Identified(Identity::guest())
    }
}

#[test]
fn a_gate_cookie_forbids_every_cache() {
    let core = Arc::new(
        Core::builder()
            .authenticator(SetsCookie)
            .external("web")
            .profile("site", "web", |_| {})
            .load()
            .expect("core"),
    );
    let dir = std::env::temp_dir().join(format!("gateway-cache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    std::fs::write(dir.join("a.txt"), b"asset").expect("file");
    let page: Route<Who, Rule> = get("/news", |cx: &mut Context<'_, Who>| {
        cx.html(200, "<p>news</p>")
    })
    .public()
    .cache(CachePolicy::Public { max_age: 3600 });
    let app: App<WaspGate> = App::with_gate(WaspGate::new(core.access().clone()))
        .development()
        .assets(Assets::new("/static", dir.clone()).cache_control("public, max-age=31536000"))
        .route(page)
        .build()
        .expect("app");
    let mut web = WebServices::new();
    web.attach(core.service_tag("web").expect("tag"), app);
    let settings = Settings {
        listen: "127.0.0.1:0".into(),
        workers: 1,
        passports: 8,
        ..Settings::default()
    };
    let door = Door::open(core, &settings, UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    for path in ["/news", "/static/a.txt"] {
        let mut s = TcpStream::connect(addr).expect("connect");
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .expect("write");
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        let text = String::from_utf8_lossy(&buf).to_ascii_lowercase();
        let head = text.split("\r\n\r\n").next().unwrap_or_default();
        assert!(head.starts_with("http/1.1 200"), "{path}: {head}");
        assert!(head.contains("set-cookie: __host-pre=visitor-a"), "{head}");
        // Every Cache-Control line together, as a cache reads them.
        let directives: Vec<&str> = head
            .lines()
            .filter_map(|l| l.strip_prefix("cache-control:"))
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .collect();
        assert!(directives.contains(&"no-store"), "{path}: {head}");
        assert!(directives.contains(&"private"), "{path}: {head}");
    }
    let _ = door.close(Duration::from_secs(1));
    let _ = std::fs::remove_dir_all(&dir);
}
