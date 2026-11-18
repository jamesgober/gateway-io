//! The theme through the whole path: themed pages, error pages, a theme
//! reloaded while the site serves, and escaping in a real page.

// A site needs a sign-in store: the gatekeeper or nex-db.
#![cfg(any(feature = "gatekeeper", feature = "store-nex"))]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_io::{Door, Gateway, Settings, WaspGate, WebServices};
use wasp::theme::{self, Page, SiteInfo};
use wasp_core::suite::config::Config;
use wasp_core::suite::kernel::UrgentLine;
use wasp_core::suite::{Member, System};
use wasp_core::{Core, CoreSubsystem};
use web_net::{App, get};

/// A page on a site behind the core's own access gate.
type SiteCx<'a> = web_net::Context<'a, gateway_io::Who, theme::SiteEngine>;
type SiteRoute = web_net::Route<gateway_io::Who, wasp_core::Rule, theme::SiteEngine>;

fn default_theme() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default")
}

fn slash(p: &Path) -> String {
    p.display()
        .to_string()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

/// A private copy of the default theme, removed on drop.
struct ThemeCopy(PathBuf);

impl ThemeCopy {
    fn new(tag: &str) -> ThemeCopy {
        let dst = std::env::temp_dir().join(format!("wasp-theme-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dst);
        copy_dir(&default_theme(), &dst);
        ThemeCopy(dst)
    }
}

impl Drop for ThemeCopy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("dir");
    for e in std::fs::read_dir(src).expect("read").flatten() {
        let to = dst.join(e.file_name());
        if e.path().is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).expect("copy");
        }
    }
}

fn settings() -> Settings {
    Settings {
        listen: "127.0.0.1:0".into(),
        workers: 2,
        passports: 8,
        ..Settings::default()
    }
}

#[derive(Debug)]
struct Got {
    status: u16,
    head: String,
    body: String,
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
    Got {
        status: head.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0),
        head: head.to_owned(),
        body: body.to_owned(),
    }
}

fn get_path(addr: SocketAddr, path: &str) -> Got {
    send(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
}

/// The process's wiring over `theme`, with the watcher off.
fn open_site(theme: &Path) -> (Door, SocketAddr, wasp::theme::ThemeWatcher) {
    let conf = format!(
        "[site]\ntheme = \"{}\"\ntheme_poll = \"0s\"\n",
        slash(theme)
    );
    let wiring = wasp::wire(&Config::from_text(&conf).expect("config")).expect("wiring");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("tag"), wiring.site);
    let door = Door::open(wiring.core, &settings(), UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    (door, addr, wiring.theme)
}

#[test]
fn themed_pages_from_the_manifest() {
    let (door, addr, _watcher) = open_site(&default_theme());
    let home = get_path(addr, "/");
    assert_eq!(home.status, 200);
    assert!(
        home.body.contains("<title>Home | WASP</title>"),
        "{}",
        home.body
    );
    assert!(
        home.body
            .contains(r#"<link rel="stylesheet" href="/theme/site.css">"#)
    );
    // Newest first, as the manifest listed them at save time.
    let order: Vec<usize> = [
        "/posts/escaping",
        "/posts/the-passport",
        "/posts/hello-world",
    ]
    .iter()
    .map(|u| home.body.find(u).expect("listed"))
    .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");

    let post = get_path(addr, "/posts/the-passport");
    assert_eq!(post.status, 200);
    assert!(
        post.body.contains("<h1>The passport</h1>")
            && post.body.contains("<time>2026-11-09</time>")
    );
    assert!(
        post.body.contains("<p>Every request carries one"),
        "the body prepared at save"
    );

    let about = get_path(addr, "/about");
    assert!(
        about
            .body
            .contains("<p>A site in memory, themed from a folder"),
        "{}",
        about.body
    );

    let css = get_path(addr, "/theme/site.css");
    assert_eq!(css.status, 200);
    assert!(
        css.head
            .to_ascii_lowercase()
            .contains("content-type: text/css")
    );
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn escaping_in_a_real_page() {
    let (door, addr, _watcher) = open_site(&default_theme());
    let got = get_path(addr, "/posts/escaping");
    assert_eq!(got.status, 200);
    let title = "Tom &amp; Jerry &lt;script&gt;alert(1)&lt;/script&gt;";
    assert!(
        got.body.contains(&format!("<title>{title} | WASP</title>")),
        "{}",
        got.body
    );
    assert!(got.body.contains(&format!("<h1>{title}</h1>")));
    assert!(
        got.body
            .contains("<p>&lt;b&gt;Not bold.&lt;/b&gt; &amp; not a tag either.</p>")
    );
    assert!(
        !got.body.contains("<script>") && !got.body.contains("<b>"),
        "no markup from content"
    );
    // The home page lists the same title, escaped too.
    assert!(get_path(addr, "/").body.contains(title));
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn error_pages_for_404_405_and_500() {
    // The site's own routes, plus one that fails, on the same theme.
    let core = Arc::new(
        Core::builder()
            .external("web")
            .profile("site", "web", |_| {})
            .load()
            .expect("core"),
    );
    let site = Arc::new(SiteInfo {
        name: "WASP".into(),
        home: "/".into(),
        about: "/about".into(),
        account: "/account".into(),
        admin: "/admin".into(),
        css: "/theme/site.css".into(),
    });
    let ok: SiteRoute = get("/ok", move |cx: &mut SiteCx<'_>| {
        cx.render(&Page {
            site: site.clone(),
            title: "Ok".into(),
            entry: None,
            posts: Arc::new(Vec::new()),
            message: "fine".into(),
            form: None,
            editor: None,
        })
    })
    .public()
    .template("page");
    let boom: SiteRoute = get("/boom", |_cx: &mut SiteCx<'_>| {
        Err(web_net::Error::internal("test.boom"))
    })
    .public()
    .template("page");
    let app = App::with_gate(WaspGate::new(core.access().clone()))
        .render(theme::Timed::untimed(
            theme::load(&default_theme()).expect("theme"),
        ))
        .development()
        .route(ok)
        .route(boom)
        .build()
        .expect("app");
    let mut web = WebServices::new();
    web.attach(core.service_tag("web").expect("tag"), app);
    let door = Door::open(core, &settings(), UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");

    assert_eq!(get_path(addr, "/ok").status, 200);

    // 404: the theme's own error/404 page.
    let got = get_path(addr, "/missing");
    assert_eq!(got.status, 404);
    assert!(got.body.contains("<h1>Nothing here</h1>"), "{}", got.body);
    assert!(got.body.contains("Reference: "));

    // 405: the theme's generic error page, with Allow.
    let got = send(
        addr,
        "DELETE /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(got.status, 405);
    assert!(
        got.head.to_ascii_lowercase().contains("allow: get"),
        "{}",
        got.head
    );
    assert!(
        got.body.contains("<h1>405 Method Not Allowed</h1>"),
        "{}",
        got.body
    );

    // 500: a handler error, the generic page, nothing of the error's code.
    let got = get_path(addr, "/boom");
    assert_eq!(got.status, 500);
    assert!(got.body.contains("<h1>500 "), "{}", got.body);
    assert!(
        !got.body.contains("test.boom"),
        "the reason stays in the log"
    );
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn a_theme_reloads_while_serving_and_a_broken_one_is_refused() {
    let copy = ThemeCopy::new("direct");
    let (door, addr, watcher) = open_site(&copy.0);
    assert!(get_path(addr, "/").body.contains("<h1>Home</h1>"));

    // Change the home template: one reload, and the next request has it.
    let home = copy.0.join("pages/home.html");
    let src = std::fs::read_to_string(&home).expect("read");
    std::fs::write(
        &home,
        src.replace(
            "<h1>{{ page.title }}</h1>",
            "<h1 class=\"v2\">{{ page.title }}</h1>",
        ),
    )
    .expect("write");
    theme::reload(watcher.theme(), &copy.0).expect("reload");
    assert!(
        get_path(addr, "/")
            .body
            .contains("<h1 class=\"v2\">Home</h1>")
    );

    // A broken theme (an unknown field) is refused; the running one stays.
    std::fs::write(
        &home,
        "{% extends \"base\" %}{% block content %}{{ page.nope }}{% endblock %}",
    )
    .expect("write");
    let err = theme::reload(watcher.theme(), &copy.0).expect_err("refused");
    assert!(err.0.contains("nope") || err.0.contains("pages"), "{err}");
    assert!(
        get_path(addr, "/")
            .body
            .contains("<h1 class=\"v2\">Home</h1>"),
        "still the last good theme"
    );

    // A theme missing a template the routes need is refused too.
    std::fs::remove_file(&home).expect("rm");
    let err = theme::reload(watcher.theme(), &copy.0).expect_err("refused");
    assert!(err.0.contains("home"), "{err}");
    assert_eq!(get_path(addr, "/").status, 200);
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn the_watcher_reloads_a_changed_theme_through_the_kernel() {
    let copy = ThemeCopy::new("watch");
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("port")
        .port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
    let conf_dir = std::env::temp_dir().join(format!("wasp-theme-conf-{}", std::process::id()));
    std::fs::create_dir_all(&conf_dir).expect("dir");
    let conf = conf_dir.join("wasp.conf");
    std::fs::write(
        &conf,
        format!(
            "[log]\nlevel = \"warn\"\nstderr = false\nfile = false\n\n[gateway]\nlisten = \"127.0.0.1:{port}\"\nworkers = 2\npassports = 8\n\n[site]\ntheme = \"{}\"\ntheme_poll = \"50ms\"\n",
            slash(&copy.0)
        ),
    )
    .expect("conf");
    let mut boot = System::builder("wasp-theme-test")
        .portable(conf_dir.join("root"))
        .config_file(&conf)
        .process_wide(false)
        .crash_capture(false)
        .disable(Member::Signals)
        .boot()
        .expect("phase 0");
    let wiring = wasp::wire(&boot.foundation().config()).expect("wiring");
    boot.start(CoreSubsystem::new(wiring.core.clone()))
        .expect("core");
    boot.start(wiring.theme).expect("theme watcher");
    boot.start(Gateway::new(wiring.core).web("web", wiring.site))
        .expect("gateway");
    let system = boot.ready().expect("ready");
    assert!(get_path(addr, "/about").body.contains("<h1>About</h1>"));

    // Edit the theme on disk; the watcher notices and reloads.
    let page = copy.0.join("pages/page.html");
    let src = std::fs::read_to_string(&page).expect("read");
    std::fs::write(
        &page,
        src.replace(
            "<h1>{{ page.title }}</h1>",
            "<h1>{{ page.title }} (live)</h1>",
        ),
    )
    .expect("write");
    let until = Instant::now() + Duration::from_secs(10);
    let mut body = String::new();
    while Instant::now() < until {
        body = get_path(addr, "/about").body;
        if body.contains("<h1>About (live)</h1>") {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        body.contains("<h1>About (live)</h1>"),
        "reloaded while serving: {body}"
    );

    let _ = system.shutdown();
    let _ = std::fs::remove_dir_all(&conf_dir);
}

#[test]
fn error_pages_of_a_site_in_a_folder_keep_its_base_path() {
    let copy_conf = format!(
        "[site]\nbase = \"/blog\"\ntheme = \"{}\"\ntheme_poll = \"0s\"\n",
        slash(&default_theme())
    );
    let wiring = wasp::wire(&Config::from_text(&copy_conf).expect("config")).expect("wiring");
    let mut web = WebServices::new();
    web.attach(wiring.core.service_tag("web").expect("tag"), wiring.site);
    let door = Door::open(wiring.core, &settings(), UrgentLine::detached(), web).expect("opens");
    let addr = door.local_addr().expect("addr");
    let got = get_path(addr, "/blog/missing");
    assert_eq!(got.status, 404);
    assert!(
        got.body.contains(r#"href="/blog/theme/site.css""#),
        "the error page's stylesheet is outside the site's folder: {}",
        got.body
    );
    let _ = door.close(Duration::from_secs(1));
}

#[test]
fn a_template_that_breaks_the_compiler_is_refused_not_fatal() {
    // Review F-2: a 60,000-term `or` chain overflowed Luminess 0.9.2's stack
    // and ended the process from the watcher thread.
    let copy = ThemeCopy::new("deep-chain");
    let theme = theme::load(&copy.0).expect("the default theme loads");
    let chain = vec!["page.message"; 60_000].join(" or ");
    std::fs::write(
        copy.0.join("pages/page.html"),
        format!("{{% extends \"base\" %}}{{% block content %}}{{% if {chain} %}}x{{% endif %}}{{% endblock %}}"),
    )
    .expect("write");
    let dir = copy.0.clone();
    let t = std::thread::Builder::new()
        .name("theme-watch".into())
        .spawn(move || theme::reload(&theme, &dir).map(|()| theme))
        .expect("spawn");
    let refused = t.join().expect("the watcher thread survives");
    assert!(refused.is_err(), "the deep theme is refused");
}

#[test]
fn a_theme_over_its_limits_or_with_a_link_is_refused() {
    let copy = ThemeCopy::new("too-big");
    let theme = theme::load(&copy.0).expect("loads");
    // Over the total size: refused before anything is compiled.
    let big = "x".repeat(usize::try_from(theme::MAX_THEME_BYTES).expect("fits") + 1);
    std::fs::write(copy.0.join("pages/huge.html"), big).expect("write");
    let err = theme::reload(&theme, &copy.0).expect_err("refused");
    assert!(err.0.contains("limits"), "{err}");
    std::fs::remove_file(copy.0.join("pages/huge.html")).expect("remove");
    theme::reload(&theme, &copy.0).expect("back within the limits");

    // A symbolic link (when this machine lets a test make one).
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/hostname", copy.0.join("pages/leak.html")).expect("link");
        let err = theme::reload(&theme, &copy.0).expect_err("refused");
        assert!(err.0.contains("symbolic links"), "{err}");
    }
}
