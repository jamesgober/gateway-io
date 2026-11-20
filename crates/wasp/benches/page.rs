//! The cost of rendering one themed page, without the network: the post page
//! and the home page of the sample site, through the theme web-net uses.
//!
//! ```text
//! cargo bench -p wasp --bench page
//! ```
//!
//! std only; fastest round of 9 x 50,000 renders, one thread.

use std::hint::black_box;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use wasp::content::{Kind, Manifest};
use wasp::theme::{self, Page, SiteInfo};
use web_net::{Output, Render};

fn measure(mut f: impl FnMut()) -> f64 {
    for _ in 0..5_000 {
        f();
    }
    (0..9)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..50_000 {
                f();
            }
            t.elapsed().as_nanos() as f64 / 50_000.0
        })
        .fold(f64::INFINITY, f64::min)
}

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../themes/default");
    let theme = theme::load(&dir).expect("theme");
    let manifest = Manifest::sample();
    let site = Arc::new(SiteInfo {
        name: "WASP".into(),
        home: "/".into(),
        about: "/about".into(),
        account: "/account".into(),
        admin: "/admin".into(),
        css: "/theme/site.css".into(),
        icon: "/theme/favicon.svg".into(),
    });
    let post = theme.pages().template("post").expect("post");
    let home = theme.pages().template("home").expect("home");
    let entry = manifest.get(Kind::Post, "the-passport");
    let mut buf = Vec::with_capacity(4096);

    let view_cost = measure(|| {
        black_box(Page {
            site: site.clone(),
            title: "The passport".into(),
            head: std::sync::Arc::default(),
            entry: entry.clone(),
            posts: manifest.posts(),
            message: String::new(),
            form: None,
            editor: None,
            security: None,
        });
    });
    let page = Page {
        site: site.clone(),
        title: "The passport".into(),
        head: std::sync::Arc::default(),
        entry: entry.clone(),
        posts: manifest.posts(),
        message: String::new(),
        form: None,
        editor: None,
        security: None,
    };
    let post_cost = measure(|| {
        buf.clear();
        let mut out = Output::new(&mut buf, 1 << 20);
        web_net::Render::render(theme.pages(), post, &page, &mut out).expect("render");
        black_box(&buf);
    });
    let post_len = buf.len();
    let home_page = Page {
        title: "Home".into(),
        entry: None,
        ..page.clone()
    };
    let home_cost = measure(|| {
        buf.clear();
        let mut out = Output::new(&mut buf, 1 << 20);
        web_net::Render::render(theme.pages(), home, &home_page, &mut out).expect("render");
        black_box(&buf);
    });
    println!("| step | ns |");
    println!("|---|---|");
    println!("| build the page view (Arc clones, one title) | {view_cost:.0} |");
    println!("| render the post page ({post_len} B) | {post_cost:.0} |");
    println!(
        "| render the home page ({} B, 3 posts) | {home_cost:.0} |",
        buf.len()
    );
}
