//! The theme: page templates and error pages compiled from a folder, and the
//! watcher that reloads them while the site serves.
//!
//! ```text
//!  <theme>/pages/*.html    page templates (`base`, `home`, `post`, `page`), view `page`
//!  <theme>/errors/*.html   error pages (`error`, `error/404`, ...), view `error`
//!  <theme>/static/         files served under /theme/ (the stylesheet)
//! ```
//!
//! Templates compile once, when the theme is loaded or changed, never per
//! request. This is the only module that uses Luminess directly. A reload compiles both engines and checks the templates the
//! routes need before swapping anything; a theme with an error is refused
//! and the running one stays.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use luminess::Engine;
use luminess::web::{ErrorView, Theme};
use wasp_core::suite::config::Config;
use wasp_core::suite::lifecycle::{Commit, Deadline, Failure, Link, Subsystem};
use wasp_core::suite::log;

use crate::content::Entry;

/// The templates every theme must have (the routes name them).
pub const REQUIRED: &[&str] = &["home", "post", "page"];

// The view schemas: every Luminess name the site uses is in this module, so
// a Luminess upgrade changes this file and nothing else.
luminess::view!(Entry as "entry" {
    kind: text,
    slug: text,
    title: text,
    url: text,
    summary: text,
    body: html,
    date: text,
});

/// Site-wide values every page reads (`page.site`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteInfo {
    /// The site's name.
    pub name: String,
    /// The home page URL.
    pub home: String,
    /// The about page URL.
    pub about: String,
    /// The account page URL.
    pub account: String,
    /// The stylesheet URL.
    pub css: String,
}

luminess::view!(SiteInfo as "site" { name: text, home: text, about: text, account: text, css: text });

/// What a page template reads, as `page`. Content is shared, not copied:
/// `entry` and `posts` point into the manifest.
#[derive(Clone, Debug)]
pub struct Page {
    /// Site-wide values.
    pub site: Arc<SiteInfo>,
    /// The page title.
    pub title: String,
    /// The entry the route shows, if any.
    pub entry: Option<Arc<Entry>>,
    /// The post listing, newest first.
    pub posts: Arc<Vec<Arc<Entry>>>,
    /// A short message, for pages without an entry.
    pub message: String,
}

luminess::view!(Page as "page" {
    site: object(SiteInfo),
    title: text,
    entry: object(Entry),
    posts: list(object(Entry)),
    message: text,
});

/// The theme web-net renders with.
pub type SiteTheme = Theme<Page>;

/// Why a theme was refused.
#[derive(Debug)]
pub struct ThemeError(pub String);

impl std::fmt::Display for ThemeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ThemeError {}

/// Compiles both engines of the theme in `dir`, checking the required
/// templates, without touching anything running.
fn compile(
    dir: &Path,
) -> Result<(luminess::Templates<Page>, luminess::Templates<ErrorView>), ThemeError> {
    let read = |e: std::io::Error| ThemeError(format!("theme {}: {e}", dir.display()));
    let pages = Engine::<Page>::builder()
        .directory(dir.join("pages"), "html")
        .map_err(read)?
        .compile()
        .map_err(|e| ThemeError(format!("theme {} pages: {e}", dir.display())))?;
    let errors = Engine::<ErrorView>::builder()
        .directory(dir.join("errors"), "html")
        .map_err(read)?
        .compile()
        .map_err(|e| ThemeError(format!("theme {} errors: {e}", dir.display())))?;
    for name in REQUIRED {
        if !pages.contains(name) {
            return Err(ThemeError(format!(
                "theme {}: pages/{name}.html is missing",
                dir.display()
            )));
        }
    }
    Ok((pages, errors))
}

/// Loads the theme in `dir`.
pub fn load(dir: &Path) -> Result<SiteTheme, ThemeError> {
    let (pages, errors) = compile(dir)?;
    Ok(Theme::new(Engine::new(pages)).with_error_pages(Engine::new(errors)))
}

/// Compiles the theme in `dir` again and swaps it into `theme` (every clone,
/// so the running site). On any error nothing changes.
pub fn reload(theme: &SiteTheme, dir: &Path) -> Result<(), ThemeError> {
    let (pages, errors) = compile(dir)?;
    let _ = theme.pages().swap(pages);
    if let Some(e) = theme.error_pages() {
        let _ = e.swap(errors);
    }
    Ok(())
}

/// A cheap fingerprint of every file under `dir`: paths, sizes, and
/// modification times. A change in any of them means a reload.
#[must_use]
pub fn fingerprint(dir: &Path) -> u64 {
    let mut files: Vec<(PathBuf, u64, Option<SystemTime>)> = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            match e.metadata() {
                Ok(m) if m.is_dir() => pending.push(path),
                Ok(m) => files.push((path, m.len(), m.modified().ok())),
                Err(_) => {}
            }
        }
    }
    files.sort();
    let mut h = DefaultHasher::new();
    files.hash(&mut h);
    h.finish()
}

/// The theme as a kernel subsystem: it watches the theme folder (every
/// `poll`, when not zero) and reloads on any change, and recompiles on a
/// configuration reload. Started before the gateway, stopped after it.
pub struct ThemeWatcher {
    theme: SiteTheme,
    dir: PathBuf,
    poll: Duration,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    link: Option<Link>,
}

impl ThemeWatcher {
    /// A watcher for `theme`, loaded from `dir`.
    #[must_use]
    pub fn new(theme: SiteTheme, dir: PathBuf, poll: Duration) -> ThemeWatcher {
        ThemeWatcher {
            theme,
            dir,
            poll,
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            link: None,
        }
    }

    /// The theme it reloads (a clone renders from the same templates).
    #[must_use]
    pub fn theme(&self) -> &SiteTheme {
        &self.theme
    }

    /// The theme folder.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

fn reload_and_log(theme: &SiteTheme, dir: &Path, link: &Link, why: &str) {
    match reload(theme, dir) {
        Ok(()) => log::info!(link.foundation().log(), "theme reloaded", cause = why),
        Err(e) => log::warn!(
            link.foundation().log(),
            "theme refused; the running one stays",
            cause = why,
            reason = e.0.as_str()
        ),
    }
}

impl Subsystem for ThemeWatcher {
    fn name(&self) -> &str {
        "theme"
    }

    fn start(&mut self, link: &Link) -> Result<(), Failure> {
        self.link = Some(link.clone());
        if self.poll.is_zero() {
            return Ok(());
        }
        let (theme, dir, poll, stop, link) = (
            self.theme.clone(),
            self.dir.clone(),
            self.poll,
            self.stop.clone(),
            link.clone(),
        );
        let thread = std::thread::Builder::new()
            .name("theme-watch".into())
            .spawn(move || {
                let mut seen = fingerprint(&dir);
                loop {
                    std::thread::park_timeout(poll);
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let now = fingerprint(&dir);
                    if now != seen {
                        seen = now;
                        reload_and_log(&theme, &dir, &link, "theme folder changed");
                    }
                }
            })?;
        self.thread = Some(thread);
        Ok(())
    }

    fn stop(&mut self, _deadline: Deadline) -> Result<(), Failure> {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            t.thread().unpark();
            let _ = t.join();
        }
        Ok(())
    }

    /// A configuration reload recompiles the theme too (the folder may have
    /// changed without the watcher, when polling is off).
    fn reload(&mut self, _config: &Config) -> Result<Commit, Failure> {
        let (pages, errors) = compile(&self.dir)?;
        let theme = self.theme.clone();
        Ok(Commit::new(move || {
            let _ = theme.pages().swap(pages);
            if let Some(e) = theme.error_pages() {
                let _ = e.swap(errors);
            }
        }))
    }
}
