//! The theme: page templates and error pages compiled from a folder, and the
//! watcher that reloads them while the site serves; and the admin pages'
//! own theme, kept apart from it.
//!
//! ```text
//!  <theme>/pages/*.html    page templates (`base`, `home`, `post`, `page`, `sign-in`, `account`), view `page`
//!  <theme>/errors/*.html   error pages (`error`, `error/404`, ...), view `error`
//!  <theme>/static/         files served under /theme/ (the stylesheet)
//!
//!  admin theme             built into the binary (`[admin] theme = "builtin"`), or a
//!                          folder of the same shape when `[admin] custom_theme = true`:
//!  <admin>/pages/*.html    `base`, `list`, `edit`, view `page`; routes name them `admin/<name>`
//!  <admin>/static/         files served under /admin/static/ (the built-in one: admin.css)
//! ```
//!
//! A route's `admin/...` template always comes from the admin theme, never
//! from the site theme: a site theme cannot restyle the admin pages, or put
//! anything into them.
//!
//! Templates compile once, when the theme is loaded or changed, never per
//! request. This is the only module that uses Luminess directly. A reload compiles both engines and checks the templates the
//! routes need before swapping anything; a theme with an error is refused
//! and the running one stays.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use luminess::Engine;
use luminess::web::{ErrorView, Theme};
use wasp_core::suite::config::Config;
use wasp_core::suite::lifecycle::{Commit, Deadline, Failure, Link, Subsystem};
use wasp_core::suite::log;

use crate::content::Entry;

/// The templates every theme must have (the routes name them).
pub const REQUIRED: &[&str] = &["home", "post", "page", "sign-in", "account"];

/// The templates every admin theme must have (routes name them `admin/<name>`).
pub const ADMIN_REQUIRED: &[&str] = &[
    "list",
    "edit",
    "security",
    "two-factor",
    "codes",
    "code",
    "accounts",
];

/// The built-in admin theme's templates.
const ADMIN_PAGES: &[(&str, &str)] = &[
    ("base", include_str!("../admin/pages/base.html")),
    ("list", include_str!("../admin/pages/list.html")),
    ("edit", include_str!("../admin/pages/edit.html")),
    ("security", include_str!("../admin/pages/security.html")),
    ("two-factor", include_str!("../admin/pages/two-factor.html")),
    ("codes", include_str!("../admin/pages/codes.html")),
    ("code", include_str!("../admin/pages/code.html")),
    ("accounts", include_str!("../admin/pages/accounts.html")),
];

/// The built-in admin theme's stylesheet, served at `/admin/static/admin.css`.
pub const ADMIN_CSS: &str = include_str!("../admin/static/admin.css");

/// The content security policy of every admin page: nothing inline, nothing
/// from another origin, never framed.
pub const ADMIN_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

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
    /// The content editor's URL.
    pub admin: String,
    /// The stylesheet URL.
    pub css: String,
    /// The site icon's address.
    pub icon: String,
}

luminess::view!(SiteInfo as "site" { name: text, home: text, about: text, account: text, admin: text, css: text, icon: text });

/// A form on a page (`page.form`): the sign-in form, the sign-out button.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Form {
    /// Where it posts.
    pub action: String,
    /// The CSRF token, for the hidden `csrf` field.
    pub csrf: String,
    /// A message to show above it (a refused sign-in), or empty.
    pub error: String,
    /// The email to fill in again after a refusal, or empty.
    pub email: String,
    /// Who is signed in, or empty.
    pub user: String,
    /// Whether the visitor may edit the content (a link to the editor).
    pub editor: bool,
}

luminess::view!(Form as "form" { action: text, csrf: text, error: text, email: text, user: text, editor: bool });

/// The content editor (`page.editor`): every entry, and the entry form with
/// what the editor typed (kept after a refusal).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Editor {
    /// Every entry: posts newest first, then pages.
    pub entries: Arc<Vec<Arc<Entry>>>,
    /// Where the entry form posts.
    pub save: String,
    /// Where the delete button posts.
    pub delete: String,
    /// The new-post form's URL.
    pub new_post: String,
    /// The new-page form's URL.
    pub new_page: String,
    /// The CSRF token, for the hidden `csrf_token` fields.
    pub csrf: String,
    /// Why the last save was refused, or empty.
    pub error: String,
    /// Whether the form edits an existing entry (it can be deleted).
    pub existing: bool,
    /// `post` or `page`.
    pub kind: String,
    /// The slug in the form.
    pub slug: String,
    /// The slug the editor opened (empty for a new entry).
    pub was: String,
    /// The title.
    pub title: String,
    /// The summary.
    pub summary: String,
    /// The date (`YYYY-MM-DD`).
    pub date: String,
    /// The body as the author writes it.
    pub body: String,
    /// The search and sharing fields, as typed.
    pub meta: crate::content::Meta,
    /// Whether the visitor manages the accounts (a link to them).
    pub admin: bool,
}

luminess::view!(Editor as "editor" {
    entries: list(object(Entry)),
    save: text,
    delete: text,
    new_post: text,
    new_page: text,
    csrf: text,
    error: text,
    existing: bool,
    kind: text,
    slug: text,
    was: text,
    title: text,
    summary: text,
    date: text,
    body: text,
    meta: object(crate::content::Meta),
    admin: bool,
});

luminess::view!(crate::content::Meta as "meta" {
    seo_title: text,
    description: text,
    og_title: text,
    og_description: text,
    canonical: text,
    robots: text,
    og_image: text,
    twitter_card: text,
});

/// One account in the administrator's list (`page.security.accounts`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountView {
    /// The account's id (32 hex digits), for the forms.
    pub id: String,
    /// Its email.
    pub identifier: String,
    /// Its roles, comma separated.
    pub roles: String,
    /// `active`, `disabled`, `locked`, `banned`, or `pending`.
    pub standing: String,
    /// Whether two-step sign-in is on.
    pub totp: bool,
    /// Whether it may be disabled or removed from here (not the viewer's own
    /// account, not the boot account).
    pub managed: bool,
}

luminess::view!(AccountView as "account" {
    id: text,
    identifier: text,
    roles: text,
    standing: text,
    totp: bool,
    managed: bool,
});

/// The account and sign-in security pages (`page.security`): the password
/// form, two-step sign-in, recovery codes, the second sign-in step, and the
/// administrator's accounts. Every page that has it renders from the admin
/// theme.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Security {
    /// The signed-in account's email, or empty.
    pub identifier: String,
    /// The CSRF token, for the hidden `csrf_token` fields.
    pub csrf: String,
    /// Why the last form was refused, or empty.
    pub error: String,
    /// What the last form did, or empty.
    pub notice: String,
    /// Where this page's main form posts.
    pub action: String,
    /// The password form's address.
    pub password: String,
    /// The sign-out-everywhere button's address.
    pub everywhere: String,
    /// The forget-remembered-devices button's address.
    pub devices: String,
    /// The two-step set-up page's address.
    pub two_factor: String,
    /// The turn-two-step-off form's address.
    pub two_factor_off: String,
    /// The new-recovery-codes form's address.
    pub new_codes: String,
    /// Where to go after the codes page.
    pub next: String,
    /// Two-step sign-in is on for the account.
    pub totp: bool,
    /// Two-step sign-in may be turned on here.
    pub offered: bool,
    /// The account's roles require two-step sign-in.
    pub required: bool,
    /// The form asks for the password too.
    pub ask_password: bool,
    /// The secret to type into an authenticator app (set-up only).
    pub secret: String,
    /// The `otpauth://` link (set-up only).
    pub uri: String,
    /// Recovery codes, shown once.
    pub codes: Vec<String>,
    /// "Remember this device" is offered, for this many days.
    pub remember_days: i64,
    /// The shortest password the account may set.
    pub min_length: i64,
    /// The account may edit the content.
    pub editor: bool,
    /// The account manages the accounts.
    pub admin: bool,
    /// The accounts (administrator only).
    pub accounts: Arc<Vec<Arc<AccountView>>>,
    /// The disable button's address (administrator only).
    pub disable: String,
    /// The enable button's address (administrator only).
    pub enable: String,
    /// The remove button's address (administrator only).
    pub remove: String,
}

luminess::view!(Security as "security" {
    identifier: text,
    csrf: text,
    error: text,
    notice: text,
    action: text,
    password: text,
    everywhere: text,
    devices: text,
    two_factor: text,
    two_factor_off: text,
    new_codes: text,
    next: text,
    totp: bool,
    offered: bool,
    required: bool,
    ask_password: bool,
    secret: text,
    uri: text,
    codes: list(text),
    remember_days: int,
    min_length: int,
    editor: bool,
    admin: bool,
    accounts: list(object(AccountView)),
    disable: text,
    enable: text,
    remove: text,
});

/// What a page's `<head>` says to search engines and when it is shared
/// (`page.head`): an entry's search and sharing fields, with the fallbacks
/// already applied, so a theme writes each one as it is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Head {
    /// The title for search results and the browser tab: the search title,
    /// else the title.
    pub title: String,
    /// The meta description: the entry's, else its summary; empty: none.
    pub description: String,
    /// The canonical address, absolute when the site has hosts; empty: none.
    pub canonical: String,
    /// The robots directive; empty: none (`index, follow`).
    pub robots: String,
    /// `article` for a post, else `website`.
    pub og_type: String,
    /// The sharing title: the entry's, else `title`.
    pub og_title: String,
    /// The sharing description: the entry's, else `description`.
    pub og_description: String,
    /// The sharing image, absolute when the site has hosts; empty: none.
    pub og_image: String,
    /// The card: the entry's, else `summary_large_image` with an image and
    /// `summary` without.
    pub twitter_card: String,
}

luminess::view!(Head as "head" {
    title: text,
    description: text,
    canonical: text,
    robots: text,
    og_type: text,
    og_title: text,
    og_description: text,
    og_image: text,
    twitter_card: text,
});

/// What a page template reads, as `page`. Content is shared, not copied:
/// `entry` and `posts` point into the manifest.
#[derive(Clone, Debug)]
pub struct Page {
    /// Site-wide values.
    pub site: Arc<SiteInfo>,
    /// The page title.
    pub title: String,
    /// The page's `<head>` fields.
    pub head: Arc<Head>,
    /// The entry the route shows, if any.
    pub entry: Option<Arc<Entry>>,
    /// The post listing, newest first.
    pub posts: Arc<Vec<Arc<Entry>>>,
    /// A short message, for pages without an entry.
    pub message: String,
    /// The page's form, if it has one.
    pub form: Option<Arc<Form>>,
    /// The content editor, on the editor's pages.
    pub editor: Option<Arc<Editor>>,
    /// The account and sign-in security pages.
    pub security: Option<Arc<Security>>,
}

luminess::view!(Page as "page" {
    site: object(SiteInfo),
    title: text,
    head: object(Head),
    entry: object(Entry),
    posts: list(object(Entry)),
    message: text,
    form: object(Form),
    editor: object(Editor),
    security: object(Security),
});

/// The theme: what the watcher reloads.
pub type SiteTheme = Theme<Page>;

/// How many times the engine rendered, since the site was built: one
/// relaxed add per render.
#[derive(Debug, Default)]
pub struct RenderCounts {
    pages: AtomicU64,
    error_pages: AtomicU64,
}

impl RenderCounts {
    /// Pages rendered from a template ([`web_net::Render::render`]).
    #[must_use]
    pub fn pages(&self) -> u64 {
        self.pages.load(Ordering::Relaxed)
    }

    /// Error pages rendered ([`web_net::Render::error_page`]).
    #[must_use]
    pub fn error_pages(&self) -> u64 {
        self.error_pages.load(Ordering::Relaxed)
    }

    /// Both together.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.pages() + self.error_pages()
    }
}

/// A render engine that counts every render and records its time into the
/// stage timing (when it is on). What web-net renders with.
#[derive(Clone)]
pub struct Timed<E> {
    inner: E,
    stages: Arc<gateway_io::StageTimes>,
    counts: Arc<RenderCounts>,
}

impl<E> Timed<E> {
    /// `inner`, timed into `stages`.
    #[must_use]
    pub fn new(inner: E, stages: Arc<gateway_io::StageTimes>) -> Timed<E> {
        Timed {
            inner,
            stages,
            counts: Arc::new(RenderCounts::default()),
        }
    }

    /// The renders so far (every clone shares them).
    #[must_use]
    pub fn counts(&self) -> &Arc<RenderCounts> {
        &self.counts
    }

    /// `inner`, with timing off.
    #[must_use]
    pub fn untimed(inner: E) -> Timed<E> {
        Timed::new(inner, Arc::new(gateway_io::StageTimes::new(false)))
    }
}

impl<E: web_net::Render> web_net::Render for Timed<E> {
    type View<'a> = E::View<'a>;

    fn template(&self, name: &str) -> Option<web_net::TemplateId> {
        self.inner.template(name)
    }

    #[inline]
    fn render(
        &self,
        template: web_net::TemplateId,
        view: &Self::View<'_>,
        out: &mut web_net::Output<'_>,
    ) -> Result<(), web_net::RenderError> {
        self.counts.pages.fetch_add(1, Ordering::Relaxed);
        if !self.stages.enabled() {
            return self.inner.render(template, view, out);
        }
        let t = std::time::Instant::now();
        let done = self.inner.render(template, view, out);
        self.stages.render(t.elapsed());
        done
    }

    fn error_page(
        &self,
        page: &web_net::ErrorPage<'_>,
        out: &mut web_net::Output<'_>,
    ) -> Result<bool, web_net::RenderError> {
        self.counts.error_pages.fetch_add(1, Ordering::Relaxed);
        let expired;
        let page = if crate::events::form_expired(page.reference) {
            let mut p = *page;
            p.title = FORM_EXPIRED_TITLE;
            p.message = FORM_EXPIRED;
            expired = p;
            &expired
        } else {
            page
        };
        if !self.stages.enabled() {
            return self.inner.error_page(page, out);
        }
        let t = std::time::Instant::now();
        let done = self.inner.error_page(page, out);
        self.stages.render(t.elapsed());
        done
    }
}

/// The error page's title when a form's token was refused.
pub const FORM_EXPIRED_TITLE: &str = "Form expired";

/// The error page's message when a form's token was refused.
pub const FORM_EXPIRED: &str = "This form expired. Reload the page and try again. If you typed a lot, go back first and copy it.";

/// The admin pages' engine.
pub type AdminTheme = Engine<Page>;

/// Where the admin theme comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminSource {
    /// The one built into the binary: it works whatever the site theme is.
    Builtin,
    /// A folder (`pages/`, `static/`), allowed only by `admin.custom_theme`.
    Folder(PathBuf),
}

/// Loads the admin theme. The built-in one compiles from the binary.
pub fn load_admin(source: &AdminSource) -> Result<AdminTheme, ThemeError> {
    match source {
        AdminSource::Builtin => compile_admin(
            "built-in admin theme",
            ADMIN_PAGES
                .iter()
                .map(|(n, s)| ((*n).to_owned(), (*s).to_owned()))
                .collect(),
        ),
        AdminSource::Folder(dir) => {
            let mut budget = MAX_THEME_BYTES;
            let mut files = 0;
            let pages = sources(&dir.join("pages"), &mut budget, &mut files)?;
            compile_admin(&dir.display().to_string(), pages)
        }
    }
}

/// Compiles an admin theme on its own thread with a large stack, as a site
/// theme is.
fn compile_admin(shown: &str, pages: Vec<(String, String)>) -> Result<AdminTheme, ThemeError> {
    let name = shown.to_owned();
    let worker = std::thread::Builder::new()
        .name("theme-compile".into())
        .stack_size(COMPILE_STACK)
        .spawn(move || {
            let failed = ThemeError(format!("admin theme {name}: the compiler failed"));
            std::panic::catch_unwind(move || {
                let engine = pages
                    .into_iter()
                    .fold(Engine::<Page>::builder(), |b, (n, s)| b.template(n, s))
                    .build()
                    .map_err(|e| ThemeError(format!("admin theme {name}: {e}")))?;
                for required in ADMIN_REQUIRED {
                    if !engine.contains(required) {
                        return Err(ThemeError(format!(
                            "admin theme {name}: pages/{required}.html is missing"
                        )));
                    }
                }
                Ok(engine)
            })
            .unwrap_or(Err(failed))
        })
        .map_err(|e| ThemeError(format!("admin theme {shown}: {e}")))?;
    worker.join().unwrap_or_else(|_| {
        Err(ThemeError(format!(
            "admin theme {shown}: the compiler failed"
        )))
    })
}

/// A template id from the admin theme: the high bit, never set by a site
/// theme's ids.
const ADMIN_TEMPLATE: u32 = 1 << 31;

/// The site theme and the admin theme as one engine: a template named
/// `admin/<name>` is the admin theme's `<name>`, and every other name is
/// the site theme's. Error pages are the site theme's.
#[derive(Clone)]
pub struct SiteRender {
    site: SiteTheme,
    admin: AdminTheme,
}

impl SiteRender {
    /// The site theme with its admin theme.
    #[must_use]
    pub fn new(site: SiteTheme, admin: AdminTheme) -> SiteRender {
        SiteRender { site, admin }
    }

    /// The site theme with the built-in admin theme.
    pub fn builtin(site: SiteTheme) -> Result<SiteRender, ThemeError> {
        Ok(SiteRender::new(site, load_admin(&AdminSource::Builtin)?))
    }
}

impl web_net::Render for SiteRender {
    type View<'a> = Page;

    fn template(&self, name: &str) -> Option<web_net::TemplateId> {
        match name.strip_prefix("admin/") {
            Some(admin) => web_net::Render::template(&self.admin, admin)
                .filter(|t| t.0 & ADMIN_TEMPLATE == 0)
                .map(|t| web_net::TemplateId(t.0 | ADMIN_TEMPLATE)),
            None => {
                web_net::Render::template(&self.site, name).filter(|t| t.0 & ADMIN_TEMPLATE == 0)
            }
        }
    }

    #[inline]
    fn render(
        &self,
        template: web_net::TemplateId,
        view: &Page,
        out: &mut web_net::Output<'_>,
    ) -> Result<(), web_net::RenderError> {
        if template.0 & ADMIN_TEMPLATE == 0 {
            web_net::Render::render(&self.site, template, view, out)
        } else {
            let id = web_net::TemplateId(template.0 & !ADMIN_TEMPLATE);
            web_net::Render::render(&self.admin, id, view, out)
        }
    }

    fn error_page(
        &self,
        page: &web_net::ErrorPage<'_>,
        out: &mut web_net::Output<'_>,
    ) -> Result<bool, web_net::RenderError> {
        web_net::Render::error_page(&self.site, page, out)
    }
}

/// The engine web-net renders the site with.
pub type SiteEngine = Timed<SiteRender>;

/// Why a theme was refused.
#[derive(Debug)]
pub struct ThemeError(pub String);

impl std::fmt::Display for ThemeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ThemeError {}

/// The most a theme's templates may hold, all files together.
pub const MAX_THEME_BYTES: u64 = 16 << 20;

/// The most template files a theme may have.
pub const MAX_THEME_FILES: usize = 2_000;

/// The stack a theme compiles on: far more than a compiler needs, so a deep
/// template is refused by the compiler's own limits, never by the stack.
const COMPILE_STACK: usize = 64 << 20;

/// The compiled engines of a theme.
type Compiled = (Engine<Page>, Engine<ErrorView>);

/// Every `.html` file under `root`, named by its path below `root` with `/`
/// between folders and without the extension (as Luminess names them), in
/// a fixed order. A symbolic link anywhere is refused, so a template can
/// never read a file outside the theme; so is a theme over
/// [`MAX_THEME_BYTES`] or [`MAX_THEME_FILES`].
fn sources(
    root: &Path,
    budget: &mut u64,
    files: &mut usize,
) -> Result<Vec<(String, String)>, ThemeError> {
    let fail =
        |p: &Path, e: &dyn std::fmt::Display| ThemeError(format!("theme {}: {e}", p.display()));
    let mut pending = vec![root.to_path_buf()];
    let mut found = Vec::new();
    while let Some(d) = pending.pop() {
        let entries = std::fs::read_dir(&d).map_err(|e| fail(&d, &e))?;
        for e in entries {
            let e = e.map_err(|e| fail(&d, &e))?;
            let path = e.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|e| fail(&path, &e))?;
            if meta.file_type().is_symlink() {
                return Err(fail(&path, &"symbolic links are refused in a theme"));
            }
            if meta.is_dir() {
                pending.push(path);
                continue;
            }
            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            let parts: Option<Vec<&str>> =
                rel.components().map(|c| c.as_os_str().to_str()).collect();
            let Some(parts) = parts else { continue };
            let Some(name) = parts.join("/").strip_suffix(".html").map(str::to_owned) else {
                continue;
            };
            *files += 1;
            *budget = budget.saturating_sub(meta.len());
            if *files > MAX_THEME_FILES || *budget == 0 {
                return Err(fail(
                    root,
                    &format!(
                        "over the theme limits ({MAX_THEME_FILES} templates, {MAX_THEME_BYTES} bytes)"
                    ),
                ));
            }
            found.push((name, path));
        }
    }
    found.sort();
    found
        .into_iter()
        .map(|(name, path)| {
            std::fs::read_to_string(&path)
                .map(|src| (name, src))
                .map_err(|e| fail(&path, &e))
        })
        .collect()
}

/// Compiles both engines of the theme in `dir`, checking the required
/// templates, without touching anything running.
///
/// The compile runs on its own thread with a large stack and inside
/// `catch_unwind`: whatever a template does to the compiler, the answer is
/// an `Err` (the theme is refused, the running one stays), never the end of
/// the process.
fn compile(dir: &Path) -> Result<Compiled, ThemeError> {
    let mut budget = MAX_THEME_BYTES;
    let mut files = 0;
    let pages = sources(&dir.join("pages"), &mut budget, &mut files)?;
    let errors = sources(&dir.join("errors"), &mut budget, &mut files)?;
    let shown = dir.display().to_string();
    let worker = std::thread::Builder::new()
        .name("theme-compile".into())
        .stack_size(COMPILE_STACK)
        .spawn(move || {
            let failed = ThemeError(format!("theme {shown}: the compiler failed"));
            std::panic::catch_unwind(move || compile_sources(&shown, pages, errors))
                .unwrap_or(Err(failed))
        })
        .map_err(|e| ThemeError(format!("theme {}: {e}", dir.display())))?;
    worker.join().unwrap_or_else(|_| {
        Err(ThemeError(format!(
            "theme {}: the compiler failed",
            dir.display()
        )))
    })
}

fn compile_sources(
    shown: &str,
    pages: Vec<(String, String)>,
    errors: Vec<(String, String)>,
) -> Result<Compiled, ThemeError> {
    let pages = pages
        .into_iter()
        .fold(Engine::<Page>::builder(), |b, (n, s)| b.template(n, s))
        .build()
        .map_err(|e| ThemeError(format!("theme {shown} pages: {e}")))?;
    let errors = errors
        .into_iter()
        .fold(Engine::<ErrorView>::builder(), |b, (n, s)| b.template(n, s))
        .build()
        .map_err(|e| ThemeError(format!("theme {shown} errors: {e}")))?;
    let dir = shown;
    for name in REQUIRED {
        if !pages.contains(name) {
            return Err(ThemeError(format!(
                "theme {dir}: pages/{name}.html is missing"
            )));
        }
    }
    Ok((pages, errors))
}

/// Loads the theme in `dir`.
pub fn load(dir: &Path) -> Result<SiteTheme, ThemeError> {
    let (pages, errors) = compile(dir)?;
    Ok(Theme::new(pages).with_error_pages(errors))
}

/// Compiles the theme in `dir` again and swaps it into `theme` (every clone,
/// so the running site). On any error nothing changes.
pub fn reload(theme: &SiteTheme, dir: &Path) -> Result<(), ThemeError> {
    let (pages, errors) = compile(dir)?;
    theme.pages().replace(pages);
    if let Some(e) = theme.error_pages() {
        e.replace(errors);
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
            // Links are not followed (and a theme with one is refused).
            match std::fs::symlink_metadata(&path) {
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
    /// The folder's fingerprint when the theme was loaded: the watcher's
    /// starting point, taken here and not on its thread, so an edit made
    /// before the thread first runs is still a change.
    seen: u64,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    link: Option<Link>,
    /// Called after every reload that took (to drop cached pages).
    changed: Arc<dyn Fn() + Send + Sync>,
}

impl ThemeWatcher {
    /// A watcher for `theme`, loaded from `dir`.
    #[must_use]
    pub fn new(theme: SiteTheme, dir: PathBuf, poll: Duration) -> ThemeWatcher {
        let seen = fingerprint(&dir);
        ThemeWatcher {
            theme,
            dir,
            poll,
            seen,
            stop: Arc::new(AtomicBool::new(false)),
            thread: None,
            link: None,
            changed: Arc::new(|| {}),
        }
    }

    /// The same watcher, calling `f` after every reload that took (to drop
    /// cached pages, which were rendered with the old theme).
    #[must_use]
    pub fn on_change(mut self, f: impl Fn() + Send + Sync + 'static) -> ThemeWatcher {
        self.changed = Arc::new(f);
        self
    }

    /// Compiles the theme folder again and swaps it in, as the watcher does
    /// when the folder changes. On any error nothing changes.
    pub fn reload_now(&self) -> Result<(), ThemeError> {
        reload(&self.theme, &self.dir)?;
        (self.changed)();
        Ok(())
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

fn reload_and_log(
    theme: &SiteTheme,
    dir: &Path,
    changed: &(dyn Fn() + Send + Sync),
    link: &Link,
    why: &str,
) {
    match reload(theme, dir) {
        Ok(()) => {
            changed();
            log::info!(link.foundation().log(), "theme reloaded", cause = why);
        }
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
        let (theme, dir, poll, stop, link, mut seen, changed) = (
            self.theme.clone(),
            self.dir.clone(),
            self.poll,
            self.stop.clone(),
            link.clone(),
            self.seen,
            self.changed.clone(),
        );
        let thread = std::thread::Builder::new()
            .name("theme-watch".into())
            .spawn(move || {
                loop {
                    std::thread::park_timeout(poll);
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    // A panic here would end live reload in silence: log it
                    // and keep watching.
                    let turn = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let now = fingerprint(&dir);
                        if now != seen {
                            seen = now;
                            reload_and_log(&theme, &dir, &*changed, &link, "theme folder changed");
                        }
                    }));
                    if turn.is_err() {
                        log::error!(
                            link.foundation().log(),
                            "theme watcher recovered from a panic"
                        );
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
        let changed = self.changed.clone();
        Ok(Commit::new(move || {
            theme.pages().replace(pages);
            if let Some(e) = theme.error_pages() {
                e.replace(errors);
            }
            changed();
        }))
    }
}
