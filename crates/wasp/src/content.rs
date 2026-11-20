//! The content manifest: entries prepared when they are saved, served from
//! memory, read by the templates through the `View` trait.
//!
//! The heavy work happens when content is saved ([`Manifest::save`]): the
//! body is turned into safe HTML once (every character escaped, paragraphs
//! split), the URL and the listing are computed. A request only borrows what
//! is already there: an entry is an `Arc<Entry>`, the post listing one shared
//! `Arc<Vec<Arc<Entry>>>`, so rendering a page copies no content.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use wasp_core::suite::config::Config;
use wasp_core::{Provider, ProviderError};

/// What kind of entry: it picks the default template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A standalone page (`/about`).
    Page,
    /// A dated post, listed on the home page (`/posts/:slug`).
    Post,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Page => "page",
            Kind::Post => "post",
        }
    }
}

/// One entry as the templates see it (`page.entry`, each of `page.posts`);
/// its view schema is declared with the theme (`theme.rs`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// `page` or `post`.
    pub kind: String,
    /// The slug.
    pub slug: String,
    /// The title (plain text; the template escapes it).
    pub title: String,
    /// The site-relative URL.
    pub url: String,
    /// A one-line summary (plain text).
    pub summary: String,
    /// The body as safe HTML, prepared when the entry was saved.
    pub body: String,
    /// The date (`2026-11-09`), for posts.
    pub date: String,
    /// The body as the author wrote it (plain text), for the editor.
    pub text: String,
    /// The search and sharing fields, as the author set them (empty: the
    /// page head falls back to the title and summary).
    pub meta: Meta,
    /// The declared custom fields of the entry's kind, in declaration order,
    /// each with its checked value (empty when the entry has none).
    pub fields: Arc<Vec<FieldValue>>,
}

/// One declared field's value on an entry (`page.entry.fields`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldValue {
    /// The field's name.
    pub name: String,
    /// Its label.
    pub label: String,
    /// Its type (`text`, `textarea`, `url`, `number`, `bool`, `date`,
    /// `select`, `media`).
    pub kind: String,
    /// The value, checked against the type (`true` or `false` for a
    /// `bool`); empty when the entry has none.
    pub value: String,
}

/// The kind of value a declared field holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    /// One line of text.
    Text,
    /// Several lines of text.
    Textarea,
    /// A site path or an `http(s)://` address.
    Url,
    /// A decimal number.
    Number,
    /// Yes or no.
    Bool,
    /// A `YYYY-MM-DD` date.
    Date,
    /// One of the declared options.
    Select,
    /// The address of a file (a site path or an `http(s)://` address until
    /// there is a media library).
    Media,
}

impl FieldType {
    /// The type's name, as declared.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FieldType::Text => "text",
            FieldType::Textarea => "textarea",
            FieldType::Url => "url",
            FieldType::Number => "number",
            FieldType::Bool => "bool",
            FieldType::Date => "date",
            FieldType::Select => "select",
            FieldType::Media => "media",
        }
    }

    fn parse(text: &str) -> Option<FieldType> {
        Some(match text {
            "text" => FieldType::Text,
            "textarea" => FieldType::Textarea,
            "url" => FieldType::Url,
            "number" => FieldType::Number,
            "bool" => FieldType::Bool,
            "date" => FieldType::Date,
            "select" => FieldType::Select,
            "media" => FieldType::Media,
            _ => return None,
        })
    }
}

/// One declared custom field (`[content.fields.<kind>.<name>]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldDecl {
    /// The name: lower case letters, digits and `_`, starting with a letter.
    pub name: String,
    /// The label the editor shows.
    pub label: String,
    /// The kind of value.
    pub kind: FieldType,
    /// A save without a value is refused (for a `bool`: it must be checked).
    pub required: bool,
    /// A line of help under the field in the editor.
    pub help: String,
    /// The choices of a `select`.
    pub options: Vec<String>,
    /// Where the editor shows it (then by name).
    pub order: i64,
}

/// Where a custom field's value is kept in a store record: its name with
/// this prefix, so it never meets a built-in field.
pub const FIELD_PREFIX: &str = "f_";

/// The most fields declared for one kind.
pub const MAX_FIELDS: usize = 32;

/// The longest field name.
pub const MAX_FIELD_NAME: usize = 32;

/// The longest `text` value, in characters.
pub const FIELD_TEXT_MAX: usize = 500;

/// The longest `textarea` value, in characters.
pub const FIELD_TEXTAREA_MAX: usize = 20_000;

/// The most options a `select` declares.
pub const MAX_OPTIONS: usize = 100;

/// The custom fields declared for posts and pages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields {
    post: Vec<FieldDecl>,
    page: Vec<FieldDecl>,
}

impl Fields {
    /// The fields `kind` declares, in the editor's order.
    #[must_use]
    pub fn of(&self, kind: Kind) -> &[FieldDecl] {
        match kind {
            Kind::Post => &self.post,
            Kind::Page => &self.page,
        }
    }

    /// The fields `[content.fields.post.*]` and `[content.fields.page.*]`
    /// declare. A bad declaration is refused with its key.
    pub fn from_config(config: &Config) -> Result<Fields, String> {
        let e = |e: wasp_core::suite::Error| e.to_string();
        if let Some(k) = config
            .keys("content.fields")
            .into_iter()
            .find(|k| !matches!(*k, "post" | "page"))
        {
            return Err(format!(
                "content.fields.{k}: fields are declared for `post` or `page`"
            ));
        }
        let mut out = Fields::default();
        for (kind, list) in [("post", &mut out.post), ("page", &mut out.page)] {
            let names = config.keys(&format!("content.fields.{kind}"));
            if names.len() > MAX_FIELDS {
                return Err(format!(
                    "content.fields.{kind}: at most {MAX_FIELDS} fields"
                ));
            }
            for name in names {
                let at = format!("content.fields.{kind}.{name}");
                let ok = name.len() <= MAX_FIELD_NAME
                    && name.starts_with(|c: char| c.is_ascii_lowercase())
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
                if !ok {
                    return Err(format!(
                        "{at}: a field name is lower case letters, digits and `_`, starting with a letter, at most {MAX_FIELD_NAME} characters"
                    ));
                }
                if let Some(k) = config.keys(&at).into_iter().find(|k| {
                    !matches!(
                        *k,
                        "help" | "label" | "options" | "order" | "required" | "type"
                    )
                }) {
                    return Err(format!(
                        "unknown key `{at}.{k}`: the keys of a field are help, label, options, order, required, type"
                    ));
                }
                // Every declaration says what it holds (the configuration
                // reader drops an empty table, so a field always has a key).
                let Some(type_name) = config.get::<String>(&format!("{at}.type")).map_err(e)?
                else {
                    return Err(format!("{at}.type is missing"));
                };
                let Some(field_type) = FieldType::parse(&type_name) else {
                    return Err(format!(
                        "{at}.type is `{type_name}`: text, textarea, url, number, bool, date, select, or media"
                    ));
                };
                let options: Vec<String> = config
                    .get_or(&format!("{at}.options"), Vec::new())
                    .map_err(e)?;
                if field_type == FieldType::Select {
                    if options.is_empty() || options.len() > MAX_OPTIONS {
                        return Err(format!(
                            "{at}.options: a select needs 1 to {MAX_OPTIONS} options"
                        ));
                    }
                    if let Some(o) = options.iter().find(|o| {
                        o.trim().is_empty()
                            || o.chars().count() > 100
                            || o.chars().any(char::is_control)
                    }) {
                        return Err(format!(
                            "{at}.options: `{o}` must be one line of 1 to 100 characters"
                        ));
                    }
                } else if !options.is_empty() {
                    return Err(format!("{at}.options: only a select has options"));
                }
                let label: String = config
                    .get_or(&format!("{at}.label"), name.to_owned())
                    .map_err(e)?;
                let help: String = config
                    .get_or(&format!("{at}.help"), String::new())
                    .map_err(e)?;
                list.push(FieldDecl {
                    name: name.to_owned(),
                    label,
                    kind: field_type,
                    required: config.get_or(&format!("{at}.required"), false).map_err(e)?,
                    help,
                    options,
                    order: config.get_or(&format!("{at}.order"), 0_i64).map_err(e)?,
                });
            }
            list.sort_by(|a, b| a.order.cmp(&b.order).then_with(|| a.name.cmp(&b.name)));
        }
        Ok(out)
    }
}

/// `value` for `decl`, checked and in the form it is kept: `Err` with the
/// reason in words for the author.
fn field_value(decl: &FieldDecl, value: &str) -> Result<String, String> {
    let one_line = || value.split_whitespace().collect::<Vec<_>>().join(" ");
    let v = match decl.kind {
        FieldType::Text => {
            let v = one_line();
            if v.chars().count() > FIELD_TEXT_MAX {
                return Err(format!("is longer than {FIELD_TEXT_MAX} characters"));
            }
            v
        }
        FieldType::Textarea => {
            let v = unix_newlines(value).trim().to_owned();
            if v.chars().count() > FIELD_TEXTAREA_MAX {
                return Err(format!("is longer than {FIELD_TEXTAREA_MAX} characters"));
            }
            if v.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
                return Err("has a control character".to_owned());
            }
            v
        }
        FieldType::Url | FieldType::Media => {
            let v = value.trim().to_owned();
            if !v.is_empty() && !address_ok(&v) {
                return Err(
                    "must be a site path starting with `/`, or an `https://` or `http://` address, with no spaces"
                        .to_owned(),
                );
            }
            v
        }
        FieldType::Number => {
            let v = value.trim().to_owned();
            let digits = v.strip_prefix('-').unwrap_or(&v);
            let (whole, fraction) = digits.split_once('.').unwrap_or((digits, "0"));
            let ok = v.is_empty()
                || (v.len() <= 32
                    && !whole.is_empty()
                    && !fraction.is_empty()
                    && whole.bytes().all(|b| b.is_ascii_digit())
                    && fraction.bytes().all(|b| b.is_ascii_digit()));
            if !ok {
                return Err("must be a number, like `12` or `-3.5`".to_owned());
            }
            v
        }
        FieldType::Bool => match value.trim() {
            "" | "false" | "off" | "0" => "false".to_owned(),
            "true" | "on" | "1" => "true".to_owned(),
            _ => return Err("must be true or false".to_owned()),
        },
        FieldType::Date => {
            let v = value.trim().to_owned();
            if !v.is_empty() && !date_ok(&v) {
                return Err("must be a date, YYYY-MM-DD".to_owned());
            }
            v
        }
        FieldType::Select => {
            let v = value.trim().to_owned();
            if !v.is_empty() && !decl.options.contains(&v) {
                return Err(format!("must be one of: {}", decl.options.join(", ")));
            }
            v
        }
    };
    if decl.kind != FieldType::Textarea && v.chars().any(char::is_control) {
        return Err("has a control character".to_owned());
    }
    Ok(v)
}

/// `YYYY-MM-DD` with a month of 1 to 12 and a day that month can have.
fn date_ok(v: &str) -> bool {
    let b = v.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |r: std::ops::Range<usize>| v.get(r).and_then(|t| t.parse::<u32>().ok());
    let (Some(y), Some(m), Some(d)) = (num(0..4), num(5..7), num(8..10)) else {
        return false;
    };
    if !v
        .bytes()
        .enumerate()
        .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
    {
        return false;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&d)
}

/// An entry's search and sharing fields. Each is optional; the page head
/// falls back to the title and summary (see `crate::site`).
///
/// The first four are text a reader sees and are translated with the title
/// and summary when translations arrive: each translation will carry its
/// own. The other four are the entry's, whatever the language.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Meta {
    /// The title for search results and the browser tab (default: the
    /// title).
    pub seo_title: String,
    /// The meta description (default: the summary).
    pub description: String,
    /// The title when shared (default: the search title).
    pub og_title: String,
    /// The description when shared (default: the meta description).
    pub og_description: String,
    /// The canonical address: a site path (`/about`) or an absolute
    /// `https://` URL (default: the entry's own address).
    pub canonical: String,
    /// The robots directive: `index, follow`, `noindex`, `nofollow`,
    /// `noindex, nofollow`, `noindex, follow`, or `index, nofollow`
    /// (default: none, which search engines read as `index, follow`).
    pub robots: String,
    /// The image when shared: a site path or an absolute `https://` URL.
    pub og_image: String,
    /// The card when shared on X: `summary` or `summary_large_image`
    /// (default: the large one when there is an image).
    pub twitter_card: String,
}

/// The robots directives an entry may set.
pub const ROBOTS: &[&str] = &[
    "index, follow",
    "noindex",
    "nofollow",
    "noindex, nofollow",
    "noindex, follow",
    "index, nofollow",
];

/// The card kinds an entry may set.
pub const TWITTER_CARDS: &[&str] = &["summary", "summary_large_image"];

/// The longest search or sharing title, in characters.
pub const META_TITLE_MAX: usize = 200;

/// The longest description, in characters.
pub const META_DESCRIPTION_MAX: usize = 500;

/// The longest address, in bytes.
pub const META_URL_MAX: usize = 2000;

impl Meta {
    /// The fields, by the names the stores and the editor's form use.
    pub const FIELDS: [&'static str; 8] = [
        "seo_title",
        "description",
        "og_title",
        "og_description",
        "canonical",
        "robots",
        "og_image",
        "twitter_card",
    ];

    /// The field `name`, or `None` for a name that is not one.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        Some(match name {
            "seo_title" => &self.seo_title,
            "description" => &self.description,
            "og_title" => &self.og_title,
            "og_description" => &self.og_description,
            "canonical" => &self.canonical,
            "robots" => &self.robots,
            "og_image" => &self.og_image,
            "twitter_card" => &self.twitter_card,
            _ => return None,
        })
    }

    /// The field `name` to write, or `None` for a name that is not one.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut String> {
        Some(match name {
            "seo_title" => &mut self.seo_title,
            "description" => &mut self.description,
            "og_title" => &mut self.og_title,
            "og_description" => &mut self.og_description,
            "canonical" => &mut self.canonical,
            "robots" => &mut self.robots,
            "og_image" => &mut self.og_image,
            "twitter_card" => &mut self.twitter_card,
            _ => return None,
        })
    }

    /// The same fields with runs of whitespace (line breaks too) made one
    /// space and the ends trimmed; the robots directive and the card kind
    /// in lower case with one space after each comma.
    #[must_use]
    pub fn cleaned(&self) -> Meta {
        let one_line = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
        let robots = self
            .robots
            .split(',')
            .map(|p| p.trim().to_lowercase())
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        Meta {
            seo_title: one_line(&self.seo_title),
            description: one_line(&self.description),
            og_title: one_line(&self.og_title),
            og_description: one_line(&self.og_description),
            canonical: self.canonical.trim().to_owned(),
            robots,
            og_image: self.og_image.trim().to_owned(),
            twitter_card: self.twitter_card.trim().to_lowercase(),
        }
    }

    /// Why these fields (cleaned) are refused, in words for the author.
    pub fn check(&self) -> Result<(), Invalid> {
        let m = self.cleaned();
        for (name, value, max) in [
            ("search title", &m.seo_title, META_TITLE_MAX),
            ("meta description", &m.description, META_DESCRIPTION_MAX),
            ("sharing title", &m.og_title, META_TITLE_MAX),
            (
                "sharing description",
                &m.og_description,
                META_DESCRIPTION_MAX,
            ),
        ] {
            if value.chars().count() > max {
                return Err(Invalid(format!(
                    "the {name} is longer than {max} characters"
                )));
            }
            if value.chars().any(char::is_control) {
                return Err(Invalid(format!("the {name} has a control character")));
            }
        }
        for (name, value) in [
            ("canonical address", &m.canonical),
            ("sharing image", &m.og_image),
        ] {
            if !value.is_empty() && !address_ok(value) {
                return Err(Invalid(format!(
                    "the {name} must be a site path starting with `/`, or an `https://` or `http://` address, with no spaces"
                )));
            }
        }
        if !m.robots.is_empty() && !ROBOTS.contains(&m.robots.as_str()) {
            return Err(Invalid(format!(
                "robots must be one of: {}",
                ROBOTS.join("; ")
            )));
        }
        if !m.twitter_card.is_empty() && !TWITTER_CARDS.contains(&m.twitter_card.as_str()) {
            return Err(Invalid(
                "the card must be `summary` or `summary_large_image`".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A site path (`/about`, never `//host`) or an `http(s)://` address, with
/// nothing that could leave an attribute.
fn address_ok(value: &str) -> bool {
    if value.len() > META_URL_MAX
        || value.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '<' | '>' | '`')
        })
    {
        return false;
    }
    if let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    {
        return !rest.is_empty() && !rest.starts_with('/');
    }
    value.starts_with('/') && !value.starts_with("//")
}

/// What an editor saves.
#[derive(Clone, Debug)]
pub struct Draft<'a> {
    /// Page or post.
    pub kind: Kind,
    /// The slug: lowercase letters, digits, and `-` only.
    pub slug: &'a str,
    /// The title.
    pub title: &'a str,
    /// A one-line summary.
    pub summary: &'a str,
    /// The body, plain text; blank lines separate paragraphs.
    pub body: &'a str,
    /// The date, for posts.
    pub date: &'a str,
    /// The search and sharing fields.
    pub meta: Meta,
    /// The custom fields' values by name, as typed.
    pub fields: Vec<(String, String)>,
}

/// Why a draft was refused (the editor sees it; nothing is saved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid(pub String);

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Invalid {}

/// Why a save failed: the draft was refused, or the store could not take it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SaveError {
    /// The draft breaks a rule; the editor fixes it.
    Invalid(Invalid),
    /// The store failed; its kind says whether to retry.
    Store(StoreError),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::Invalid(e) => e.fmt(f),
            SaveError::Store(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SaveError {}

impl From<Invalid> for SaveError {
    fn from(e: Invalid) -> SaveError {
        SaveError::Invalid(e)
    }
}

/// The content, in memory until a content store exists (build-path step 8).
#[derive(Clone, Debug, Default)]
pub struct Manifest {
    base: String,
    fields: Arc<Fields>,
    entries: BTreeMap<String, Arc<Entry>>,
    posts: Arc<Vec<Arc<Entry>>>,
    store: Option<Arc<dyn ContentStore>>,
}

impl std::fmt::Debug for dyn ContentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContentStore({})", self.name())
    }
}

/// An entry as stored: what was prepared when it was saved. The URL is not
/// stored; it depends on where the site is installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    /// `page` or `post`.
    pub kind: String,
    /// The slug (the store's key).
    pub slug: String,
    /// The title.
    pub title: String,
    /// The summary.
    pub summary: String,
    /// The body as the author wrote it (plain text); it is escaped and split
    /// into paragraphs again at every load.
    pub body: String,
    /// The date, for posts.
    pub date: String,
    /// The search and sharing fields (missing in an older record: empty).
    pub meta: Meta,
    /// The custom fields' values by name (without the store's prefix); a
    /// field missing here is empty.
    pub fields: Vec<(String, String)>,
}

/// What kind of failure a store reports, whatever the backend: a file, an
/// embedded database, or one across the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StoreErrorKind {
    /// The store cannot answer now (down, unreachable, locked by another
    /// process, out of a bounded resource). Retry later.
    Unavailable,
    /// The store did not answer in time. The call may or may not have taken
    /// effect; retry later.
    Timeout,
    /// The write lost to another writer, or a unique value is taken. Read
    /// again and retry.
    Conflict,
    /// The input was refused. Retrying the same input fails the same way.
    Invalid,
    /// Anything else: damaged data, a bug. Needs a person.
    Other,
}

/// Why the store failed: its kind, and a message for the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreError {
    kind: StoreErrorKind,
    message: String,
}

impl StoreError {
    /// A failure of `kind`.
    pub fn new(kind: StoreErrorKind, message: impl Into<String>) -> StoreError {
        StoreError {
            kind,
            message: message.into(),
        }
    }

    /// The store cannot answer now.
    pub fn unavailable(message: impl Into<String>) -> StoreError {
        StoreError::new(StoreErrorKind::Unavailable, message)
    }

    /// The input was refused.
    pub fn invalid(message: impl Into<String>) -> StoreError {
        StoreError::new(StoreErrorKind::Invalid, message)
    }

    /// Any other failure.
    pub fn other(message: impl Into<String>) -> StoreError {
        StoreError::new(StoreErrorKind::Other, message)
    }

    /// What kind of failure.
    #[must_use]
    pub fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    /// The message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether the same call may succeed later (unavailable, timeout,
    /// conflict).
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            StoreErrorKind::Unavailable | StoreErrorKind::Timeout | StoreErrorKind::Conflict
        )
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

/// Where the content lives between restarts: the provider seam for content.
/// Writes happen when content is saved, never per request; the site reads
/// everything at boot.
///
/// The seam fits any backend, local or remote:
///
/// - every call can fail, with a [`StoreErrorKind`] that says whether to
///   retry;
/// - values cross by copy: nothing returned borrows from the store, and
///   nothing is held between calls;
/// - an entry is found by its slug alone, an opaque key the store never
///   interprets;
/// - no handle to a shared database appears in the signatures, so one
///   process, several, or a cluster can sit behind it;
/// - health is the store's own ([`Provider::healthy`]), reported per
///   backend.
pub trait ContentStore: Provider {
    /// Every stored entry, in no particular order.
    fn load(&self) -> Result<Vec<Stored>, StoreError>;
    /// Stores an entry, replacing the one with the same slug.
    fn put(&self, entry: &Stored) -> Result<(), StoreError>;
    /// Removes the entry with this slug; `false` when there was none.
    fn remove(&self, slug: &str) -> Result<bool, StoreError>;
}

/// Content in memory: gone at a restart. For tests and a first run.
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: Mutex<BTreeMap<String, Stored>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }
}

impl Provider for MemoryStore {
    fn name(&self) -> &str {
        "content-memory"
    }
    fn flush(&self) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl ContentStore for MemoryStore {
    fn load(&self) -> Result<Vec<Stored>, StoreError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::other("store lock poisoned"))?;
        Ok(entries.values().cloned().collect())
    }
    fn put(&self, entry: &Stored) -> Result<(), StoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::other("store lock poisoned"))?;
        entries.insert(entry.slug.clone(), entry.clone());
        Ok(())
    }
    fn remove(&self, slug: &str) -> Result<bool, StoreError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| StoreError::other("store lock poisoned"))?;
        Ok(entries.remove(slug).is_some())
    }
}

pub use crate::content::bison_store::{BisonStore, Recovery};

/// The bison-db store.
mod bison_store {
    use std::path::{Path, PathBuf};
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    use bison_db::{Db, DbOptions, Document, RecoveryMode, SyncPolicy, Value};
    use wasp_core::{Provider, ProviderError};

    use super::{ContentStore, FIELD_PREFIX, Meta, StoreError, StoreErrorKind, Stored};

    /// Content in a bison-db file: one document per entry, keyed by slug. Every
    /// write is synced to disk (content is written rarely and must survive a
    /// crash); the slug index is declared at open (bison-db keeps indexes in
    /// memory).
    ///
    /// One process holds the file: a second open (another instance on the
    /// same data folder) is refused at boot. A file damaged anywhere but a
    /// torn last record is refused too, and left as it was; the operator
    /// backs it up and starts once with `content.recovery = "salvage"`,
    /// which keeps every record that still verifies (bison-db saves the
    /// damaged file beside it as `<path>.damaged` first).
    pub struct BisonStore {
        db: RwLock<Db>,
        path: PathBuf,
        discarded: u64,
        /// A write failed: bison-db refuses writes until the store is
        /// reopened, so the provider reports itself unhealthy.
        failed: AtomicBool,
    }

    /// How a damaged store file is opened.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum Recovery {
        /// Refuse a file damaged before its end (the default).
        #[default]
        Strict,
        /// Keep every record that still verifies; the damaged file is copied
        /// beside the store first.
        Salvage,
    }

    const FIELDS: [&str; 6] = ["kind", "slug", "title", "summary", "body", "date"];

    fn bison(e: bison_db::Error) -> StoreError {
        let kind = match e {
            bison_db::Error::Locked | bison_db::Error::Io(_) => StoreErrorKind::Unavailable,
            bison_db::Error::ValueTooLarge => StoreErrorKind::Invalid,
            _ => StoreErrorKind::Other,
        };
        StoreError::new(kind, format!("content store: {e}"))
    }

    impl BisonStore {
        /// Opens (or creates) the store at `path`, creating its folder.
        pub fn open(path: impl AsRef<Path>) -> Result<BisonStore, StoreError> {
            BisonStore::open_with(path, Recovery::Strict)
        }

        /// [`open`](Self::open), with the recovery mode for a damaged file.
        pub fn open_with(
            path: impl AsRef<Path>,
            recovery: Recovery,
        ) -> Result<BisonStore, StoreError> {
            let path = path.as_ref().to_path_buf();
            if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).map_err(|e| {
                    StoreError::other(format!("content store {}: {e}", dir.display()))
                })?;
            }
            let shown = path.display().to_string();
            let mut db = DbOptions::new()
                .sync(SyncPolicy::Always)
                .recovery(match recovery {
                    Recovery::Strict => RecoveryMode::Strict,
                    Recovery::Salvage => RecoveryMode::Salvage,
                })
                .open(&path)
                .map_err(|e| match e {
                    bison_db::Error::Locked => StoreError::unavailable(format!(
                        "content store {shown} is open in another process: is another instance running on this data folder?"
                    )),
                    bison_db::Error::Corrupt(what) => StoreError::other(format!(
                        "content store {shown} is damaged before its end ({what}); nothing was changed. Back the file up, then start once with content.recovery = \"salvage\" to keep every record that still verifies"
                    )),
                    other => StoreError::other(format!("content store {shown}: {other}")),
                })?;
            db.create_index("slug").map_err(bison)?;
            let discarded = db.discarded_bytes();
            Ok(BisonStore {
                db: RwLock::new(db),
                path,
                discarded,
                failed: AtomicBool::new(false),
            })
        }

        /// Bytes the open removed: a torn last record after a crash, or the
        /// damaged regions a salvage skipped. Logged at boot when not zero.
        #[must_use]
        pub fn discarded(&self) -> u64 {
            self.discarded
        }

        /// Notes a failed write: the provider is unhealthy until reopened.
        fn failing<T>(&self, r: Result<T, StoreError>) -> Result<T, StoreError> {
            if r.is_err() {
                self.failed.store(true, Ordering::Release);
            }
            r
        }

        /// The store's file.
        #[must_use]
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl std::fmt::Debug for BisonStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BisonStore")
                .field("path", &self.path)
                .finish()
        }
    }

    impl Provider for BisonStore {
        fn name(&self) -> &str {
            "content-bison"
        }
        fn healthy(&self) -> bool {
            !self.failed.load(Ordering::Acquire)
        }
        fn flush(&self) -> Result<(), ProviderError> {
            let mut db = self
                .db
                .write()
                .map_err(|_| ProviderError("content store lock poisoned".into()))?;
            db.flush()
                .map_err(|e| ProviderError(format!("content store: {e}")))
        }
    }

    impl ContentStore for BisonStore {
        fn load(&self) -> Result<Vec<Stored>, StoreError> {
            let db = self
                .db
                .read()
                .map_err(|_| StoreError::other("store lock poisoned"))?;
            let mut out = Vec::with_capacity(db.len());
            for id in db.ids() {
                let Some(doc) = db.get(id).map_err(bison)? else {
                    continue;
                };
                let text = |name: &str| {
                    doc.get(name)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                };
                let mut meta = Meta::default();
                for name in Meta::FIELDS {
                    if let Some(f) = meta.get_mut(name) {
                        *f = text(name);
                    }
                }
                let fields = doc
                    .iter()
                    .filter_map(|(k, v)| {
                        let name = k.strip_prefix(FIELD_PREFIX)?;
                        Some((name.to_owned(), v.as_str()?.to_owned()))
                    })
                    .collect();
                out.push(Stored {
                    kind: text("kind"),
                    slug: text("slug"),
                    title: text("title"),
                    summary: text("summary"),
                    body: text("body"),
                    date: text("date"),
                    meta,
                    fields,
                });
            }
            Ok(out)
        }

        fn put(&self, entry: &Stored) -> Result<(), StoreError> {
            let mut doc = Document::new();
            let values = [
                &entry.kind,
                &entry.slug,
                &entry.title,
                &entry.summary,
                &entry.body,
                &entry.date,
            ];
            for (name, value) in FIELDS.iter().zip(values) {
                doc.set(*name, value.as_str());
            }
            for name in Meta::FIELDS {
                let value = entry.meta.get(name).unwrap_or("");
                if !value.is_empty() {
                    doc.set(name, value);
                }
            }
            for (name, value) in &entry.fields {
                doc.set(format!("{FIELD_PREFIX}{name}").as_str(), value.as_str());
            }
            self.failing((|| {
                let mut db = self
                    .db
                    .write()
                    .map_err(|_| StoreError::other("store lock poisoned"))?;
                let existing = db
                    .find("slug", &Value::from(entry.slug.as_str()))
                    .map_err(bison)?;
                match existing.first() {
                    Some(id) => {
                        db.update(*id, doc).map_err(bison)?;
                    }
                    None => {
                        db.insert(doc).map_err(bison)?;
                    }
                }
                Ok(())
            })())
        }

        fn remove(&self, slug: &str) -> Result<bool, StoreError> {
            self.failing((|| {
                let mut db = self
                    .db
                    .write()
                    .map_err(|_| StoreError::other("store lock poisoned"))?;
                let ids = db.find("slug", &Value::from(slug)).map_err(bison)?;
                let mut any = false;
                for id in ids {
                    any |= db.delete(id).map_err(bison)?;
                }
                Ok(any)
            })())
        }
    }
}

/// The draft's value for the field `name`, or empty.
fn field_of<'d>(draft: &'d Draft<'_>, name: &str) -> &'d str {
    draft
        .fields
        .iter()
        .find(|(n, _)| n == name)
        .map_or("", |(_, v)| v.as_str())
}

/// Escapes text for HTML, once, at save time.
fn escape_into(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}

impl Manifest {
    /// An empty manifest.
    #[must_use]
    pub fn new() -> Manifest {
        Manifest::default()
    }

    /// An empty manifest for a site installed under `base` (`/blog`): entry
    /// URLs are prepared with it.
    #[must_use]
    pub fn with_base(base: &str) -> Manifest {
        Manifest {
            base: base.trim_end_matches('/').to_owned(),
            ..Manifest::default()
        }
    }

    /// The same manifest, with these custom fields declared.
    #[must_use]
    pub fn with_fields(mut self, fields: Fields) -> Manifest {
        self.fields = Arc::new(fields);
        self
    }

    /// The custom fields declared.
    #[must_use]
    pub fn fields(&self) -> &Fields {
        &self.fields
    }

    /// Validates and prepares a draft, then stores it (replacing an entry with
    /// the same slug) and rebuilds the post listing, newest first.
    pub fn save(&mut self, draft: &Draft<'_>) -> Result<(), SaveError> {
        self.save_checked(draft, false)
    }

    /// [`save`](Self::save), with `required` custom fields not checked when
    /// `seed` (the sample content a first run gets knows no field the site
    /// declares).
    fn save_checked(&mut self, draft: &Draft<'_>, seed: bool) -> Result<(), SaveError> {
        self.validate(draft, seed)?;
        let entry = Arc::new(self.prepare(draft));
        if let Some(store) = &self.store {
            // The author's text is what is stored; the HTML is made again
            // from it at every load, never trusted from the store.
            store
                .put(&Stored {
                    kind: entry.kind.clone(),
                    slug: entry.slug.clone(),
                    title: entry.title.clone(),
                    summary: entry.summary.clone(),
                    body: draft.body.to_owned(),
                    date: entry.date.clone(),
                    meta: entry.meta.clone(),
                    fields: entry
                        .fields
                        .iter()
                        .map(|f| (f.name.clone(), f.value.clone()))
                        .collect(),
                })
                .map_err(SaveError::Store)?;
        }
        self.entries.insert(entry.slug.clone(), entry);
        self.rebuild_posts();
        Ok(())
    }

    /// The rules a draft must meet, at save and at load (`load`: a required
    /// custom field may be empty, and a value nothing declares is passed
    /// over).
    fn validate(&self, draft: &Draft<'_>, load: bool) -> Result<(), Invalid> {
        let slug_ok = !draft.slug.is_empty()
            && draft
                .slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !slug_ok {
            return Err(Invalid(format!(
                "slug `{}`: lowercase letters, digits, and `-` only",
                draft.slug
            )));
        }
        if draft.title.trim().is_empty() {
            return Err(Invalid(format!("`{}` has no title", draft.slug)));
        }
        if draft.kind == Kind::Post && draft.date.len() != 10 {
            return Err(Invalid(format!(
                "post `{}` needs a date (YYYY-MM-DD)",
                draft.slug
            )));
        }
        draft
            .meta
            .check()
            .map_err(|e| Invalid(format!("`{}`: {}", draft.slug, e.0)))?;
        let declared = self.fields.of(draft.kind);
        if !load
            && let Some((name, _)) = draft
                .fields
                .iter()
                .find(|(n, _)| !declared.iter().any(|d| d.name == *n))
        {
            return Err(Invalid(format!(
                "`{}`: no field `{name}` is declared for a {}",
                draft.slug,
                draft.kind.as_str()
            )));
        }
        for decl in declared {
            let value = field_of(draft, &decl.name);
            let v = field_value(decl, value)
                .map_err(|why| Invalid(format!("`{}`: {} {why}", draft.slug, decl.label)))?;
            if !load && decl.required && (v.is_empty() || v == "false") {
                return Err(Invalid(format!(
                    "`{}`: {} is required",
                    draft.slug, decl.label
                )));
            }
        }
        Ok(())
    }

    /// A draft that passed validation, prepared: the body escaped and split
    /// into paragraphs, the URL made for this site's base.
    fn prepare(&self, draft: &Draft<'_>) -> Entry {
        // A browser sends a textarea's line breaks as CRLF.
        let text = unix_newlines(draft.body);
        let mut body = String::with_capacity(text.len() + 32);
        for para in text.split("\n\n").map(str::trim).filter(|p| !p.is_empty()) {
            body.push_str("<p>");
            escape_into(&mut body, para);
            body.push_str("</p>");
        }
        let url = match draft.kind {
            Kind::Page => format!("{}/{}", self.base, draft.slug),
            Kind::Post => format!("{}/posts/{}", self.base, draft.slug),
        };
        Entry {
            kind: draft.kind.as_str().to_owned(),
            slug: draft.slug.to_owned(),
            title: draft.title.to_owned(),
            url,
            summary: draft.summary.to_owned(),
            body,
            date: draft.date.to_owned(),
            text: text.into_owned(),
            meta: draft.meta.cleaned(),
            fields: Arc::new(
                self.fields
                    .of(draft.kind)
                    .iter()
                    .map(|d| FieldValue {
                        name: d.name.clone(),
                        label: d.label.clone(),
                        kind: d.kind.as_str().to_owned(),
                        // Checked by `validate` already.
                        value: field_value(d, field_of(draft, &d.name)).unwrap_or_default(),
                    })
                    .collect(),
            ),
        }
    }

    /// Rebuilds the post listing, newest first.
    fn rebuild_posts(&mut self) {
        let mut posts: Vec<Arc<Entry>> = self
            .entries
            .values()
            .filter(|e| e.kind == "post")
            .cloned()
            .collect();
        posts.sort_by(|a, b| b.date.cmp(&a.date).then_with(|| a.slug.cmp(&b.slug)));
        self.posts = Arc::new(posts);
    }

    /// The manifest of everything in `store`, for a site under `base`; saves
    /// go through the store. An empty store is given the sample content
    /// (`seed`), so a first run has a site.
    pub fn open(
        store: Arc<dyn ContentStore>,
        base: &str,
        seed: bool,
    ) -> Result<Manifest, StoreError> {
        Manifest::open_with(store, base, seed, Fields::default())
    }

    /// [`open`](Self::open), with these custom fields declared: every
    /// stored value is checked against its field's type.
    pub fn open_with(
        store: Arc<dyn ContentStore>,
        base: &str,
        seed: bool,
        fields: Fields,
    ) -> Result<Manifest, StoreError> {
        let mut m = Manifest::with_base(base).with_fields(fields);
        let stored = store.load()?;
        for s in &stored {
            // The same rules and preparation as a save: what any writer put
            // in the store is checked and escaped like an author's draft,
            // never trusted as HTML.
            let kind = match s.kind.as_str() {
                "post" => Kind::Post,
                "page" => Kind::Page,
                other => {
                    return Err(StoreError::other(format!(
                        "`{}`: unknown kind `{other}`",
                        s.slug
                    )));
                }
            };
            let draft = Draft {
                kind,
                slug: &s.slug,
                title: &s.title,
                summary: &s.summary,
                body: &s.body,
                date: &s.date,
                meta: s.meta.clone(),
                fields: s.fields.clone(),
            };
            m.validate(&draft, true)
                .map_err(|e| StoreError::invalid(e.0))?;
            let entry = Arc::new(m.prepare(&draft));
            m.entries.insert(entry.slug.clone(), entry);
        }
        // One listing for everything loaded, not one per entry.
        m.rebuild_posts();
        m.store = Some(store);
        if stored.is_empty() && seed {
            for d in &sample_drafts() {
                m.save_checked(d, true).map_err(|e| match e {
                    SaveError::Store(e) => e,
                    SaveError::Invalid(e) => StoreError::invalid(e.0),
                })?;
            }
        }
        Ok(m)
    }

    /// Removes an entry (from the store too).
    pub fn remove(&mut self, slug: &str) -> Result<bool, StoreError> {
        if let Some(store) = &self.store {
            store.remove(slug)?;
        }
        let gone = self.entries.remove(slug).is_some();
        if gone {
            let posts: Vec<Arc<Entry>> = self
                .posts
                .iter()
                .filter(|p| p.slug != slug)
                .cloned()
                .collect();
            self.posts = Arc::new(posts);
        }
        Ok(gone)
    }

    /// The entry with this slug and kind.
    #[must_use]
    pub fn get(&self, kind: Kind, slug: &str) -> Option<Arc<Entry>> {
        self.entries
            .get(slug)
            .filter(|e| e.kind == kind.as_str())
            .cloned()
    }

    /// The entry with this slug, of either kind.
    #[must_use]
    pub fn find(&self, slug: &str) -> Option<Arc<Entry>> {
        self.entries.get(slug).cloned()
    }

    /// Whether an entry of either kind has this slug (one slug, one entry).
    #[must_use]
    pub fn contains(&self, slug: &str) -> bool {
        self.entries.contains_key(slug)
    }

    /// Every entry: posts newest first, then pages by slug.
    #[must_use]
    pub fn all(&self) -> Vec<Arc<Entry>> {
        let mut all: Vec<Arc<Entry>> = self.posts.iter().cloned().collect();
        all.extend(self.entries.values().filter(|e| e.kind == "page").cloned());
        all
    }

    /// The posts, newest first (shared, not copied).
    #[must_use]
    pub fn posts(&self) -> Arc<Vec<Arc<Entry>>> {
        self.posts.clone()
    }

    /// The sample content.
    #[must_use]
    pub fn sample() -> Manifest {
        Manifest::sample_at("")
    }

    /// The sample content for a site under `base`.
    #[must_use]
    pub fn sample_at(base: &str) -> Manifest {
        let mut m = Manifest::with_base(base);
        let drafts = sample_drafts();
        for d in &drafts {
            // The sample is fixed and valid.
            let _ = m.save(d);
        }
        m
    }
}

/// Today's date in UTC (`YYYY-MM-DD`), the default for a new post.
#[must_use]
pub fn today() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    date_of(i64::try_from(secs / 86_400).unwrap_or(0))
}

/// The civil date `days` after 1970-01-01.
fn date_of(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The content the site serves, shared by every request and the editor.
///
/// A request takes a snapshot (one `Arc`, no lock held while it renders). A
/// save prepares the next manifest beside the live one, writes through the
/// store, and swaps it in; saves run one at a time, and readers only ever
/// wait for the swap of a pointer, never for the store.
pub struct Content {
    live: RwLock<Arc<Manifest>>,
    writer: Mutex<()>,
    changed: Vec<Box<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Content")
            .field("live", &self.snapshot())
            .field("listeners", &self.changed.len())
            .finish()
    }
}

impl Content {
    /// The content of `manifest`.
    #[must_use]
    pub fn new(manifest: Manifest) -> Content {
        Content {
            live: RwLock::new(Arc::new(manifest)),
            writer: Mutex::new(()),
            changed: Vec::new(),
        }
    }

    /// The same content, calling `f` after every change is live (to drop
    /// cached pages).
    #[must_use]
    pub fn on_change(mut self, f: impl Fn() + Send + Sync + 'static) -> Content {
        self.changed.push(Box::new(f));
        self
    }

    /// The content as it is now.
    #[must_use]
    pub fn snapshot(&self) -> Arc<Manifest> {
        self.live
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn publish(&self, next: Manifest) {
        *self.live.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
        for f in &self.changed {
            f();
        }
    }

    /// Saves `draft`. `replaces` is the slug the editor opened (`None` for
    /// a new entry): a slug that another entry already has is refused, and
    /// a renamed entry's old slug is removed.
    pub fn save(&self, draft: &Draft<'_>, replaces: Option<&str>) -> Result<(), SaveError> {
        let _one = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = (*self.snapshot()).clone();
        let renamed = replaces.filter(|old| *old != draft.slug && next.contains(old));
        if replaces != Some(draft.slug) && next.contains(draft.slug) {
            return Err(SaveError::Invalid(Invalid(format!(
                "slug `{}` is taken: another page or post has it",
                draft.slug
            ))));
        }
        next.save(draft)?;
        let removed = match renamed {
            Some(old) => next.remove(old).map(|_| ()),
            None => Ok(()),
        };
        // What the store took is live, even when removing the old slug
        // failed (both entries are then in the store and in memory).
        self.publish(next);
        removed.map_err(SaveError::Store)
    }

    /// Removes the entry with this slug; `false` when there was none.
    pub fn remove(&self, slug: &str) -> Result<bool, StoreError> {
        let _one = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = (*self.snapshot()).clone();
        let gone = next.remove(slug)?;
        if gone {
            self.publish(next);
        }
        Ok(gone)
    }
}

fn sample_drafts() -> [Draft<'static>; 4] {
    [
        Draft {
            kind: Kind::Post,
            slug: "hello-world",
            title: "Hello, world",
            summary: "The first page through the gateway, the core, and the web service.",
            body: "This page came in through the gateway, was identified by the core, routed by the web service, and rendered by the theme.\n\nEvery value on it was read through a view, never through JSON.",
            date: "2026-11-08",
            meta: Meta::default(),
            fields: Vec::new(),
        },
        Draft {
            kind: Kind::Post,
            slug: "the-passport",
            title: "The passport",
            summary: "One per request, from the pool to the reply and back.",
            body: "Every request carries one from the pool to the reply, and back, wiped.",
            date: "2026-11-09",
            meta: Meta::default(),
            fields: Vec::new(),
        },
        Draft {
            kind: Kind::Post,
            slug: "escaping",
            title: "Tom & Jerry <script>alert(1)</script>",
            summary: "A title with markup in it, written as text.",
            body: "<b>Not bold.</b> & not a tag either.",
            date: "2026-11-10",
            meta: Meta::default(),
            fields: Vec::new(),
        },
        Draft {
            kind: Kind::Page,
            slug: "about",
            title: "About",
            summary: "What this site is.",
            body: "A site in memory, themed from a folder, on the platform's walking skeleton.",
            date: "",
            meta: Meta::default(),
            fields: Vec::new(),
        },
    ]
}

/// `text` with every CRLF and lone CR as LF.
fn unix_newlines(text: &str) -> std::borrow::Cow<'_, str> {
    if text.contains('\r') {
        std::borrow::Cow::Owned(text.replace("\r\n", "\n").replace('\r', "\n"))
    } else {
        std::borrow::Cow::Borrowed(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(text: &str) -> Result<Fields, String> {
        Fields::from_config(&Config::from_text(text).expect("toml"))
    }

    #[test]
    fn field_declarations_are_checked() {
        for (text, says) in [
            (
                "[content.fields.post.Author]\ntype = \"text\"\n",
                "lower case",
            ),
            (
                "[content.fields.post.author]\ntype = \"colour\"\n",
                "text, textarea",
            ),
            (
                "[content.fields.post.size]\ntype = \"select\"\n",
                "1 to 100 options",
            ),
            (
                "[content.fields.post.size]\ntype = \"text\"\noptions = [\"a\"]\n",
                "only a select",
            ),
            (
                "[content.fields.post.size]\nlable = \"Size\"\n",
                "unknown key",
            ),
            (
                "[content.fields.post.size]\nlabel = \"Size\"\n",
                "type is missing",
            ),
            (
                "[content.fields.event.size]\ntype = \"text\"\n",
                "`post` or `page`",
            ),
        ] {
            let e = fields(text).expect_err(text);
            assert!(e.contains(says), "{text}: {e}");
        }
        let f = fields(
            "[content.fields.post.zeta]\ntype = \"text\"\norder = 1\n[content.fields.post.alpha]\ntype = \"text\"\norder = 2\n[content.fields.post.beta]\ntype = \"text\"\norder = 1\n",
        )
        .expect("fields");
        let names: Vec<&str> = f.of(Kind::Post).iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["beta", "zeta", "alpha"], "by order, then name");
        assert!(f.of(Kind::Page).is_empty());
    }

    #[test]
    fn field_values_are_checked_by_type() {
        let decl = |kind| FieldDecl {
            name: "f".into(),
            label: "F".into(),
            kind,
            required: false,
            help: String::new(),
            options: vec!["small".into(), "large".into()],
            order: 0,
        };
        let ok = |kind, v: &str| field_value(&decl(kind), v);
        assert_eq!(ok(FieldType::Text, "  a\r\n b ").as_deref(), Ok("a b"));
        assert_eq!(ok(FieldType::Textarea, "a\r\nb").as_deref(), Ok("a\nb"));
        assert!(ok(FieldType::Url, "javascript:alert(1)").is_err());
        assert_eq!(
            ok(FieldType::Media, "/static/a.png").as_deref(),
            Ok("/static/a.png")
        );
        assert_eq!(ok(FieldType::Number, "-3.5").as_deref(), Ok("-3.5"));
        for bad in ["1e5", "3.", ".5", "12a", "--1"] {
            assert!(ok(FieldType::Number, bad).is_err(), "{bad}");
        }
        assert_eq!(ok(FieldType::Bool, "on").as_deref(), Ok("true"));
        assert_eq!(ok(FieldType::Bool, "").as_deref(), Ok("false"));
        assert!(ok(FieldType::Bool, "maybe").is_err());
        assert_eq!(
            ok(FieldType::Date, "2024-02-29").as_deref(),
            Ok("2024-02-29")
        );
        for bad in ["2023-02-29", "2026-13-01", "2026-1-01", "20260101"] {
            assert!(ok(FieldType::Date, bad).is_err(), "{bad}");
        }
        assert_eq!(ok(FieldType::Select, "large").as_deref(), Ok("large"));
        assert!(ok(FieldType::Select, "huge").is_err());
        assert!(ok(FieldType::Text, &"x".repeat(FIELD_TEXT_MAX + 1)).is_err());
    }

    #[test]
    fn required_is_checked_at_save_and_types_at_load() {
        let declared = fields("[content.fields.post.price]\ntype = \"number\"\nrequired = true\n")
            .expect("fields");
        let draft = |fields: Vec<(String, String)>| Draft {
            kind: Kind::Post,
            slug: "p",
            title: "P",
            summary: "",
            body: "x",
            date: "2026-11-20",
            meta: Meta::default(),
            fields,
        };
        let mut m = Manifest::new().with_fields(declared.clone());
        let e = m.save(&draft(Vec::new())).expect_err("required");
        assert!(e.to_string().contains("price is required"), "{e}");
        let e = m
            .save(&draft(vec![("colour".into(), "red".into())]))
            .expect_err("undeclared");
        assert!(e.to_string().contains("no field `colour`"), "{e}");
        m.save(&draft(vec![("price".into(), "12.50".into())]))
            .expect("saved");
        let e = m.get(Kind::Post, "p").expect("entry");
        assert_eq!(e.fields[0].value, "12.50");
        assert_eq!(e.fields[0].kind, "number");

        // At load an empty required field passes; a value its type no
        // longer allows does not.
        let store: Arc<dyn ContentStore> = Arc::new(MemoryStore::new());
        let stored = |value: &str| Stored {
            kind: "post".into(),
            slug: "p".into(),
            title: "P".into(),
            summary: String::new(),
            body: "x".into(),
            date: "2026-11-20".into(),
            meta: Meta::default(),
            fields: vec![("price".into(), value.into())],
        };
        store.put(&stored("")).expect("put");
        Manifest::open_with(store.clone(), "", false, declared.clone())
            .expect("an empty required field loads");
        store.put(&stored("cheap")).expect("put");
        let e = Manifest::open_with(store, "", false, declared).expect_err("not a number");
        assert!(e.message.contains("price must be a number"), "{e:?}");
    }

    #[test]
    fn meta_fields_are_cleaned_and_checked() {
        let m = Meta {
            seo_title: "  A\r\n title  ".into(),
            robots: "NoIndex ,NOFOLLOW".into(),
            twitter_card: " Summary ".into(),
            ..Meta::default()
        };
        let c = m.cleaned();
        assert_eq!(c.seo_title, "A title");
        assert_eq!(c.robots, "noindex, nofollow");
        assert_eq!(c.twitter_card, "summary");
        assert!(m.check().is_ok());
        for bad in [
            Meta {
                canonical: "javascript:alert(1)".into(),
                ..Meta::default()
            },
            Meta {
                canonical: "//evil.example/".into(),
                ..Meta::default()
            },
            Meta {
                og_image: "https://".into(),
                ..Meta::default()
            },
            Meta {
                og_image: "/a\"b.png".into(),
                ..Meta::default()
            },
            Meta {
                robots: "noarchive".into(),
                ..Meta::default()
            },
            Meta {
                twitter_card: "player".into(),
                ..Meta::default()
            },
            Meta {
                description: "x".repeat(META_DESCRIPTION_MAX + 1),
                ..Meta::default()
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        assert!(
            Meta {
                canonical: "https://example.com/about".into(),
                og_image: "/static/card.png".into(),
                ..Meta::default()
            }
            .check()
            .is_ok()
        );
    }

    #[test]
    fn line_breaks_from_a_browser_make_paragraphs() {
        let mut m = Manifest::sample();
        m.save(&Draft {
            kind: Kind::Post,
            slug: "crlf",
            title: "From a browser",
            summary: "",
            body: "First line\r\nstill first.\r\n\r\nSecond.\r\rThird, from an old Mac.",
            date: "2026-11-19",
            meta: Meta::default(),
            fields: Vec::new(),
        })
        .expect("save");
        let e = m.get(Kind::Post, "crlf").expect("entry");
        assert_eq!(
            e.body,
            "<p>First line\nstill first.</p><p>Second.</p><p>Third, from an old Mac.</p>"
        );
        assert!(
            !e.text.contains('\r'),
            "the text kept for editing has no CR"
        );
    }

    #[test]
    fn save_prepares_escaped_paragraphs_and_lists_posts_newest_first() {
        let m = Manifest::sample();
        let e = m.get(Kind::Post, "escaping").expect("entry");
        assert_eq!(
            e.body,
            "<p>&lt;b&gt;Not bold.&lt;/b&gt; &amp; not a tag either.</p>"
        );
        assert_eq!(e.url, "/posts/escaping");
        let slugs: Vec<_> = m.posts().iter().map(|p| p.slug.clone()).collect();
        assert_eq!(slugs, ["escaping", "the-passport", "hello-world"]);
        assert!(m.get(Kind::Post, "about").is_none(), "a page is not a post");
    }

    #[test]
    fn content_survives_a_restart_in_bison_db() {
        let dir = std::env::temp_dir().join(format!("wasp-content-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("content.bison");
        {
            let store: Arc<dyn ContentStore> = Arc::new(BisonStore::open(&path).expect("open"));
            let mut m = Manifest::open(store.clone(), "", true).expect("manifest");
            assert_eq!(m.posts().len(), 3, "seeded on first open");
            m.save(&Draft {
                kind: Kind::Post,
                slug: "after-restart",
                title: "Still here",
                summary: "Saved before the restart.",
                body: "A <b>body</b>.",
                date: "2026-11-11",
                meta: Meta::default(),
                fields: Vec::new(),
            })
            .expect("save");
            assert!(m.remove("hello-world").expect("remove"));
            store.flush().expect("flush");
        }
        // A new process: nothing in memory, the file is all there is.
        let store: Arc<dyn ContentStore> = Arc::new(BisonStore::open(&path).expect("reopen"));
        let m = Manifest::open(store, "/blog", true).expect("manifest");
        let e = m.get(Kind::Post, "after-restart").expect("survived");
        assert_eq!(e.title, "Still here");
        assert_eq!(
            e.body, "<p>A &lt;b&gt;body&lt;/b&gt;.</p>",
            "stored prepared, not re-parsed"
        );
        assert_eq!(
            e.url, "/blog/posts/after-restart",
            "URL from where the site is now"
        );
        assert!(
            m.get(Kind::Post, "hello-world").is_none(),
            "the removal survived too"
        );
        assert_eq!(m.posts().len(), 3, "not seeded again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dates_are_civil_dates() {
        assert_eq!(super::date_of(0), "1970-01-01");
        assert_eq!(super::date_of(11_016), "2000-02-29");
        assert_eq!(super::date_of(19_723), "2024-01-01");
        assert_eq!(super::today().len(), 10);
    }

    #[test]
    fn content_saves_renames_and_refuses_a_taken_slug() {
        let changes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = changes.clone();
        let content = Content::new(Manifest::sample()).on_change(move || {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let before = content.snapshot();
        let draft = Draft {
            kind: Kind::Page,
            slug: "contact",
            title: "Contact",
            summary: "",
            body: "Write to us.",
            date: "",
            meta: Meta::default(),
            fields: Vec::new(),
        };
        content.save(&draft, None).expect("new");
        assert!(before.find("contact").is_none(), "a snapshot never changes");
        assert_eq!(
            content.snapshot().find("contact").map(|e| e.text.clone()),
            Some("Write to us.".to_owned())
        );
        let taken = content.save(
            &Draft {
                slug: "about",
                ..draft.clone()
            },
            None,
        );
        assert!(matches!(taken, Err(SaveError::Invalid(_))), "{taken:?}");
        let renamed = Draft {
            slug: "write-to-us",
            ..draft.clone()
        };
        content.save(&renamed, Some("contact")).expect("renamed");
        let now = content.snapshot();
        assert!(now.find("contact").is_none() && now.find("write-to-us").is_some());
        assert!(content.remove("write-to-us").expect("removed"));
        assert!(!content.remove("write-to-us").expect("gone"));
        // A save, a rename, a removal: each told the listeners (the refused
        // save and the removal of nothing did not).
        assert_eq!(changes.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn invalid_drafts_are_refused() {
        let mut m = Manifest::new();
        let bad = Draft {
            kind: Kind::Post,
            slug: "Bad Slug",
            title: "x",
            summary: "",
            body: "",
            date: "2026-11-10",
            meta: Meta::default(),
            fields: Vec::new(),
        };
        assert!(m.save(&bad).is_err());
        assert!(
            m.save(&Draft {
                slug: "ok",
                date: "",
                ..bad.clone()
            })
            .is_err(),
            "a post needs a date"
        );
        assert!(
            m.save(&Draft {
                slug: "ok",
                title: " ",
                ..bad
            })
            .is_err()
        );
    }

    #[test]
    fn what_the_store_holds_is_escaped_and_checked_at_load() {
        // Review F-7: anything that writes the store (an import, a restore,
        // another process) is treated like an author's draft.
        let store = Arc::new(MemoryStore::new());
        let put = |kind: &str, slug: &str, body: &str| {
            store
                .put(&Stored {
                    kind: kind.into(),
                    slug: slug.into(),
                    title: "Imported".into(),
                    summary: String::new(),
                    body: body.into(),
                    date: "2026-11-11".into(),
                    meta: Meta::default(),
                    fields: Vec::new(),
                })
                .expect("put");
        };
        put(
            "post",
            "x",
            "hi<script>alert(1)</script><meta http-equiv=refresh content=\"0;url=https://evil.example/\">",
        );
        let m = Manifest::open(store.clone(), "", false).expect("open");
        let body = &m.get(Kind::Post, "x").expect("entry").body;
        assert!(!body.contains("<script"), "{body}");
        assert!(!body.contains("<meta"), "{body}");
        assert!(body.starts_with("<p>hi&lt;script&gt;"), "{body}");

        put("post", "Bad Slug", "x");
        assert!(
            Manifest::open(store.clone(), "", false).is_err(),
            "slug rule at load"
        );
        let _ = store.remove("Bad Slug");
        put("script", "y", "x");
        assert!(
            Manifest::open(store.clone(), "", false).is_err(),
            "unknown kind at load"
        );
    }
}
