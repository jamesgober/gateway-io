//! Log rules: which finished requests get a line, with which fields, where
//! to, and how many a second. One table per rule, `[log_rule.<name>]`:
//!
//! | Key | Default | Meaning |
//! |---|---|---|
//! | `codes` | required | statuses (`"404"`) or classes (`"5xx"`), from 100 to 599 |
//! | `fields` | `client`, `method`, `path`, `status`, `code`, `request` | from `client`, `method`, `path`, `query`, `status`, `code`, `message`, `user`, `user_agent`, `referrer`, `request` |
//! | `include_query` | false | the query is written only when this is true |
//! | `destination` | `log` | `log` (the foundation's log) or `file:<path>` (JSON lines, owner-only) |
//! | `max_size` | 10485760 | a file destination's size before it is rotated, in bytes (64 KiB to 1 GiB) |
//! | `keep` | 5 | rotated files kept (0 to 100) |
//! | `rate` | 100 | lines a second at most; `0` for no cap |
//!
//! `client` is the address the access log and the bouncer use: the peer,
//! or the forwarded address only when the peer is a trusted proxy. The
//! lines are written on the access log's thread, never on a worker; what a
//! rule could not write (over its rate, a full queue, a file it could not
//! write or rotate) is counted and reported in its next line as `dropped`.

use std::fs::File;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime};

use wasp_core::suite::config::Config;
use wasp_core::suite::log::{Field as LogField, Level, Value};

use crate::access::AccessEntry;

/// The longest user agent or referrer kept, in bytes.
pub const MAX_HEADER: usize = 256;

/// The longest query kept, in bytes.
pub const MAX_QUERY: usize = 512;

/// The most rules.
pub const MAX_RULES: usize = 64;

/// A field a rule can write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// The client address.
    Client,
    /// The method.
    Method,
    /// The path, without the query.
    Path,
    /// The query (only with `include_query`).
    Query,
    /// The status.
    Status,
    /// The application's error code.
    Code,
    /// The message the service gave.
    Message,
    /// The signed-in account's id.
    User,
    /// The `User-Agent` header, cut to [`MAX_HEADER`] bytes.
    UserAgent,
    /// The `Referer` header, cut to [`MAX_HEADER`] bytes.
    Referrer,
    /// The request's reference (what an error page shows).
    Request,
}

impl Field {
    fn parse(name: &str) -> Option<Field> {
        Some(match name {
            "client" => Field::Client,
            "method" => Field::Method,
            "path" => Field::Path,
            "query" => Field::Query,
            "status" => Field::Status,
            "code" => Field::Code,
            "message" => Field::Message,
            "user" => Field::User,
            "user_agent" => Field::UserAgent,
            "referrer" => Field::Referrer,
            "request" => Field::Request,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Field::Client => "client",
            Field::Method => "method",
            Field::Path => "path",
            Field::Query => "query",
            Field::Status => "status",
            Field::Code => "code",
            Field::Message => "message",
            Field::User => "user",
            Field::UserAgent => "user_agent",
            Field::Referrer => "referrer",
            Field::Request => "request",
        }
    }
}

const DEFAULT_FIELDS: &[Field] = &[
    Field::Client,
    Field::Method,
    Field::Path,
    Field::Status,
    Field::Code,
    Field::Request,
];

/// Where a rule's lines go.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    /// The foundation's log: info for 1xx to 4xx, warn for 5xx.
    Log,
    /// A file of its own, one JSON line per request.
    File {
        /// The file.
        path: PathBuf,
        /// Its size before it is rotated.
        max_size: u64,
        /// Rotated files kept.
        keep: u32,
    },
}

/// One rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Its name (`[log_rule.<name>]`).
    pub name: String,
    codes: Vec<(u16, u16)>,
    fields: Vec<Field>,
    destination: Destination,
    rate: u32,
}

impl Rule {
    fn matches(&self, status: u16) -> bool {
        self.codes
            .iter()
            .any(|(lo, hi)| (*lo..=*hi).contains(&status))
    }
}

/// What the head hook must keep for the rules.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wants {
    /// The query.
    pub query: bool,
    /// The `User-Agent` header.
    pub user_agent: bool,
    /// The `Referer` header.
    pub referrer: bool,
}

/// Every rule.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogRules {
    rules: Vec<Rule>,
}

/// The rules in force, swapped whole by a reload.
pub type LogRulesCell = Arc<RwLock<Arc<LogRules>>>;

const RULE_KEYS: &[&str] = &[
    "codes",
    "destination",
    "fields",
    "include_query",
    "keep",
    "max_size",
    "rate",
];

impl LogRules {
    /// The rules `[log_rule.*]` sets. A bad rule is refused with its key.
    pub fn from_config(config: &Config) -> Result<LogRules, String> {
        let e = |e: wasp_core::suite::Error| e.to_string();
        let names = config.keys("log_rule");
        if names.len() > MAX_RULES {
            return Err(format!("[log_rule]: at most {MAX_RULES} rules"));
        }
        let mut rules = Vec::new();
        for name in names {
            let at = format!("log_rule.{name}");
            if let Some(k) = config
                .keys(&at)
                .into_iter()
                .find(|k| !RULE_KEYS.contains(k))
            {
                return Err(format!(
                    "unknown key `{at}.{k}`: the keys of a rule are {}",
                    RULE_KEYS.join(", ")
                ));
            }
            let Some(code_list) = config
                .get::<Vec<String>>(&format!("{at}.codes"))
                .map_err(e)?
            else {
                return Err(format!(
                    "{at}.codes is missing (statuses like \"404\" or classes like \"5xx\")"
                ));
            };
            if code_list.is_empty() {
                return Err(format!("{at}.codes is empty"));
            }
            let mut codes = Vec::new();
            for c in &code_list {
                codes.push(code_range(c).ok_or_else(|| {
                    format!("{at}.codes: `{c}` is not a status from 100 to 599 or a class from 1xx to 5xx")
                })?);
            }
            let include_query: bool = config
                .get_or(&format!("{at}.include_query"), false)
                .map_err(e)?;
            let fields = match config
                .get::<Vec<String>>(&format!("{at}.fields"))
                .map_err(e)?
            {
                None => DEFAULT_FIELDS.to_vec(),
                Some(list) => {
                    let mut out = Vec::new();
                    for f in &list {
                        let field = Field::parse(f)
                            .ok_or_else(|| format!("{at}.fields: no field `{f}`"))?;
                        if !out.contains(&field) {
                            out.push(field);
                        }
                    }
                    out
                }
            };
            // The query only with the switch, whatever the list says.
            let fields: Vec<Field> = fields
                .into_iter()
                .filter(|f| *f != Field::Query || include_query)
                .collect();
            let fields = if include_query && !fields.contains(&Field::Query) {
                let mut f = fields;
                f.push(Field::Query);
                f
            } else {
                fields
            };
            let destination: String = config
                .get_or(&format!("{at}.destination"), "log".to_owned())
                .map_err(e)?;
            let max_size: u64 = config
                .get_or(&format!("{at}.max_size"), 10 * 1024 * 1024_u64)
                .map_err(e)?;
            let keep: u64 = config.get_or(&format!("{at}.keep"), 5_u64).map_err(e)?;
            let destination = match destination.as_str() {
                "log" => Destination::Log,
                other => {
                    let Some(path) = other.strip_prefix("file:").filter(|p| !p.trim().is_empty())
                    else {
                        return Err(format!(
                            "{at}.destination is `{other}`: `log`, or `file:` and a path"
                        ));
                    };
                    if !(64 * 1024..=1024 * 1024 * 1024).contains(&max_size) {
                        return Err(format!(
                            "{at}.max_size must be between 65536 (64 KiB) and 1073741824 (1 GiB)"
                        ));
                    }
                    if keep > 100 {
                        return Err(format!("{at}.keep must be at most 100"));
                    }
                    Destination::File {
                        path: PathBuf::from(path.trim()),
                        max_size,
                        keep: u32::try_from(keep).unwrap_or(100),
                    }
                }
            };
            let rate: u64 = config.get_or(&format!("{at}.rate"), 100_u64).map_err(e)?;
            if rate > 100_000 {
                return Err(format!(
                    "{at}.rate must be at most 100000 a second (0 for no cap)"
                ));
            }
            rules.push(Rule {
                name: name.to_owned(),
                codes,
                fields,
                destination,
                rate: u32::try_from(rate).unwrap_or(100_000),
            });
        }
        Ok(LogRules { rules })
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rules.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// What the head hook must keep for these rules.
    #[must_use]
    pub fn wants(&self) -> Wants {
        let any = |f: Field| self.rules.iter().any(|r| r.fields.contains(&f));
        Wants {
            query: any(Field::Query),
            user_agent: any(Field::UserAgent),
            referrer: any(Field::Referrer),
        }
    }
}

/// `404` as (404, 404), `5xx` as (500, 599).
fn code_range(text: &str) -> Option<(u16, u16)> {
    let t = text.trim();
    if t.len() != 3 {
        return None;
    }
    if let Some(class) = t.strip_suffix("xx") {
        let c: u16 = class.parse().ok()?;
        return (1..=5).contains(&c).then_some((c * 100, c * 100 + 99));
    }
    let n: u16 = t.parse().ok()?;
    (100..=599).contains(&n).then_some((n, n))
}

/// What the rules' writer keeps per rule: its rate window, what it could
/// not write since its last line, and its open file.
#[derive(Default)]
struct State {
    second: Option<Instant>,
    in_second: u32,
    dropped: u64,
    file: Option<(File, u64)>,
}

/// The rules' side of the access log's writer thread.
pub(crate) struct Writer {
    cell: LogRulesCell,
    seen: Arc<LogRules>,
    states: Vec<State>,
}

impl Writer {
    pub(crate) fn new(cell: LogRulesCell) -> Writer {
        Writer {
            cell,
            seen: Arc::default(),
            states: Vec::new(),
        }
    }

    /// Writes `e` for every rule it matches.
    pub(crate) fn write(
        &mut self,
        logger: Option<&wasp_core::suite::log::Logger>,
        e: &AccessEntry,
    ) {
        let now = self
            .cell
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if !Arc::ptr_eq(&now, &self.seen) {
            // New rules: fresh windows and counts, files opened again.
            self.states = now.rules.iter().map(|_| State::default()).collect();
            self.seen = now;
        }
        let Some(status) = e.status else { return };
        for (rule, state) in self.seen.rules.iter().zip(self.states.iter_mut()) {
            if !rule.matches(status) {
                continue;
            }
            if rule.rate > 0 {
                let t = Instant::now();
                match state.second {
                    Some(s) if t.duration_since(s).as_secs() < 1 => {}
                    _ => {
                        state.second = Some(t);
                        state.in_second = 0;
                    }
                }
                if state.in_second >= rule.rate {
                    state.dropped += 1;
                    continue;
                }
                state.in_second += 1;
            }
            let dropped = state.dropped + e.dropped;
            let written = match &rule.destination {
                Destination::Log => {
                    if let Some(l) = logger {
                        log_line(l, rule, e, status, dropped);
                    }
                    true
                }
                Destination::File {
                    path,
                    max_size,
                    keep,
                } => {
                    let line = json_line(rule, e, status, dropped);
                    write_file(state, path, *max_size, *keep, &line)
                }
            };
            if written {
                state.dropped = 0;
            } else {
                state.dropped += 1;
            }
        }
    }
}

/// The value of `field` in `e`, as text (empty when the request had none).
fn text_of(field: Field, e: &AccessEntry) -> String {
    match field {
        Field::Client => e.client.map(|a: IpAddr| a.to_string()).unwrap_or_default(),
        Field::Method => e.method.to_string(),
        Field::Path => e.path.to_string(),
        Field::Query => e.query.as_deref().unwrap_or("").to_owned(),
        Field::Status => e.status.map(|s| s.to_string()).unwrap_or_default(),
        Field::Code => e.code.to_owned(),
        Field::Message => e.message.to_string(),
        Field::User => e.user.map(|u| format!("{u:032x}")).unwrap_or_default(),
        Field::UserAgent => e.user_agent.as_deref().unwrap_or("").to_owned(),
        Field::Referrer => e.referrer.as_deref().unwrap_or("").to_owned(),
        Field::Request => e.request.to_string(),
    }
}

fn log_line(
    logger: &wasp_core::suite::log::Logger,
    rule: &Rule,
    e: &AccessEntry,
    status: u16,
    dropped: u64,
) {
    let texts: Vec<(Field, String)> = rule.fields.iter().map(|f| (*f, text_of(*f, e))).collect();
    let mut fields: Vec<LogField<'_>> = Vec::with_capacity(texts.len() + 2);
    fields.push(LogField::new("rule", Value::Str(&rule.name)));
    for (f, t) in &texts {
        if *f == Field::Status {
            fields.push(LogField::new("status", Value::U64(u64::from(status))));
        } else {
            fields.push(LogField::new(f.name(), Value::Str(t)));
        }
    }
    fields.push(LogField::new("dropped", Value::U64(dropped)));
    let level = if status >= 500 {
        Level::Warn
    } else {
        Level::Info
    };
    logger.log(level, "request", &fields);
}

/// One JSON line: the time, the rule, the fields, and the drop count.
fn json_line(rule: &Rule, e: &AccessEntry, status: u16, dropped: u64) -> String {
    let ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    let mut out = format!("{{\"ts_ms\":{ms},\"rule\":");
    json_str(&mut out, &rule.name);
    for f in &rule.fields {
        out.push(',');
        json_str(&mut out, f.name());
        out.push(':');
        if *f == Field::Status {
            out.push_str(&status.to_string());
        } else {
            json_str(&mut out, &text_of(*f, e));
        }
    }
    out.push_str(&format!(",\"dropped\":{dropped}}}\n"));
    out
}

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Appends `line` to the rule's file, rotating it first when the line would
/// take it past `max_size`. `false` when the line could not be written.
fn write_file(state: &mut State, path: &Path, max_size: u64, keep: u32, line: &str) -> bool {
    let len = line.len() as u64;
    if len > max_size {
        return false;
    }
    if state.file.is_none() {
        match open_owner_only(path) {
            Ok(f) => {
                let size = f.metadata().map_or(0, |m| m.len());
                state.file = Some((f, size));
            }
            Err(_) => return false,
        }
    }
    if state
        .file
        .as_ref()
        .is_some_and(|(_, size)| size + len > max_size)
    {
        state.file = None;
        if rotate(path, keep).is_err() {
            return false;
        }
        match open_owner_only(path) {
            Ok(f) => state.file = Some((f, 0)),
            Err(_) => return false,
        }
    }
    let Some((file, size)) = state.file.as_mut() else {
        return false;
    };
    if file.write_all(line.as_bytes()).is_err() {
        state.file = None;
        return false;
    }
    *size += len;
    true
}

/// `path` for appending, made owner-only when it is created.
fn open_owner_only(path: &Path) -> std::io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// `path` becomes `path.1`, `path.1` becomes `path.2`, up to `keep`; the
/// oldest goes. With `keep` 0 the file is simply removed.
fn rotate(path: &Path, keep: u32) -> std::io::Result<()> {
    let numbered = |n: u32| {
        let mut p = path.as_os_str().to_owned();
        p.push(format!(".{n}"));
        PathBuf::from(p)
    };
    if keep == 0 {
        return std::fs::remove_file(path);
    }
    let _ = std::fs::remove_file(numbered(keep));
    for n in (1..keep).rev() {
        let from = numbered(n);
        if from.exists() {
            std::fs::rename(&from, numbered(n + 1))?;
        }
    }
    std::fs::rename(path, numbered(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> Result<LogRules, String> {
        LogRules::from_config(&Config::from_text(text).expect("toml"))
    }

    #[test]
    fn rules_are_checked() {
        for (text, says) in [
            ("[log_rule.a]\nfields = [\"path\"]\n", "codes is missing"),
            ("[log_rule.a]\ncodes = [\"600\"]\n", "from 100 to 599"),
            ("[log_rule.a]\ncodes = [\"99\"]\n", "from 100 to 599"),
            ("[log_rule.a]\ncodes = [\"6xx\"]\n", "from 100 to 599"),
            (
                "[log_rule.a]\ncodes = [\"404\"]\nfields = [\"cookie\"]\n",
                "no field `cookie`",
            ),
            (
                "[log_rule.a]\ncodes = [\"404\"]\ndestination = \"syslog\"\n",
                "`log`, or `file:`",
            ),
            (
                "[log_rule.a]\ncodes = [\"404\"]\ndestination = \"file:/tmp/x\"\nmax_size = 10\n",
                "max_size",
            ),
            ("[log_rule.a]\ncodes = [\"404\"]\nrats = 5\n", "unknown key"),
        ] {
            let e = rules(text).expect_err(text);
            assert!(e.contains(says), "{text}: {e}");
        }
        let r = rules("[log_rule.broken]\ncodes = [\"404\", \"5xx\"]\nfields = [\"path\", \"query\", \"referrer\"]\n")
            .expect("rules");
        let rule = &r.rules()[0];
        assert!(rule.matches(404) && rule.matches(503) && !rule.matches(403));
        assert!(
            !rule.fields.contains(&Field::Query),
            "no query without include_query"
        );
        assert_eq!(
            r.wants(),
            Wants {
                query: false,
                user_agent: false,
                referrer: true
            }
        );
        let q =
            rules("[log_rule.q]\ncodes = [\"2xx\"]\ninclude_query = true\nfields = [\"path\"]\n")
                .expect("rules");
        assert!(q.wants().query, "the switch brings the query in");
    }

    #[test]
    fn json_lines_escape_and_files_rotate() {
        let mut s = String::new();
        json_str(&mut s, "a\"b\\c\n\u{1}");
        assert_eq!(s, "\"a\\\"b\\\\c\\n\\u0001\"");

        let dir = std::env::temp_dir().join(format!("gateway-rules-rotate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("rule.log");
        let mut state = State::default();
        let line = format!("{}\n", "x".repeat(99));
        for _ in 0..25 {
            assert!(write_file(&mut state, &path, 1000, 2, &line));
        }
        let size = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
        assert!(size(&path) <= 1000);
        assert_eq!(size(&dir.join("rule.log.1")), 1000);
        assert_eq!(size(&dir.join("rule.log.2")), 1000);
        assert!(!dir.join("rule.log.3").exists(), "only `keep` old files");
        assert!(
            !write_file(&mut state, &path, 50, 2, &line),
            "a line over max_size is dropped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
