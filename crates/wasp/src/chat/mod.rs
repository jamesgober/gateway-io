//! The messenger (G-83): one-to-one direct messages and groups (G-84, in
//! [`group`]) over a WebSocket route, JSON frames, kept through a
//! [`ChatStore`].
//!
//! The protocol, one JSON object per text frame, each with an `op`:
//!
//! | The client sends | The server answers |
//! |---|---|
//! | `{"op":"conversations","after":".."}` | `{"op":"conversations","items":[..],"more":".." or null}`, a page, the most recent first (the first page is also sent on connect) |
//! | `{"op":"open","with":"<account>"}` | `{"op":"conversation","id":..,"members":[..]}` |
//! | `{"op":"history","conversation":..,"before":n,"limit":n}` | `{"op":"history","conversation":..,"messages":[..],"more":n or null}` |
//! | `{"op":"send","conversation":..,"body":[spans],"nonce":".."}` | `{"op":"sent","nonce":..,"conversation":..,"number":n}` |
//! | `{"op":"read","conversation":..,"number":n}` | `{"op":"read",..}`, pushed to the other member when the marker moves |
//! | `{"op":"mute","conversation":..,"on":true}` | `{"op":"muted","conversation":..,"on":true}` |
//! | `{"op":"block","account":..,"on":true}` | `{"op":"blocked","account":..,"on":true}` |
//!
//! Every open connection of each member gets `{"op":"message","message":..}`
//! for a new message (not a member who muted the conversation), and
//! `{"op":"read",..}` when the other member reads (never across a block).
//! An error is
//! `{"op":"error","code":..,"message":..}`, with the `nonce` when there was
//! one.

pub mod group;
pub mod store;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use gateway_io::ws::{WebSocketConn, WebSocketService, WsMessage, WsSender};
use serve_net::Envelope;
use wasp_core::PermSet;
use wasp_core::suite::config::Config;

pub use group::{Group, GroupMember, GroupRole, GroupSettings, Invite};
pub use store::{ChatStore, Conversation, MemoryChat, Usage};

use crate::api::{Obj, list};
use crate::json::{self, Value};

/// A conversation's id: 16 bytes, written as 32 hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConvId(pub [u8; 16]);

impl std::fmt::Display for ConvId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for ConvId {
    type Err = ();
    fn from_str(s: &str) -> Result<ConvId, ()> {
        if s.len() != 32 {
            return Err(());
        }
        let n = u128::from_str_radix(s, 16).map_err(|_| ())?;
        Ok(ConvId(n.to_be_bytes()))
    }
}

impl ConvId {
    /// A new random id, for a group; `None` when the system has no
    /// randomness to give.
    #[must_use]
    pub fn random() -> Option<ConvId> {
        let key = crypt_io::generate_key().ok()?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&key[..16]);
        Some(ConvId(id))
    }

    /// The one direct conversation of `a` and `b` in `realm`.
    #[must_use]
    pub fn direct(realm: &str, a: u128, b: u128) -> ConvId {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let digest = crypt_io::hash::blake3(
            format!("wasp chat direct {realm} {lo:032x} {hi:032x}").as_bytes(),
        );
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        ConvId(id)
    }
}

/// A mark on a span of text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Mark {
    name: &'static str,
    bit: u8,
    /// Editors and admins only.
    advanced: bool,
}

const MARKS: &[Mark] = &[
    Mark {
        name: "bold",
        bit: 1,
        advanced: false,
    },
    Mark {
        name: "italic",
        bit: 2,
        advanced: false,
    },
    Mark {
        name: "link",
        bit: 4,
        advanced: false,
    },
    Mark {
        name: "code",
        bit: 8,
        advanced: true,
    },
    Mark {
        name: "pre",
        bit: 16,
        advanced: true,
    },
    Mark {
        name: "quote",
        bit: 32,
        advanced: true,
    },
    Mark {
        name: "strike",
        bit: 64,
        advanced: true,
    },
];

const LINK: u8 = 4;

/// The most spans in one message.
pub const MAX_SPANS: usize = 64;

/// Text with marks: never markup.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Span {
    /// The text, as typed.
    pub text: String,
    /// Its marks, as bits.
    pub marks: u8,
    /// The address, with the `link` mark.
    pub href: Option<String>,
}

/// One message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Its conversation.
    pub conversation: ConvId,
    /// Its number there, from 1.
    pub number: u64,
    /// Who wrote it.
    pub author: u128,
    /// When, in Unix milliseconds.
    pub at_ms: u64,
    /// What it says.
    pub body: Vec<Span>,
}

/// `body` as JSON spans.
#[must_use]
pub fn spans_json(body: &[Span]) -> String {
    list(body.iter().map(|s| {
        let marks: Vec<&str> = MARKS
            .iter()
            .filter(|m| s.marks & m.bit != 0)
            .map(|m| m.name)
            .collect();
        let o = Obj::new().str("text", &s.text).strs("marks", marks);
        match &s.href {
            Some(h) => o.str("href", h).end(),
            None => o.end(),
        }
    }))
}

/// Spans as a store keeps them (written by [`spans_json`], so trusted to
/// be checked already).
#[must_use]
pub fn spans_from_json(text: &str) -> Option<Vec<Span>> {
    let v = json::parse(text).ok()?;
    read_spans(&v, true, usize::MAX).ok()
}

/// The spans in `v`, checked: at most [`MAX_SPANS`], at most `max_len`
/// characters in all, only the marks `advanced` allows, a link with a safe
/// address.
fn read_spans(v: &Value, advanced: bool, max_len: usize) -> Result<Vec<Span>, &'static str> {
    let items = v.as_arr().ok_or("the body must be a list of spans")?;
    if items.is_empty() {
        return Err("a message needs some text");
    }
    if items.len() > MAX_SPANS {
        return Err("too many spans");
    }
    let mut total = 0usize;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let text = item
            .get("text")
            .and_then(Value::as_str)
            .ok_or("a span needs its text")?;
        if text.chars().any(|c| c.is_control() && c != '\n') {
            return Err("text may not hold control characters");
        }
        total += text.chars().count();
        if total > max_len {
            return Err("the message is too long");
        }
        let mut marks = 0u8;
        if let Some(names) = item.get("marks") {
            for name in names.as_arr().ok_or("marks must be a list")? {
                let name = name.as_str().ok_or("a mark is a name")?;
                let mark = MARKS
                    .iter()
                    .find(|m| m.name == name)
                    .ok_or("no such mark")?;
                if mark.advanced && !advanced {
                    return Err("that mark is not yours to use");
                }
                marks |= mark.bit;
            }
        }
        let href = match (marks & LINK != 0, item.get("href").and_then(Value::as_str)) {
            (true, Some(h)) if crate::content::address_ok(h) => Some(h.to_owned()),
            (true, _) => return Err("a link needs an http(s) or site address"),
            (false, Some(_)) => return Err("an address belongs to a link"),
            (false, None) => None,
        };
        out.push(Span {
            text: text.to_owned(),
            marks,
            href,
        });
    }
    if total == 0 {
        return Err("a message needs some text");
    }
    Ok(out)
}

/// What a role may do in the messenger: how many messages a page holds, how
/// far back it may page, and whether it may start groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Messages in one page, at most.
    pub page: usize,
    /// Messages back from the last one; 0 for all.
    pub history: u64,
    /// Whether it may start a group.
    pub groups: bool,
}

impl Limits {
    /// The more generous of two.
    fn most(self, other: Limits) -> Limits {
        let history = if self.history == 0 || other.history == 0 {
            0
        } else {
            self.history.max(other.history)
        };
        Limits {
            page: self.page.max(other.page),
            history,
            groups: self.groups || other.groups,
        }
    }
}

/// The messenger's settings (`[chat]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatSettings {
    /// Whether the site has the messenger (`chat.enabled`, default off).
    pub enabled: bool,
    /// The socket's path (`chat.path`, default `/ws/chat`).
    pub path: String,
    /// The most characters in one message (`chat.max_length`, 4,000).
    pub max_length: usize,
    /// Members' limits (`[chat.role.member]`).
    pub member: Limits,
    /// Editors' limits (`[chat.role.editor]`).
    pub editor: Limits,
    /// Admins' limits (`[chat.role.admin]`).
    pub admin: Limits,
    /// The most conversations one account may start, groups too
    /// (`chat.max_conversations`, 500).
    pub max_conversations: u64,
    /// The most messages one account may keep sent
    /// (`chat.max_messages`, 100,000; 0 for no cap).
    pub max_messages: u64,
    /// Sends a second for one account, across its connections
    /// (`chat.rate`, 5; 0 for no budget).
    pub rate: u32,
    /// The most sends at once after a quiet spell (`chat.burst`, 20).
    pub burst: u32,
    /// Deliveries a second for one account: a message costs one per other
    /// member (`chat.fanout`, 2,000; 0 for no budget). Bursts of twice it.
    pub fanout: u32,
    /// The most members and open invites in a group
    /// (`chat.group.max_members`, 200, at most 1,000).
    pub group_max_members: u64,
    /// How many days an invite lasts (`chat.group.invite_days`, 14).
    pub invite_days: u64,
}

impl Default for ChatSettings {
    fn default() -> ChatSettings {
        ChatSettings {
            enabled: false,
            path: "/ws/chat".to_owned(),
            max_length: 4000,
            max_conversations: 500,
            max_messages: 100_000,
            rate: 5,
            burst: 20,
            fanout: 2000,
            group_max_members: 200,
            invite_days: 14,
            member: Limits {
                page: 50,
                history: 1000,
                groups: true,
            },
            editor: Limits {
                page: 100,
                history: 0,
                groups: true,
            },
            admin: Limits {
                page: 100,
                history: 0,
                groups: true,
            },
        }
    }
}

/// The keys of `[chat]`.
pub const KEYS: &[&str] = &[
    "burst",
    "enabled",
    "fanout",
    "group",
    "max_conversations",
    "max_length",
    "max_messages",
    "path",
    "rate",
    "role",
];

/// The keys of `[chat.group]`.
const GROUP_KEYS: &[&str] = &["invite_days", "max_members"];

/// The keys of `[chat.role.<role>]`.
const ROLE_KEYS: &[&str] = &["groups", "history", "page"];

impl ChatSettings {
    /// Reads `[chat]`; with `nex` false (no nex-db accounts) turning it on is
    /// refused.
    pub fn from_config(config: &Config, nex: bool) -> Result<ChatSettings, String> {
        let d = ChatSettings::default();
        let e = |e: wasp_core::suite::Error| e.to_string();
        let enabled: bool = config.get_or("chat.enabled", d.enabled).map_err(e)?;
        if enabled && !nex {
            return Err(
                "chat.enabled needs nex-db accounts (auth.store = \"nex\"): conversations are kept with them"
                    .to_owned(),
            );
        }
        let path: String = config.get_or("chat.path", d.path.clone()).map_err(e)?;
        let path = crate::api::checked_path(&path, "chat.path")?;
        let ranged = |key: &str, default: u64, lo: u64, hi: u64| -> Result<u64, String> {
            let n: u64 = config.get_or(key, default).map_err(e)?;
            if (lo..=hi).contains(&n) {
                Ok(n)
            } else {
                Err(format!("{key} must be {lo} to {hi}, not {n}"))
            }
        };
        let max_length = ranged("chat.max_length", d.max_length as u64, 1, 100_000)?;
        let max_conversations =
            ranged("chat.max_conversations", d.max_conversations, 1, 1_000_000)?;
        let max_messages = ranged("chat.max_messages", d.max_messages, 0, u64::MAX)?;
        let rate = ranged("chat.rate", u64::from(d.rate), 0, 10_000)?;
        let burst = ranged("chat.burst", (rate * 4).max(1), rate.max(1), 100_000)?;
        let fanout = ranged("chat.fanout", u64::from(d.fanout), 0, 1_000_000)?;
        if let Some(k) = config
            .keys("chat.group")
            .into_iter()
            .find(|k| !GROUP_KEYS.contains(k))
        {
            return Err(format!(
                "unknown key `chat.group.{k}`: the keys are {}",
                GROUP_KEYS.join(", ")
            ));
        }
        let group_max_members = ranged("chat.group.max_members", d.group_max_members, 2, 1000)?;
        let invite_days = ranged("chat.group.invite_days", d.invite_days, 1, 365)?;
        for role in config.keys("chat.role") {
            if !matches!(role, "member" | "editor" | "admin") {
                return Err(format!(
                    "unknown role `chat.role.{role}`: the roles are member, editor, admin"
                ));
            }
            let at = format!("chat.role.{role}");
            if let Some(k) = config
                .keys(&at)
                .into_iter()
                .find(|k| !ROLE_KEYS.contains(k))
            {
                return Err(format!(
                    "unknown key `{at}.{k}`: the keys are {}",
                    ROLE_KEYS.join(", ")
                ));
            }
        }
        let limits = |role: &str, d: Limits| -> Result<Limits, String> {
            let page = ranged(&format!("chat.role.{role}.page"), d.page as u64, 1, 500)?;
            let history: u64 = config
                .get_or(&format!("chat.role.{role}.history"), d.history)
                .map_err(e)?;
            let groups: bool = config
                .get_or(&format!("chat.role.{role}.groups"), d.groups)
                .map_err(e)?;
            Ok(Limits {
                page: page as usize,
                history,
                groups,
            })
        };
        let small = |n: u64| u32::try_from(n).unwrap_or(u32::MAX);
        Ok(ChatSettings {
            enabled,
            path,
            max_length: max_length as usize,
            max_conversations,
            max_messages,
            rate: small(rate),
            burst: small(burst),
            fanout: small(fanout),
            group_max_members,
            invite_days,
            member: limits("member", d.member)?,
            editor: limits("editor", d.editor)?,
            admin: limits("admin", d.admin)?,
        })
    }

    /// The limits of an account with these permissions: the most its roles
    /// allow.
    #[must_use]
    pub fn limits_for(&self, perms: PermSet) -> Limits {
        let mut l = self.member;
        if perms.contains(crate::site_nex::EDITOR) {
            l = l.most(self.editor);
        }
        if perms.contains(crate::site_nex::ADMIN) {
            l = l.most(self.admin);
        }
        l
    }
}

/// Whether an account exists in the realm and may take part.
pub trait Directory: Send + Sync + 'static {
    /// Whether `account` may be written to: it exists, may sign in, and is
    /// a member.
    fn reachable(&self, account: u128) -> bool;
}

impl Directory for crate::nex::NexAuth {
    fn reachable(&self, account: u128) -> bool {
        let user = wasp_core::UserId(account);
        self.may_sign_in(user).unwrap_or(false)
            && self
                .role_names(user)
                .is_ok_and(|r| r.iter().any(|n| n == crate::nex::MEMBER_ROLE))
    }
}

/// Conversations in one page of the list.
pub const LIST_PAGE: usize = 50;

/// How many taken numbers a send steps over before it gives up (another
/// writer, or a send cut short before it moved the conversation's last
/// number).
const NUMBER_TRIES: u64 = 64;

/// Groups whose records are kept in memory at once; past it the cache
/// starts again.
const GROUP_CACHE: usize = 10_000;

/// Accounts whose budgets are kept at once; past it the full ones go.
const BUDGETS: usize = 100_000;

/// One open connection, as pushes reach it.
struct Live {
    id: u64,
    sender: WsSender,
    /// Set when the client stopped reading and pushes to it were dropped:
    /// its next frame closes it, and it catches up when it comes back.
    behind: Arc<AtomicBool>,
}

/// A token bucket: `rate` a second, at most `burst`.
#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: std::time::Instant,
}

impl Bucket {
    fn full(burst: u32) -> Bucket {
        Bucket {
            tokens: f64::from(burst),
            at: std::time::Instant::now(),
        }
    }

    fn refill(&mut self, rate: u32, burst: u32) {
        let now = std::time::Instant::now();
        let gained = now.duration_since(self.at).as_secs_f64() * f64::from(rate);
        self.tokens = (self.tokens + gained).min(f64::from(burst));
        self.at = now;
    }

    /// Milliseconds until `n` tokens are there; 0 when they are now.
    fn wait_for(&self, n: f64, rate: u32) -> u64 {
        if self.tokens >= n || rate == 0 {
            0
        } else {
            ((n - self.tokens) * 1000.0 / f64::from(rate)).ceil() as u64
        }
    }
}

/// One account's two budgets.
#[derive(Debug)]
struct Budget {
    sends: Bucket,
    deliveries: Bucket,
}

/// The messenger for one realm: its store, and every open connection by
/// account.
pub struct Chat {
    store: Arc<dyn ChatStore>,
    directory: Arc<dyn Directory>,
    realm: String,
    settings: ChatSettings,
    live: Mutex<HashMap<u128, Vec<Live>>>,
    next: AtomicU64,
    /// Numbering and group changes, by conversation.
    conversation_locks: Box<[Mutex<()>]>,
    /// Quotas, by account. Taken before a conversation's lock, never after.
    account_locks: Box<[Mutex<()>]>,
    /// Group records read or written in this process.
    groups: Mutex<HashMap<ConvId, Arc<Group>>>,
    budgets: Mutex<HashMap<u128, Budget>>,
}

impl std::fmt::Debug for Chat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chat")
            .field("realm", &self.realm)
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn hex(account: u128) -> String {
    format!("{account:032x}")
}

/// An error answer.
fn error(code: &str, message: &str, nonce: Option<&str>) -> String {
    let o = Obj::new()
        .str("op", "error")
        .str("code", code)
        .str("message", message);
    match nonce {
        Some(n) => o.str("nonce", n).end(),
        None => o.end(),
    }
}

fn message_json(m: &Message) -> String {
    Obj::new()
        .str("conversation", &m.conversation.to_string())
        .num("number", m.number)
        .str("author", &hex(m.author))
        .num("at", m.at_ms)
        .raw("body", &spans_json(&m.body))
        .end()
}

fn stripe(locks: &[Mutex<()>], key: u64) -> &Mutex<()> {
    &locks[usize::try_from(key % locks.len() as u64).unwrap_or(0)]
}

/// What a caller holds in a conversation.
enum Access {
    /// A member of a direct conversation.
    Direct(Conversation),
    /// A member of a group, as the group's record says.
    Group(Conversation, Arc<Group>, GroupMember),
}

impl Access {
    fn conversation(&self) -> &Conversation {
        match self {
            Access::Direct(c) | Access::Group(c, _, _) => c,
        }
    }
}

impl Chat {
    /// The messenger for `realm` over `store`.
    #[must_use]
    pub fn new(
        store: Arc<dyn ChatStore>,
        directory: Arc<dyn Directory>,
        realm: &str,
        settings: ChatSettings,
    ) -> Arc<Chat> {
        Arc::new(Chat {
            store,
            directory,
            realm: realm.to_owned(),
            settings,
            live: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            conversation_locks: (0..64).map(|_| Mutex::new(())).collect(),
            account_locks: (0..64).map(|_| Mutex::new(())).collect(),
            groups: Mutex::new(HashMap::new()),
            budgets: Mutex::new(HashMap::new()),
        })
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &ChatSettings {
        &self.settings
    }

    /// One connection of `account`, which holds `perms`. The gateway ends
    /// the connection when the account's permissions change, so what they
    /// allow is read once, here.
    #[must_use]
    pub fn connection(self: &Arc<Chat>, account: u128, perms: PermSet) -> ChatConn {
        ChatConn {
            chat: Arc::clone(self),
            account,
            advanced: perms.contains(crate::site_nex::EDITOR)
                || perms.contains(crate::site_nex::ADMIN),
            limits: self.settings.limits_for(perms),
            id: self.next.fetch_add(1, Ordering::Relaxed),
            behind: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Sends `text` to every open connection of `account`. A connection
    /// whose client stopped reading is dropped from the pushes, and marked
    /// to close: it catches up when it comes back.
    fn push(&self, account: u128, text: &str) {
        let mut live = lock(&self.live);
        if let Some(conns) = live.get_mut(&account) {
            conns.retain(|c| match c.sender.send_text(text) {
                Ok(()) => true,
                Err(_) => {
                    c.behind.store(true, Ordering::Release);
                    false
                }
            });
            if conns.is_empty() {
                live.remove(&account);
            }
        }
    }

    /// Of `accounts`, the ones with a connection open now.
    fn online(&self, accounts: impl IntoIterator<Item = u128>) -> Vec<u128> {
        let live = lock(&self.live);
        accounts
            .into_iter()
            .filter(|a| live.contains_key(a))
            .collect()
    }

    /// Takes one send and `deliveries` deliveries from `account`'s budgets,
    /// or tells how many milliseconds until it could.
    fn charge(&self, account: u128, deliveries: u64) -> Result<(), u64> {
        let s = &self.settings;
        let (fanout_burst, n) = (s.fanout.saturating_mul(2), deliveries as f64);
        let mut budgets = lock(&self.budgets);
        if budgets.len() >= BUDGETS && !budgets.contains_key(&account) {
            budgets.retain(|_, b| {
                b.sends.refill(s.rate, s.burst);
                b.deliveries.refill(s.fanout, fanout_burst);
                b.sends.tokens < f64::from(s.burst) || b.deliveries.tokens < f64::from(fanout_burst)
            });
        }
        let b = budgets.entry(account).or_insert_with(|| Budget {
            sends: Bucket::full(s.burst),
            deliveries: Bucket::full(fanout_burst),
        });
        b.sends.refill(s.rate, s.burst);
        b.deliveries.refill(s.fanout, fanout_burst);
        let wait_send = if s.rate == 0 {
            0
        } else {
            b.sends.wait_for(1.0, s.rate)
        };
        let wait_fanout = if s.fanout == 0 {
            0
        } else {
            b.deliveries.wait_for(n, s.fanout)
        };
        let wait = wait_send.max(wait_fanout);
        if wait > 0 {
            return Err(wait);
        }
        if s.rate > 0 {
            b.sends.tokens -= 1.0;
        }
        if s.fanout > 0 {
            b.deliveries.tokens -= n;
        }
        Ok(())
    }

    /// The record of group `id`, when there is one.
    fn group(&self, id: &ConvId) -> Result<Option<Arc<Group>>, String> {
        if let Some(g) = lock(&self.groups).get(id) {
            return Ok(Some(Arc::clone(g)));
        }
        let Some(g) = self.store.group(id).map_err(|_| unavailable())? else {
            return Ok(None);
        };
        let g = Arc::new(g);
        let mut cache = lock(&self.groups);
        if cache.len() >= GROUP_CACHE {
            cache.clear();
        }
        cache.insert(*id, Arc::clone(&g));
        Ok(Some(g))
    }

    /// Keeps group `id`'s record.
    fn keep_group(&self, id: &ConvId, g: Group) -> Result<Arc<Group>, String> {
        self.store.put_group(id, &g).map_err(|_| unavailable())?;
        let g = Arc::new(g);
        lock(&self.groups).insert(*id, Arc::clone(&g));
        Ok(g)
    }

    /// The lock that orders writes to conversation `id`.
    fn conversation_lock(&self, id: &ConvId) -> std::sync::MutexGuard<'_, ()> {
        let key = u64::from_le_bytes(id.0[..8].try_into().unwrap_or([0; 8]));
        lock(stripe(&self.conversation_locks, key))
    }

    /// What `me` holds in conversation `id`: nothing is `chat.not_a_member`.
    fn access(&self, id: &ConvId, me: u128) -> Result<Access, String> {
        let not = || {
            error(
                "chat.not_a_member",
                "There is no such conversation of yours.",
                None,
            )
        };
        let c = match self.store.conversation(id) {
            Ok(Some(c)) => c,
            Ok(None) => return Err(not()),
            Err(_) => return Err(unavailable()),
        };
        if !c.group {
            return if c.members.contains(&me) {
                Ok(Access::Direct(c))
            } else {
                Err(not())
            };
        }
        let Some(g) = self.group(id)? else {
            return Err(not());
        };
        match g.member(me) {
            Some(m) => {
                let m = m.clone();
                Ok(Access::Group(c, g, m))
            }
            None => Err(not()),
        }
    }

    /// Whether a block stands between `a` and `b`, either way.
    fn blocked_between(&self, a: u128, b: u128) -> Result<bool, String> {
        let one = self.store.blocked(a, b).map_err(|_| unavailable())?;
        let two = self.store.blocked(b, a).map_err(|_| unavailable())?;
        Ok(one || two)
    }

    /// Whether `me` may write to `other` now: `other` is reachable and no
    /// block stands between them. Which of the two failed is never told.
    fn may_write(&self, me: u128, other: u128) -> Result<bool, String> {
        Ok(self.directory.reachable(other) && !self.blocked_between(me, other)?)
    }

    /// Counts a conversation `me` starts against its quota: `chat.quota`
    /// past it. Call under `me`'s account lock.
    fn start_one(&self, me: u128) -> Result<store::Usage, String> {
        let usage = self.store.usage(me).map_err(|_| unavailable())?;
        if usage.started >= self.settings.max_conversations {
            return Err(error(
                "chat.quota",
                "You have started as many conversations as you may.",
                None,
            ));
        }
        Ok(usage)
    }
}

fn unavailable() -> String {
    error(
        "chat.unavailable",
        "Messages cannot be read or kept now. Try again shortly.",
        None,
    )
}

/// The one answer when an account cannot be written to, for any reason.
fn cannot_write() -> String {
    error(
        "chat.cannot_write",
        "You cannot write to that account.",
        None,
    )
}

/// One open connection's side of the messenger.
pub struct ChatConn {
    chat: Arc<Chat>,
    account: u128,
    advanced: bool,
    limits: Limits,
    id: u64,
    behind: Arc<AtomicBool>,
}

impl std::fmt::Debug for ChatConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatConn")
            .field("account", &hex(self.account))
            .field("advanced", &self.advanced)
            .finish_non_exhaustive()
    }
}

fn conv_of(v: &Value) -> Option<ConvId> {
    v.get("conversation")?.as_str()?.parse().ok()
}

fn account_of(v: &Value, key: &str) -> Option<u128> {
    let s = v.get(key)?.as_str()?;
    if s.len() != 32 {
        return None;
    }
    u128::from_str_radix(s, 16).ok()
}

fn number_of(v: &Value, key: &str) -> Option<u64> {
    v.get(key)?.as_int().and_then(|n| u64::try_from(n).ok())
}

fn bad_conversation() -> String {
    error("chat.bad_conversation", "`conversation` is an id.", None)
}

impl ChatConn {
    /// What one frame from the client asks: the answers for this
    /// connection (pushes to others go out on the way).
    pub fn handle(&self, frame: &str) -> String {
        let v = match json::parse(frame) {
            Ok(v) => v,
            Err(_) => return error("chat.bad_frame", "A frame is one JSON object.", None),
        };
        let nonce = v.get("nonce").and_then(Value::as_str).map(str::to_owned);
        let answer = match v.get("op").and_then(Value::as_str) {
            Some("conversations") => self.conversations(&v),
            Some("open") => self.open(&v),
            Some("history") => self.history(&v),
            Some("send") => self.send(&v, nonce.as_deref()),
            Some("read") => self.read(&v),
            Some("mute") => self.mute(&v),
            Some("block") => self.block(&v),
            Some(op) => self.group_op(op, &v),
            None => Err(error("chat.bad_op", "There is no such op.", None)),
        };
        match answer {
            Ok(a) => a,
            // An error answer gets the request's nonce, when it had one.
            Err(e) => match (&nonce, json::parse(&e)) {
                (Some(n), Ok(Value::Obj(members))) => {
                    let o = members.iter().fold(Obj::new(), |o, (k, v)| match v {
                        Value::Str(s) => o.str(k, s),
                        Value::Int(i) => o.num(k, u64::try_from(*i).unwrap_or(0)),
                        _ => o,
                    });
                    o.str("nonce", n).end()
                }
                _ => e,
            },
        }
    }

    /// One page of the caller's conversations, the most recent first.
    fn conversations(&self, v: &Value) -> Result<String, String> {
        let chat = &self.chat;
        let after = v.get("after").and_then(Value::as_str);
        let (ids, more) = chat
            .store
            .conversations_of(self.account, after, LIST_PAGE)
            .map_err(|e| match e.kind() {
                crate::content::StoreErrorKind::Invalid => error(
                    "chat.bad_after",
                    "`after` is the `more` of the page before.",
                    None,
                ),
                _ => unavailable(),
            })?;
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            let Ok(access) = chat.access(&id, self.account) else {
                continue;
            };
            let c = access.conversation();
            let read = chat
                .store
                .read_marker(&id, self.account)
                .map_err(|_| unavailable())?;
            let muted = chat
                .store
                .muted(&id, self.account)
                .map_err(|_| unavailable())?;
            // What this member can see starts after it joined, in a group
            // that keeps the earlier messages from new members.
            let seen = match &access {
                Access::Group(_, g, m) if !g.settings.before_join => read.max(m.joined),
                _ => read,
            };
            let o = Obj::new().str("id", &id.to_string());
            let o = match &access {
                Access::Direct(c) => {
                    let members: Vec<String> = c.members.iter().map(|m| hex(*m)).collect();
                    o.str("kind", "direct")
                        .strs("members", members.iter().map(String::as_str))
                }
                Access::Group(_, g, _) => o
                    .str("kind", "group")
                    .str("name", &g.name)
                    .num("count", g.members.len() as u64),
            };
            items.push(
                o.num("last", c.last)
                    .num("at", c.at_ms)
                    .num("read", seen.min(c.last))
                    .num("unread", c.last.saturating_sub(seen))
                    .raw("muted", if muted { "true" } else { "false" })
                    .end(),
            );
        }
        let o = Obj::new()
            .str("op", "conversations")
            .str("me", &hex(self.account));
        let o = match after {
            Some(a) => o.str("after", a),
            None => o.null("after"),
        };
        let o = o.raw("items", &list(items));
        Ok(match more {
            Some(m) => o.str("more", &m).end(),
            None => o.null("more").end(),
        })
    }

    fn open(&self, v: &Value) -> Result<String, String> {
        let Some(other) = account_of(v, "with") else {
            return Err(error(
                "chat.bad_account",
                "`with` is an account id (32 hex digits).",
                None,
            ));
        };
        if other == self.account {
            return Err(error(
                "chat.self",
                "A conversation needs someone else.",
                None,
            ));
        }
        let chat = &self.chat;
        if !chat.may_write(self.account, other)? {
            return Err(cannot_write());
        }
        let id = ConvId::direct(&chat.realm, self.account, other);
        let (lo, hi) = if self.account < other {
            (self.account, other)
        } else {
            (other, self.account)
        };
        {
            let _quota = lock(stripe(&chat.account_locks, self.account as u64));
            if chat
                .store
                .conversation(&id)
                .map_err(|_| unavailable())?
                .is_none()
            {
                let mut usage = chat.start_one(self.account)?;
                let c = Conversation {
                    id,
                    group: false,
                    members: vec![lo, hi],
                    last: 0,
                    at_ms: 0,
                };
                if chat.store.create(&c).map_err(|_| unavailable())? {
                    usage.started += 1;
                    chat.store
                        .set_usage(self.account, usage)
                        .map_err(|_| unavailable())?;
                }
            }
        }
        // In the opener's list now; in the other's with the first message.
        chat.store
            .index(self.account, &id)
            .map_err(|_| unavailable())?;
        Ok(Obj::new()
            .str("op", "conversation")
            .str("id", &id.to_string())
            .strs("members", [hex(lo), hex(hi)].iter().map(String::as_str))
            .end())
    }

    fn history(&self, v: &Value) -> Result<String, String> {
        let Some(id) = conv_of(v) else {
            return Err(bad_conversation());
        };
        let chat = &self.chat;
        let access = chat.access(&id, self.account)?;
        let last = access.conversation().last;
        // How far back this caller may scroll: its role's depth, the
        // group's, and in a group that keeps them from new members, nothing
        // from before it joined.
        let depth = |h: u64| match h {
            0 => 1,
            h => last.saturating_sub(h).saturating_add(1).max(1),
        };
        let mut floor = depth(self.limits.history);
        if let Access::Group(_, g, m) = &access {
            floor = floor.max(depth(g.settings.history));
            if !g.settings.before_join {
                floor = floor.max(m.joined + 1);
            }
        }
        let before = number_of(v, "before").unwrap_or(last + 1).min(last + 1);
        let limit = number_of(v, "limit")
            .map_or(self.limits.page, |n| {
                usize::try_from(n).unwrap_or(usize::MAX)
            })
            .clamp(1, self.limits.page) as u64;
        let from = before.saturating_sub(limit).max(floor);
        let mut messages = Vec::new();
        let mut hidden: HashMap<u128, bool> = HashMap::new();
        for n in from..before {
            let Some(m) = chat.store.message(&id, n).map_err(|_| unavailable())? else {
                continue;
            };
            // In a group, an author this reader blocked is not shown.
            if matches!(access, Access::Group(..)) && m.author != self.account {
                let skip = match hidden.get(&m.author) {
                    Some(s) => *s,
                    None => {
                        let s = chat
                            .store
                            .blocked(self.account, m.author)
                            .map_err(|_| unavailable())?;
                        hidden.insert(m.author, s);
                        s
                    }
                };
                if skip {
                    continue;
                }
            }
            messages.push(message_json(&m));
        }
        let o = Obj::new()
            .str("op", "history")
            .str("conversation", &id.to_string())
            .raw("messages", &list(messages));
        Ok(if from > floor {
            o.num("more", from).end()
        } else {
            o.null("more").end()
        })
    }

    fn send(&self, v: &Value, nonce: Option<&str>) -> Result<String, String> {
        let Some(id) = conv_of(v) else {
            return Err(bad_conversation());
        };
        let chat = &self.chat;
        let access = chat.access(&id, self.account)?;
        let (recipients, advanced): (Vec<u128>, bool) = match &access {
            Access::Direct(c) => {
                let others: Vec<u128> = c
                    .members
                    .iter()
                    .copied()
                    .filter(|m| *m != self.account)
                    .collect();
                for other in &others {
                    if !chat.may_write(self.account, *other)? {
                        return Err(cannot_write());
                    }
                }
                (others, self.advanced)
            }
            Access::Group(_, g, _) => (
                g.members
                    .iter()
                    .map(|m| m.account)
                    .filter(|a| *a != self.account)
                    .collect(),
                self.advanced && g.settings.advanced,
            ),
        };
        let body = v
            .get("body")
            .ok_or_else(|| error("chat.bad_body", "`body` is a list of spans.", None))?;
        let body = read_spans(body, advanced, chat.settings.max_length)
            .map_err(|why| error("chat.bad_body", why, None))?;
        if let Err(ms) = chat.charge(self.account, recipients.len() as u64) {
            return Err(Obj::new()
                .str("op", "error")
                .str("code", "chat.slow_down")
                .str(
                    "message",
                    "You are sending faster than you may. Wait a moment.",
                )
                .num("retry_ms", ms)
                .end());
        }
        let message = {
            let _quota = lock(stripe(&chat.account_locks, self.account as u64));
            let mut usage = chat.store.usage(self.account).map_err(|_| unavailable())?;
            if chat.settings.max_messages > 0 && usage.messages >= chat.settings.max_messages {
                return Err(error(
                    "chat.quota",
                    "You have sent as many messages as you may keep.",
                    None,
                ));
            }
            let message = {
                let _numbering = chat.conversation_lock(&id);
                let last = chat
                    .store
                    .conversation(&id)
                    .map_err(|_| unavailable())?
                    .map_or(access.conversation().last, |c| c.last);
                let mut m = Message {
                    conversation: id,
                    number: last + 1,
                    author: self.account,
                    at_ms: now_ms(),
                    body,
                };
                // Write once: a number already taken (another process, or a
                // send cut short before it moved `last`) is stepped over.
                let mut kept = false;
                for _ in 0..NUMBER_TRIES {
                    if chat.store.append(&m).map_err(|_| unavailable())? {
                        kept = true;
                        break;
                    }
                    m.number += 1;
                }
                if !kept {
                    return Err(unavailable());
                }
                chat.store
                    .set_last(&id, m.number, m.at_ms)
                    .map_err(|_| unavailable())?;
                m
            };
            usage.messages += 1;
            let _ = chat.store.set_usage(self.account, usage);
            message
        };
        // A direct conversation goes to the front of both lists (into the
        // other's with its first message); a group, of the writer's.
        let _ = chat.store.index(self.account, &id);
        if let Access::Direct(_) = access {
            for other in &recipients {
                let _ = chat.store.index(*other, &id);
            }
        }
        let _ = chat.store.set_read(&id, self.account, message.number);
        let push = Obj::new()
            .str("op", "message")
            .raw("message", &message_json(&message))
            .end();
        // The writer's own connections, then each member online who did not
        // mute it (nor, in a group, block the writer).
        chat.push(self.account, &push);
        let group = matches!(access, Access::Group(..));
        for member in chat.online(recipients) {
            if chat.store.muted(&id, member).unwrap_or(false)
                || (group && chat.store.blocked(member, self.account).unwrap_or(false))
            {
                continue;
            }
            chat.push(member, &push);
        }
        let o = Obj::new()
            .str("op", "sent")
            .str("conversation", &id.to_string())
            .num("number", message.number);
        Ok(match nonce {
            Some(n) => o.str("nonce", n).end(),
            None => o.end(),
        })
    }

    fn read(&self, v: &Value) -> Result<String, String> {
        let (Some(id), Some(number)) = (conv_of(v), number_of(v, "number")) else {
            return Err(error(
                "chat.bad_read",
                "`read` needs a conversation and a number.",
                None,
            ));
        };
        let chat = &self.chat;
        let access = chat.access(&id, self.account)?;
        let c = access.conversation();
        let was = chat
            .store
            .read_marker(&id, self.account)
            .map_err(|_| unavailable())?;
        let now = number.min(c.last).max(was);
        let answer = Obj::new()
            .str("op", "read")
            .str("conversation", &id.to_string())
            .str("member", &hex(self.account))
            .num("number", now)
            .end();
        // Nothing moved: nothing is written, and no one is told.
        if now == was {
            return Ok(answer);
        }
        chat.store
            .set_read(&id, self.account, now)
            .map_err(|_| unavailable())?;
        // The other member hears it; never across a block, nor one who muted
        // the conversation. A group sends no read receipts.
        if let Access::Direct(c) = &access {
            for other in c.members.iter().filter(|m| **m != self.account) {
                if chat.blocked_between(self.account, *other)?
                    || chat.store.muted(&id, *other).unwrap_or(false)
                {
                    continue;
                }
                chat.push(*other, &answer);
            }
        }
        Ok(answer)
    }

    fn mute(&self, v: &Value) -> Result<String, String> {
        let (Some(id), Some(on)) = (conv_of(v), v.get("on").and_then(Value::as_bool)) else {
            return Err(error(
                "chat.bad_mute",
                "`mute` needs a conversation and `on`.",
                None,
            ));
        };
        let chat = &self.chat;
        chat.access(&id, self.account)?;
        chat.store
            .set_muted(&id, self.account, on)
            .map_err(|_| unavailable())?;
        Ok(Obj::new()
            .str("op", "muted")
            .str("conversation", &id.to_string())
            .raw("on", if on { "true" } else { "false" })
            .end())
    }

    fn block(&self, v: &Value) -> Result<String, String> {
        let (Some(whom), Some(on)) = (
            account_of(v, "account"),
            v.get("on").and_then(Value::as_bool),
        ) else {
            return Err(error(
                "chat.bad_block",
                "`block` needs an account and `on`.",
                None,
            ));
        };
        if whom == self.account {
            return Err(error("chat.self", "You cannot block yourself.", None));
        }
        self.chat
            .store
            .set_blocked(self.account, whom, on)
            .map_err(|_| unavailable())?;
        Ok(Obj::new()
            .str("op", "blocked")
            .str("account", &hex(whom))
            .raw("on", if on { "true" } else { "false" })
            .end())
    }
}

impl WebSocketService for ChatConn {
    fn opened(&self, _env: &Envelope, conn: &mut WebSocketConn<'_>) {
        lock(&self.chat.live)
            .entry(self.account)
            .or_default()
            .push(Live {
                id: self.id,
                sender: conn.sender(),
                behind: Arc::clone(&self.behind),
            });
        // Catching up: the first page of conversations, with what is unread.
        let summary = self
            .conversations(&Value::Obj(Vec::new()))
            .unwrap_or_else(|e| e);
        let _ = conn.send_text(&summary);
    }

    fn message(&self, _env: &Envelope, message: WsMessage<'_>, conn: &mut WebSocketConn<'_>) {
        if self.behind.load(Ordering::Acquire) {
            // Pushes were lost while the client was not reading.
            let _ = conn.close(1013, "missed messages: connect again to catch up");
            return;
        }
        let answer = match message {
            WsMessage::Text(t) => self.handle(t),
            _ => error("chat.bad_frame", "Frames are JSON text.", None),
        };
        let _ = conn.send_text(&answer);
    }

    fn closed(&self, _env: &Envelope, _code: Option<u16>) {
        let mut live = lock(&self.chat.live);
        if let Some(conns) = live.get_mut(&self.account) {
            conns.retain(|c| c.id != self.id);
            if conns.is_empty() {
                live.remove(&self.account);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Everyone;
    impl Directory for Everyone {
        fn reachable(&self, account: u128) -> bool {
            account != 404
        }
    }

    fn chat(settings: ChatSettings) -> Arc<Chat> {
        Chat::new(
            Arc::new(MemoryChat::new()),
            Arc::new(Everyone),
            "users",
            settings,
        )
    }

    fn field(json: &str, key: &str) -> Option<Value> {
        crate::json::parse(json).ok()?.get(key).cloned()
    }

    #[test]
    fn spans_are_text_with_marks_and_editors_get_more() {
        let v = |t: &str| crate::json::parse(t).expect("json");
        let ok = read_spans(
            &v(r#"[{"text":"hi "},{"text":"there","marks":["bold","link"],"href":"https://example.com/a"}]"#),
            false,
            100,
        )
        .expect("a member's spans");
        assert_eq!(ok.len(), 2);
        assert_eq!(spans_from_json(&spans_json(&ok)), Some(ok));
        for (bad, why) in [
            (r#"[]"#, "needs some text"),
            (r#"[{"text":""}]"#, "needs some text"),
            (r#"[{"text":"x","marks":["code"]}]"#, "not yours"),
            (r#"[{"text":"x","marks":["blink"]}]"#, "no such mark"),
            (
                r#"[{"text":"x","marks":["link"],"href":"javascript:alert(1)"}]"#,
                "address",
            ),
            (
                r#"[{"text":"x","href":"https://a.example"}]"#,
                "belongs to a link",
            ),
            (r#"[{"text":"<b>x</b>\u0007"}]"#, "control"),
            (r#"[{"text":"0123456789x"}]"#, "too long"),
            (
                r#"[{"text":"x","marks":["link"],"href":"/\\evil.example"}]"#,
                "address",
            ),
        ] {
            let e = read_spans(&v(bad), false, 10).expect_err(bad);
            assert!(e.contains(why), "{bad}: {e}");
        }
        assert!(read_spans(&v(r#"[{"text":"x","marks":["code","pre"]}]"#), true, 10).is_ok());
        // Markup is only text: it is kept as typed, and written escaped.
        let s = read_spans(&v(r#"[{"text":"<script>"}]"#), false, 100).expect("text");
        assert!(spans_json(&s).contains("\\u003cscript>"));
    }

    #[test]
    fn members_talk_page_back_and_read() {
        let chat = chat(ChatSettings {
            member: Limits {
                page: 2,
                history: 3,
                groups: true,
            },
            ..ChatSettings::default()
        });
        let ann = chat.connection(1, crate::site_nex::MEMBER);
        let bob = chat.connection(2, crate::site_nex::MEMBER);
        let eve = chat.connection(3, crate::site_nex::MEMBER);
        let opened = ann.handle(r#"{"op":"open","with":"00000000000000000000000000000002"}"#);
        let id = field(&opened, "id")
            .and_then(|v| v.as_str().map(str::to_owned))
            .expect("id");
        // Bob opening it gets the same conversation.
        let again = bob.handle(r#"{"op":"open","with":"00000000000000000000000000000001"}"#);
        assert_eq!(
            field(&again, "id").and_then(|v| v.as_str().map(str::to_owned)),
            Some(id.clone())
        );
        for n in 1..=5 {
            let sent = ann.handle(&format!(
                r#"{{"op":"send","conversation":"{id}","nonce":"n{n}","body":[{{"text":"m{n}"}}]}}"#
            ));
            assert_eq!(
                field(&sent, "number").and_then(|v| v.as_int()),
                Some(n),
                "{sent}"
            );
            assert_eq!(
                field(&sent, "nonce").and_then(|v| v.as_str().map(str::to_owned)),
                Some(format!("n{n}"))
            );
        }
        // Pages of 2, newest first, at most 3 back.
        let page = bob.handle(&format!(r#"{{"op":"history","conversation":"{id}"}}"#));
        assert!(
            page.contains("\"m4\"") && page.contains("\"m5\"") && !page.contains("\"m3\""),
            "{page}"
        );
        assert_eq!(field(&page, "more").and_then(|v| v.as_int()), Some(4));
        let older = bob.handle(&format!(
            r#"{{"op":"history","conversation":"{id}","before":4}}"#
        ));
        assert!(
            older.contains("\"m3\"") && !older.contains("\"m2\""),
            "{older}"
        );
        assert_eq!(
            field(&older, "more"),
            Some(Value::Null),
            "the history ends there"
        );
        // Unread, then read.
        let list = bob.handle(r#"{"op":"conversations"}"#);
        assert!(list.contains("\"unread\":5"), "{list}");
        bob.handle(&format!(
            r#"{{"op":"read","conversation":"{id}","number":5}}"#
        ));
        assert!(
            bob.handle(r#"{"op":"conversations"}"#)
                .contains("\"unread\":0")
        );
        // Someone else's conversation is no one's business but theirs.
        for op in ["history", "send", "read", "mute"] {
            let e = eve.handle(&format!(
                r#"{{"op":"{op}","conversation":"{id}","number":1,"on":true,"body":[{{"text":"x"}}]}}"#
            ));
            assert!(e.contains("chat.not_a_member"), "{op}: {e}");
        }
        assert!(
            ann.handle(r#"{"op":"open","with":"00000000000000000000000000000001"}"#)
                .contains("chat.self")
        );
        assert!(
            ann.handle(&format!(r#"{{"op":"open","with":"{:032x}"}}"#, 404))
                .contains("chat.cannot_write")
        );
        assert!(ann.handle("not json").contains("chat.bad_frame"));
        assert!(ann.handle(r#"{"op":"dance"}"#).contains("chat.bad_op"));
    }

    #[test]
    fn a_block_stops_both_ways() {
        let chat = chat(ChatSettings::default());
        let ann = chat.connection(1, crate::site_nex::MEMBER);
        let bob = chat.connection(2, crate::site_nex::MEMBER);
        let opened = ann.handle(r#"{"op":"open","with":"00000000000000000000000000000002"}"#);
        let id = field(&opened, "id")
            .and_then(|v| v.as_str().map(str::to_owned))
            .expect("id");
        bob.handle(r#"{"op":"block","account":"00000000000000000000000000000001","on":true}"#);
        let send = |c: &ChatConn| {
            c.handle(&format!(
                r#"{{"op":"send","conversation":"{id}","body":[{{"text":"hi"}}]}}"#
            ))
        };
        // The same answer as for an account that is not there: a block is
        // never told.
        assert!(send(&ann).contains("chat.cannot_write"));
        assert!(send(&bob).contains("chat.cannot_write"));
        assert!(
            ann.handle(r#"{"op":"open","with":"00000000000000000000000000000002"}"#)
                .contains("chat.cannot_write")
        );
        bob.handle(r#"{"op":"block","account":"00000000000000000000000000000001","on":false}"#);
        assert!(send(&ann).contains("\"op\":\"sent\""));
    }

    #[test]
    fn settings_have_safe_defaults_and_role_limits() {
        let c = |t: &str| Config::from_text(t).expect("toml");
        let d = ChatSettings::from_config(&c(""), true).expect("defaults");
        assert!(!d.enabled);
        assert_eq!(
            d.limits_for(crate::site_nex::MEMBER),
            Limits {
                page: 50,
                history: 1000,
                groups: true,
            }
        );
        assert_eq!(
            d.limits_for(PermSet(
                crate::site_nex::MEMBER.0 | crate::site_nex::EDITOR.0
            )),
            Limits {
                page: 100,
                history: 0,
                groups: true,
            }
        );
        assert!(ChatSettings::from_config(&c("[chat]\nenabled = true\n"), false).is_err());
        assert!(ChatSettings::from_config(&c("[chat.role.guest]\npage = 1\n"), true).is_err());
        assert!(ChatSettings::from_config(&c("[chat.role.member]\npage = 0\n"), true).is_err());
        assert!(ChatSettings::from_config(&c("[chat]\npath = \"/admin/chat\"\n"), true).is_err());
    }

    fn id_of(answer: &str) -> String {
        field(answer, "id")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| panic!("no id: {answer}"))
    }

    fn items(answer: &str) -> usize {
        field(answer, "items")
            .and_then(|v| v.as_arr().map(<[Value]>::len))
            .unwrap_or_else(|| panic!("no items: {answer}"))
    }

    #[test]
    fn the_list_is_paged_and_shows_a_conversation_once_it_has_a_message() {
        let chat = chat(ChatSettings::default());
        let ann = chat.connection(1, crate::site_nex::MEMBER);
        let mut first = String::new();
        for other in 100..160u128 {
            let id = id_of(&ann.handle(&format!(r#"{{"op":"open","with":"{other:032x}"}}"#)));
            if other == 100 {
                first = id;
            }
        }
        let page = ann.handle(r#"{"op":"conversations"}"#);
        assert_eq!(items(&page), LIST_PAGE);
        let more = field(&page, "more")
            .and_then(|v| v.as_str().map(str::to_owned))
            .expect("more");
        let rest = ann.handle(&format!(r#"{{"op":"conversations","after":"{more}"}}"#));
        assert_eq!(items(&rest), 10);
        assert_eq!(field(&rest, "more"), Some(Value::Null));
        assert!(
            ann.handle(r#"{"op":"conversations","after":"nonsense"}"#)
                .contains("chat.bad_after")
        );
        // Opening one plants nothing in the other's list; the first message
        // puts it there.
        let other = chat.connection(100, crate::site_nex::MEMBER);
        assert_eq!(items(&other.handle(r#"{"op":"conversations"}"#)), 0);
        ann.handle(&format!(
            r#"{{"op":"send","conversation":"{first}","body":[{{"text":"hi"}}]}}"#
        ));
        let list = other.handle(r#"{"op":"conversations"}"#);
        assert_eq!(items(&list), 1);
        assert!(list.contains(&first), "{list}");
        // And it moves to the front of the sender's.
        assert!(
            ann.handle(r#"{"op":"conversations"}"#)
                .find(&first)
                .is_some_and(|at| at < 200),
            "the newest first"
        );
    }

    #[test]
    fn an_account_has_quotas() {
        let chat = chat(ChatSettings {
            max_conversations: 2,
            max_messages: 2,
            ..ChatSettings::default()
        });
        let ann = chat.connection(1, crate::site_nex::MEMBER);
        let open = |n: u128| ann.handle(&format!(r#"{{"op":"open","with":"{n:032x}"}}"#));
        let id = id_of(&open(2));
        id_of(&open(3));
        assert!(open(4).contains("chat.quota"));
        // Opening one it has is not starting one.
        assert_eq!(id_of(&open(2)), id);
        // Nor is one someone else started.
        let five = chat.connection(5, crate::site_nex::MEMBER);
        id_of(&five.handle(r#"{"op":"open","with":"00000000000000000000000000000001"}"#));
        id_of(&open(5));
        let send = || {
            ann.handle(&format!(
                r#"{{"op":"send","conversation":"{id}","body":[{{"text":"hi"}}]}}"#
            ))
        };
        assert!(send().contains("\"sent\""));
        assert!(send().contains("\"sent\""));
        assert!(send().contains("chat.quota"));
    }

    #[test]
    fn a_number_is_never_written_twice() {
        let store = Arc::new(MemoryChat::new());
        let chat = Chat::new(
            store.clone(),
            Arc::new(Everyone),
            "users",
            ChatSettings::default(),
        );
        let ann = chat.connection(1, crate::site_nex::MEMBER);
        let id = id_of(&ann.handle(r#"{"op":"open","with":"00000000000000000000000000000002"}"#));
        let conv: ConvId = id.parse().expect("id");
        // Message 1 kept, but the send stopped before it moved `last` (a
        // crash, or another process).
        let kept = Message {
            conversation: conv,
            number: 1,
            author: 2,
            at_ms: 1,
            body: vec![Span {
                text: "first".to_owned(),
                marks: 0,
                href: None,
            }],
        };
        assert!(store.append(&kept).expect("append"));
        assert!(!store.append(&kept).expect("append"), "taken");
        let sent = ann.handle(&format!(
            r#"{{"op":"send","conversation":"{id}","body":[{{"text":"second"}}]}}"#
        ));
        assert_eq!(
            field(&sent, "number").and_then(|v| v.as_int()),
            Some(2),
            "{sent}"
        );
        assert_eq!(store.message(&conv, 1).expect("read"), Some(kept));
        assert_eq!(
            store.conversation(&conv).expect("read").map(|c| c.last),
            Some(2)
        );
    }

    #[test]
    fn a_read_that_moves_nothing_writes_nothing() {
        let chat = chat(ChatSettings::default());
        let ann = chat.connection(1, crate::site_nex::MEMBER);
        let bob = chat.connection(2, crate::site_nex::MEMBER);
        let id = id_of(&ann.handle(r#"{"op":"open","with":"00000000000000000000000000000002"}"#));
        ann.handle(&format!(
            r#"{{"op":"send","conversation":"{id}","body":[{{"text":"hi"}}]}}"#
        ));
        let read = |n: u64| {
            bob.handle(&format!(
                r#"{{"op":"read","conversation":"{id}","number":{n}}}"#
            ))
        };
        assert_eq!(field(&read(1), "number").and_then(|v| v.as_int()), Some(1));
        // Past the last message, or back: the marker stays.
        assert_eq!(field(&read(9), "number").and_then(|v| v.as_int()), Some(1));
        assert_eq!(field(&read(0), "number").and_then(|v| v.as_int()), Some(1));
    }

    fn code(answer: &str) -> String {
        field(answer, "code")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    }

    fn op(answer: &str) -> String {
        field(answer, "op")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    }

    fn texts(answer: &str) -> Vec<String> {
        field(answer, "messages")
            .and_then(|v| v.as_arr().map(<[Value]>::to_vec))
            .unwrap_or_default()
            .iter()
            .filter_map(|m| {
                m.get("body")?
                    .as_arr()?
                    .first()?
                    .get("text")?
                    .as_str()
                    .map(str::to_owned)
            })
            .collect()
    }

    struct Group3 {
        chat: Arc<Chat>,
        id: String,
        ann: ChatConn,
        bob: ChatConn,
        cara: ChatConn,
    }

    /// Ann's group "Team", with Bob and Cara in it.
    fn team(settings: ChatSettings) -> Group3 {
        let chat = chat(settings);
        let ann = chat.connection(1, crate::site_nex::MEMBER);
        let bob = chat.connection(2, crate::site_nex::MEMBER);
        let cara = chat.connection(3, crate::site_nex::MEMBER);
        let made = ann.handle(r#"{"op":"create","name":"  Team  "}"#);
        assert_eq!(op(&made), "group", "{made}");
        let id = id_of(&made);
        for (n, who) in [(2u128, &bob), (3, &cara)] {
            let inv = ann.handle(&format!(
                r#"{{"op":"invite","conversation":"{id}","account":"{n:032x}"}}"#
            ));
            assert_eq!(op(&inv), "invite", "{inv}");
            assert!(who.handle(r#"{"op":"invites"}"#).contains(&id));
            assert_eq!(
                op(&who.handle(&format!(r#"{{"op":"join","conversation":"{id}"}}"#))),
                "group"
            );
        }
        Group3 {
            chat,
            id,
            ann,
            bob,
            cara,
        }
    }

    #[test]
    fn a_group_is_joined_by_invite_and_run_by_its_owner() {
        let Group3 {
            chat,
            id,
            ann,
            bob,
            cara,
        } = team(ChatSettings::default());
        let dan = chat.connection(4, crate::site_nex::MEMBER);
        let ask = |c: &ChatConn, f: String| c.handle(&f);
        let g = ask(&ann, format!(r#"{{"op":"group","conversation":"{id}"}}"#));
        assert!(
            g.contains("\"name\":\"Team\"") && g.contains("\"count\":3"),
            "{g}"
        );
        // No invite, no way in; a member may not invite unless the group
        // allows it.
        assert_eq!(
            code(&ask(
                &dan,
                format!(r#"{{"op":"join","conversation":"{id}"}}"#)
            )),
            "chat.not_invited"
        );
        let invite_dan = |c: &ChatConn| {
            c.handle(&format!(
                r#"{{"op":"invite","conversation":"{id}","account":"{:032x}"}}"#,
                4
            ))
        };
        assert_eq!(code(&invite_dan(&bob)), "chat.not_allowed");
        assert_eq!(
            code(&ask(
                &dan,
                format!(r#"{{"op":"history","conversation":"{id}"}}"#)
            )),
            "chat.not_a_member"
        );
        // The owner makes Bob a moderator: he invites, and kicks members.
        assert_eq!(
            code(&ask(
                &bob,
                format!(
                    r#"{{"op":"role","conversation":"{id}","account":"{:032x}","role":"moderator"}}"#,
                    3
                )
            )),
            "chat.not_allowed"
        );
        assert_eq!(
            op(&ask(
                &ann,
                format!(
                    r#"{{"op":"role","conversation":"{id}","account":"{:032x}","role":"moderator"}}"#,
                    2
                )
            )),
            "role"
        );
        assert_eq!(op(&invite_dan(&bob)), "invite");
        assert_eq!(
            op(&ask(
                &dan,
                format!(r#"{{"op":"join","conversation":"{id}"}}"#)
            )),
            "group"
        );
        assert_eq!(
            code(&ask(
                &dan,
                format!(
                    r#"{{"op":"kick","conversation":"{id}","account":"{:032x}"}}"#,
                    2
                )
            )),
            "chat.not_allowed"
        );
        assert_eq!(
            code(&ask(
                &bob,
                format!(
                    r#"{{"op":"kick","conversation":"{id}","account":"{:032x}"}}"#,
                    1
                )
            )),
            "chat.not_allowed",
            "not the owner"
        );
        assert_eq!(
            op(&ask(
                &bob,
                format!(
                    r#"{{"op":"kick","conversation":"{id}","account":"{:032x}","ban":true}}"#,
                    4
                )
            )),
            "kicked"
        );
        assert_eq!(
            code(&ask(
                &dan,
                format!(r#"{{"op":"history","conversation":"{id}"}}"#)
            )),
            "chat.not_a_member"
        );
        // Banned: the same answer as for anyone who cannot be written to.
        assert_eq!(code(&invite_dan(&bob)), "chat.cannot_write");
        assert_eq!(
            op(&ask(
                &ann,
                format!(
                    r#"{{"op":"unban","conversation":"{id}","account":"{:032x}"}}"#,
                    4
                )
            )),
            "unbanned"
        );
        assert_eq!(op(&invite_dan(&bob)), "invite");
        assert_eq!(
            op(&ask(
                &dan,
                format!(r#"{{"op":"decline","conversation":"{id}"}}"#)
            )),
            "declined"
        );
        assert_eq!(
            code(&ask(
                &dan,
                format!(r#"{{"op":"join","conversation":"{id}"}}"#)
            )),
            "chat.not_invited"
        );
        // Settings are the owner's; the cap holds.
        assert_eq!(
            code(&ask(
                &bob,
                format!(r#"{{"op":"settings","conversation":"{id}","cap":10}}"#)
            )),
            "chat.not_allowed"
        );
        assert_eq!(
            code(&ask(
                &ann,
                format!(r#"{{"op":"settings","conversation":"{id}","cap":2}}"#)
            )),
            "chat.bad_settings"
        );
        assert_eq!(
            op(&ask(
                &ann,
                format!(r#"{{"op":"settings","conversation":"{id}","cap":3,"name":"Crew"}}"#)
            )),
            "group"
        );
        assert_eq!(code(&invite_dan(&ann)), "chat.full");
        // Members page, roles shown.
        let members = ask(
            &cara,
            format!(r#"{{"op":"members","conversation":"{id}"}}"#),
        );
        assert!(
            members.contains("\"role\":\"owner\"") && members.contains("\"role\":\"moderator\""),
            "{members}"
        );
        // Hand on, then leave: the group goes on without its first owner.
        assert_eq!(
            op(&ask(
                &ann,
                format!(
                    r#"{{"op":"transfer","conversation":"{id}","account":"{:032x}"}}"#,
                    3
                )
            )),
            "group"
        );
        assert_eq!(
            code(&ask(
                &ann,
                format!(r#"{{"op":"settings","conversation":"{id}","cap":5}}"#)
            )),
            "chat.not_allowed"
        );
        assert_eq!(
            op(&ask(
                &cara,
                format!(r#"{{"op":"leave","conversation":"{id}"}}"#)
            )),
            "left"
        );
        // Cara was owner: the longest-standing moderator takes it (Ann,
        // made one by the transfer, before Bob).
        let g = ask(&bob, format!(r#"{{"op":"group","conversation":"{id}"}}"#));
        assert!(
            g.contains(&format!("\"owner\":\"{:032x}\"", 1))
                || g.contains(&format!("\"owner\":\"{:032x}\"", 2)),
            "{g}"
        );
        // The last ones out: the group is gone.
        ask(&ann, format!(r#"{{"op":"leave","conversation":"{id}"}}"#));
        ask(&bob, format!(r#"{{"op":"leave","conversation":"{id}"}}"#));
        let conv: ConvId = id.parse().expect("id");
        assert_eq!(chat.store.conversation(&conv).expect("read"), None);
        assert_eq!(chat.store.group(&conv).expect("read"), None);
    }

    #[test]
    fn a_group_holds_its_marks_history_and_blocks() {
        let Group3 {
            chat,
            id,
            ann,
            bob,
            cara,
        } = team(ChatSettings::default());
        let send = |c: &ChatConn, body: &str| {
            c.handle(&format!(
                r#"{{"op":"send","conversation":"{id}","body":{body}}}"#
            ))
        };
        for t in ["one", "two", "three"] {
            assert_eq!(op(&send(&ann, &format!(r#"[{{"text":"{t}"}}]"#))), "sent");
        }
        // An editor joins: a basic group still refuses code from them.
        let ed = chat.connection(
            5,
            PermSet(crate::site_nex::MEMBER.0 | crate::site_nex::EDITOR.0),
        );
        ann.handle(&format!(
            r#"{{"op":"invite","conversation":"{id}","account":"{:032x}"}}"#,
            5
        ));
        ed.handle(&format!(r#"{{"op":"join","conversation":"{id}"}}"#));
        let code_span = r#"[{"text":"x","marks":["code"]}]"#;
        assert_eq!(code(&send(&ed, code_span)), "chat.bad_body");
        ann.handle(&format!(
            r#"{{"op":"settings","conversation":"{id}","marks":"advanced"}}"#
        ));
        assert_eq!(op(&send(&ed, code_span)), "sent");
        assert_eq!(
            code(&send(&bob, code_span)),
            "chat.bad_body",
            "a member's role still decides"
        );
        // A new member starts at its join: nothing from before.
        let history =
            |c: &ChatConn| c.handle(&format!(r#"{{"op":"history","conversation":"{id}"}}"#));
        assert_eq!(texts(&history(&ed)), ["x"]);
        assert_eq!(texts(&history(&bob)), ["one", "two", "three", "x"]);
        ann.handle(&format!(
            r#"{{"op":"settings","conversation":"{id}","before_join":true,"history":2}}"#
        ));
        assert_eq!(texts(&history(&ed)), ["three", "x"]);
        // A block hides the blocked author from the blocker, and stops
        // no one writing.
        bob.handle(&format!(
            r#"{{"op":"block","account":"{:032x}","on":true}}"#,
            1
        ));
        assert_eq!(op(&send(&ann, r#"[{"text":"four"}]"#)), "sent");
        let bob_sees = texts(&bob.handle(&format!(
            r#"{{"op":"history","conversation":"{id}","limit":10}}"#
        )));
        assert!(!bob_sees.iter().any(|t| t == "four"), "{bob_sees:?}");
        assert!(texts(&history(&cara)).contains(&"four".to_owned()));
        // Listed as a group, with its name.
        let list = cara.handle(r#"{"op":"conversations"}"#);
        assert!(
            list.contains("\"kind\":\"group\"") && list.contains("\"name\":\"Team\""),
            "{list}"
        );
        // Group ops on a direct conversation are refused.
        let direct = id_of(&ann.handle(&format!(r#"{{"op":"open","with":"{:032x}"}}"#, 3)));
        assert_eq!(
            code(&ann.handle(&format!(r#"{{"op":"members","conversation":"{direct}"}}"#))),
            "chat.not_a_group"
        );
    }

    #[test]
    fn sends_are_charged_per_delivery() {
        let Group3 { id, ann, .. } = team(ChatSettings {
            fanout: 2,
            ..ChatSettings::default()
        });
        // Two others: each message costs two of four (the burst is twice
        // the rate).
        let send = |nonce: &str| {
            ann.handle(&format!(
                r#"{{"op":"send","conversation":"{id}","nonce":"{nonce}","body":[{{"text":"hi"}}]}}"#
            ))
        };
        assert_eq!(op(&send("a")), "sent");
        assert_eq!(op(&send("b")), "sent");
        let slow = send("c");
        assert_eq!(code(&slow), "chat.slow_down", "{slow}");
        assert!(
            field(&slow, "retry_ms")
                .and_then(|v| v.as_int())
                .is_some_and(|ms| ms > 0),
            "{slow}"
        );
        assert_eq!(
            field(&slow, "nonce").and_then(|v| v.as_str().map(str::to_owned)),
            Some("c".to_owned())
        );
        // Nothing was kept for it.
        assert_eq!(
            texts(&ann.handle(&format!(r#"{{"op":"history","conversation":"{id}"}}"#))).len(),
            2
        );
    }

    #[test]
    fn who_may_start_a_group() {
        let chat = chat(ChatSettings {
            member: Limits {
                groups: false,
                ..ChatSettings::default().member
            },
            ..ChatSettings::default()
        });
        let ann = chat.connection(1, crate::site_nex::MEMBER);
        assert_eq!(
            code(&ann.handle(r#"{"op":"create","name":"x"}"#)),
            "chat.not_allowed"
        );
        let ed = chat.connection(
            2,
            PermSet(crate::site_nex::MEMBER.0 | crate::site_nex::EDITOR.0),
        );
        assert_eq!(op(&ed.handle(r#"{"op":"create","name":"x"}"#)), "group");
        for bad in [
            r#""""#,
            r#""   ""#,
            "\"a\\u0007\"",
            &format!("\"{}\"", "x".repeat(101)),
        ] {
            assert_eq!(
                code(&ed.handle(&format!(r#"{{"op":"create","name":{bad}}}"#))),
                "chat.bad_name",
                "{bad}"
            );
        }
    }
}
