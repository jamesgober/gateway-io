//! The messenger (G-83): one-to-one direct messages over a WebSocket route,
//! JSON frames, kept through a [`ChatStore`].
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

pub mod store;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use gateway_io::ws::{WebSocketConn, WebSocketService, WsMessage, WsSender};
use serve_net::Envelope;
use wasp_core::PermSet;
use wasp_core::suite::config::Config;

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

/// How far back a role may page, and how many messages a page holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Messages in one page, at most.
    pub page: usize,
    /// Messages back from the last one; 0 for all.
    pub history: u64,
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
    /// The most conversations one account may start
    /// (`chat.max_conversations`, 500).
    pub max_conversations: u64,
    /// The most messages one account may keep sent
    /// (`chat.max_messages`, 100,000; 0 for no cap).
    pub max_messages: u64,
}

impl Default for ChatSettings {
    fn default() -> ChatSettings {
        ChatSettings {
            enabled: false,
            path: "/ws/chat".to_owned(),
            max_length: 4000,
            max_conversations: 500,
            max_messages: 100_000,
            member: Limits {
                page: 50,
                history: 1000,
            },
            editor: Limits {
                page: 100,
                history: 0,
            },
            admin: Limits {
                page: 100,
                history: 0,
            },
        }
    }
}

/// The keys of `[chat]`.
pub const KEYS: &[&str] = &[
    "enabled",
    "max_conversations",
    "max_length",
    "max_messages",
    "path",
    "role",
];

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
        let max: u64 = config
            .get_or("chat.max_length", d.max_length as u64)
            .map_err(e)?;
        let max_length = usize::try_from(max)
            .ok()
            .filter(|n| (1..=100_000).contains(n))
            .ok_or_else(|| format!("chat.max_length must be 1 to 100000 characters, not {max}"))?;
        let max_conversations: u64 = config
            .get_or("chat.max_conversations", d.max_conversations)
            .map_err(e)?;
        if !(1..=1_000_000).contains(&max_conversations) {
            return Err(format!(
                "chat.max_conversations must be 1 to 1000000, not {max_conversations}"
            ));
        }
        let max_messages: u64 = config
            .get_or("chat.max_messages", d.max_messages)
            .map_err(e)?;
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
                .find(|k| !matches!(*k, "page" | "history"))
            {
                return Err(format!(
                    "unknown key `{at}.{k}`: the keys are page, history"
                ));
            }
        }
        let limits = |role: &str, d: Limits| -> Result<Limits, String> {
            let page: u64 = config
                .get_or(&format!("chat.role.{role}.page"), d.page as u64)
                .map_err(e)?;
            let history: u64 = config
                .get_or(&format!("chat.role.{role}.history"), d.history)
                .map_err(e)?;
            if !(1..=500).contains(&page) {
                return Err(format!(
                    "chat.role.{role}.page must be 1 to 500, not {page}"
                ));
            }
            Ok(Limits {
                page: page as usize,
                history,
            })
        };
        Ok(ChatSettings {
            enabled,
            path,
            max_length,
            max_conversations,
            max_messages,
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

/// One open connection, as pushes reach it.
struct Live {
    id: u64,
    sender: WsSender,
    /// Set when the client stopped reading and pushes to it were dropped:
    /// its next frame closes it, and it catches up when it comes back.
    behind: Arc<AtomicBool>,
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
    /// Numbering, by conversation.
    conversation_locks: Box<[Mutex<()>]>,
    /// Quotas, by account. Taken before a conversation's lock, never after.
    account_locks: Box<[Mutex<()>]>,
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

    /// The conversation `id` when `me` is a member of it.
    fn member_of(&self, id: &ConvId, me: u128) -> Result<Conversation, String> {
        match self.store.conversation(id) {
            Ok(Some(c)) if c.members.contains(&me) => Ok(c),
            Ok(_) => Err(error(
                "chat.not_a_member",
                "There is no such conversation of yours.",
                None,
            )),
            Err(_) => Err(unavailable()),
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
            _ => Err(error("chat.bad_op", "There is no such op.", None)),
        };
        match answer {
            Ok(a) => a,
            // An error answer gets the request's nonce, when it had one.
            Err(e) => match (&nonce, json::parse(&e)) {
                (Some(n), Ok(Value::Obj(members))) => {
                    let get = |k: &str| {
                        members
                            .iter()
                            .find(|(key, _)| key == k)
                            .and_then(|(_, v)| v.as_str())
                            .unwrap_or("")
                            .to_owned()
                    };
                    error(&get("code"), &get("message"), Some(n))
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
            let Ok(Some(c)) = chat.store.conversation(&id) else {
                continue;
            };
            if !c.members.contains(&self.account) {
                continue;
            }
            let read = chat
                .store
                .read_marker(&id, self.account)
                .map_err(|_| unavailable())?;
            let muted = chat
                .store
                .muted(&id, self.account)
                .map_err(|_| unavailable())?;
            let members: Vec<String> = c.members.iter().map(|m| hex(*m)).collect();
            items.push(
                Obj::new()
                    .str("id", &id.to_string())
                    .strs("members", members.iter().map(String::as_str))
                    .num("last", c.last)
                    .num("at", c.at_ms)
                    .num("read", read.min(c.last))
                    .num("unread", c.last.saturating_sub(read))
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
                let mut usage = chat.store.usage(self.account).map_err(|_| unavailable())?;
                if usage.started >= chat.settings.max_conversations {
                    return Err(error(
                        "chat.quota",
                        "You have started as many conversations as you may.",
                        None,
                    ));
                }
                let c = Conversation {
                    id,
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
            return Err(error(
                "chat.bad_conversation",
                "`conversation` is an id.",
                None,
            ));
        };
        let chat = &self.chat;
        let last = chat.member_of(&id, self.account)?.last;
        // How far back this caller may scroll.
        let floor = match self.limits.history {
            0 => 1,
            h => last.saturating_sub(h).saturating_add(1).max(1),
        };
        let before = number_of(v, "before").unwrap_or(last + 1).min(last + 1);
        let limit = number_of(v, "limit")
            .map_or(self.limits.page, |n| {
                usize::try_from(n).unwrap_or(usize::MAX)
            })
            .clamp(1, self.limits.page) as u64;
        let from = before.saturating_sub(limit).max(floor);
        let mut messages = Vec::new();
        for n in from..before {
            if let Some(m) = chat.store.message(&id, n).map_err(|_| unavailable())? {
                messages.push(message_json(&m));
            }
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
            return Err(error(
                "chat.bad_conversation",
                "`conversation` is an id.",
                None,
            ));
        };
        let chat = &self.chat;
        let c = chat.member_of(&id, self.account)?;
        for other in c.members.iter().filter(|m| **m != self.account) {
            if !chat.may_write(self.account, *other)? {
                return Err(cannot_write());
            }
        }
        let body = v
            .get("body")
            .ok_or_else(|| error("chat.bad_body", "`body` is a list of spans.", None))?;
        let body = read_spans(body, self.advanced, chat.settings.max_length)
            .map_err(|why| error("chat.bad_body", why, None))?;
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
                let key = u64::from_le_bytes(id.0[..8].try_into().unwrap_or([0; 8]));
                let _numbering = lock(stripe(&chat.conversation_locks, key));
                let last = chat
                    .store
                    .conversation(&id)
                    .map_err(|_| unavailable())?
                    .map_or(c.last, |c| c.last);
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
        // Both members' lists put it first; the other's gets it now when this
        // is the first message.
        for member in &c.members {
            let _ = chat.store.index(*member, &id);
        }
        let _ = chat.store.set_read(&id, self.account, message.number);
        let push = Obj::new()
            .str("op", "message")
            .raw("message", &message_json(&message))
            .end();
        for member in &c.members {
            if *member != self.account && chat.store.muted(&id, *member).unwrap_or(false) {
                continue;
            }
            chat.push(*member, &push);
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
        let c = chat.member_of(&id, self.account)?;
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
        // The other members hear it; never across a block, nor one who muted
        // the conversation.
        for other in c.members.iter().filter(|m| **m != self.account) {
            if chat.blocked_between(self.account, *other)?
                || chat.store.muted(&id, *other).unwrap_or(false)
            {
                continue;
            }
            chat.push(*other, &answer);
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
        chat.member_of(&id, self.account)?;
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
                history: 1000
            }
        );
        assert_eq!(
            d.limits_for(PermSet(
                crate::site_nex::MEMBER.0 | crate::site_nex::EDITOR.0
            )),
            Limits {
                page: 100,
                history: 0
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
}
