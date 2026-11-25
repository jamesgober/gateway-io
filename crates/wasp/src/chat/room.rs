//! Chat rooms (G-85): places people walk into. A room is about who is in it
//! now: a connection enters and exits, everyone there hears it, and a
//! message reaches the connections in the room at that moment. Public rooms
//! are listed in a directory; unlisted ones are entered by id; private ones
//! only by the accounts on their list.

use std::collections::HashMap;
use std::sync::Arc;

use crate::api::{Obj, list};
use crate::json::Value;
use wasp_core::suite::config::Config;

use super::{
    Access, ChatConn, ConvId, ConvKind, Conversation, Message, RoomRight, cannot_write, error, hex,
    lock, now_ms, number_of, read_spans, spans_json, stripe, unavailable,
};

/// The longest room name, in characters.
pub const NAME_MAX: usize = 60;
/// The longest topic, in characters.
pub const TOPIC_MAX: usize = 200;
/// The most words a room's own filter holds.
pub const ROOM_WORDS: usize = 100;
/// The most bans, and the most mutes, one room holds at once.
pub const MAX_HOLDS: usize = 1000;
/// Rooms in one page of the directory.
const DIRECTORY_PAGE: usize = 50;
/// People in one page of `who`.
const WHO_PAGE: usize = 200;
/// How long a kick keeps someone out by default, in minutes.
const KICK_MINUTES: u64 = 5;

const MINUTE_MS: u64 = 60_000;

/// Who may find and enter a room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoomAccess {
    /// Listed; anyone whose site role reaches the room's.
    Public,
    /// The same, but never listed: entered by id.
    Unlisted,
    /// The owner, the moderators and the accounts on the room's list.
    Private,
}

impl RoomAccess {
    fn as_str(self) -> &'static str {
        match self {
            RoomAccess::Public => "public",
            RoomAccess::Unlisted => "unlisted",
            RoomAccess::Private => "private",
        }
    }

    fn from_name(s: &str) -> Option<RoomAccess> {
        match s {
            "public" => Some(RoomAccess::Public),
            "unlisted" => Some(RoomAccess::Unlisted),
            "private" => Some(RoomAccess::Private),
            _ => None,
        }
    }
}

/// The site roles as ranks: a room is open from one up.
fn rank_name(rank: u8) -> &'static str {
    match rank {
        0 => "member",
        1 => "editor",
        _ => "admin",
    }
}

fn rank_of(name: &str) -> Option<u8> {
    match name {
        "member" => Some(0),
        "editor" => Some(1),
        "admin" => Some(2),
        _ => None,
    }
}

/// A mute or a ban: whom, and until when (0: until lifted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hold {
    /// The account.
    pub account: u128,
    /// When it ends, ms since 1970; 0 for never.
    pub until_ms: u64,
}

impl Hold {
    fn on(&self, now: u64) -> bool {
        self.until_ms == 0 || self.until_ms > now
    }
}

/// A room's record: its rules, its moderators, and who it holds out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Room {
    /// Its name, plain text.
    pub name: String,
    /// What it is about, plain text.
    pub topic: String,
    /// One of the site's categories.
    pub category: String,
    /// Who may find and enter it.
    pub access: RoomAccess,
    /// The site role it is open from (0 member, 1 editor, 2 admin).
    pub rank: u8,
    /// Its owner.
    pub owner: u128,
    /// Its moderators.
    pub moderators: Vec<u128>,
    /// Who may enter a private room.
    pub list: Vec<u128>,
    /// Whether it keeps its messages.
    pub persistent: bool,
    /// How many messages back people may page; 0 for all it keeps.
    pub scroll: u64,
    /// How many messages it keeps.
    pub keep: u64,
    /// Whether authors may use the advanced marks.
    pub advanced: bool,
    /// Seconds between one person's messages; 0 for none.
    pub slow_secs: u64,
    /// Its own filter, lower case.
    pub words: Vec<String>,
    /// Who may not enter, and until when.
    pub bans: Vec<Hold>,
    /// Who may not send, and until when.
    pub mutes: Vec<Hold>,
}

impl Room {
    /// Whether `account`, of site `rank`, may enter at `now`.
    #[must_use]
    pub fn may_enter(&self, account: u128, rank: u8, now: u64) -> bool {
        if account == self.owner || self.moderators.contains(&account) {
            return true;
        }
        if self.bans.iter().any(|b| b.account == account && b.on(now)) {
            return false;
        }
        match self.access {
            RoomAccess::Private => self.list.contains(&account),
            RoomAccess::Public | RoomAccess::Unlisted => rank >= self.rank,
        }
    }

    fn muted(&self, account: u128, now: u64) -> Option<u64> {
        self.mutes
            .iter()
            .find(|m| m.account == account && m.on(now))
            .map(|m| m.until_ms)
    }

    fn drop_lapsed(&mut self, now: u64) {
        self.bans.retain(|b| b.on(now));
        self.mutes.retain(|m| m.on(now));
    }

    /// The record as the stores keep it.
    #[must_use]
    pub fn to_json(&self) -> String {
        let ids = |v: &[u128]| list(v.iter().map(|a| format!("\"{}\"", hex(*a))));
        let holds = |v: &[Hold]| {
            list(
                v.iter()
                    .map(|h| format!("[\"{}\",{}]", hex(h.account), h.until_ms)),
            )
        };
        Obj::new()
            .str("name", &self.name)
            .str("topic", &self.topic)
            .str("category", &self.category)
            .str("access", self.access.as_str())
            .str("role", rank_name(self.rank))
            .str("owner", &hex(self.owner))
            .raw("moderators", &ids(&self.moderators))
            .raw("list", &ids(&self.list))
            .raw("persistent", if self.persistent { "true" } else { "false" })
            .num("scroll", self.scroll)
            .num("keep", self.keep)
            .str("marks", if self.advanced { "advanced" } else { "basic" })
            .num("slow", self.slow_secs)
            .strs("words", self.words.iter().map(String::as_str))
            .raw("bans", &holds(&self.bans))
            .raw("mutes", &holds(&self.mutes))
            .end()
    }

    /// A record from what [`Room::to_json`] wrote.
    #[must_use]
    pub fn from_json(text: &str) -> Option<Room> {
        let v = crate::json::parse(text).ok()?;
        let id = |v: &Value| -> Option<u128> {
            let s = v.as_str()?;
            (s.len() == 32).then_some(())?;
            u128::from_str_radix(s, 16).ok()
        };
        let num = |v: &Value| v.as_int().and_then(|n| u64::try_from(n).ok());
        let ids =
            |key: &str| -> Option<Vec<u128>> { v.get(key)?.as_arr()?.iter().map(id).collect() };
        let holds = |key: &str| -> Option<Vec<Hold>> {
            v.get(key)?
                .as_arr()?
                .iter()
                .map(|h| {
                    let h = h.as_arr()?;
                    Some(Hold {
                        account: id(h.first()?)?,
                        until_ms: num(h.get(1)?)?,
                    })
                })
                .collect()
        };
        let text = |key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
        Some(Room {
            name: text("name")?,
            topic: text("topic")?,
            category: text("category")?,
            access: RoomAccess::from_name(v.get("access")?.as_str()?)?,
            rank: rank_of(v.get("role")?.as_str()?)?,
            owner: id(v.get("owner")?)?,
            moderators: ids("moderators")?,
            list: ids("list")?,
            persistent: v.get("persistent")?.as_bool()?,
            scroll: num(v.get("scroll")?)?,
            keep: num(v.get("keep")?)?,
            advanced: v.get("marks")?.as_str()? == "advanced",
            slow_secs: num(v.get("slow")?)?,
            words: v
                .get("words")?
                .as_arr()?
                .iter()
                .map(|w| w.as_str().map(str::to_owned))
                .collect::<Option<_>>()?,
            bans: holds("bans")?,
            mutes: holds("mutes")?,
        })
    }
}

/// A word for a filter: one word, 1 to 64 characters, no spaces, lower
/// case.
fn filter_word(w: &str) -> Option<String> {
    let w = w.trim();
    (!w.is_empty() && w.chars().count() <= 64 && w.chars().all(char::is_alphanumeric))
        .then(|| w.to_lowercase())
}

impl super::RoomSettings {
    /// Reads `[chat.rooms]`.
    pub(super) fn from_config(config: &Config) -> Result<super::RoomSettings, String> {
        let d = super::RoomSettings::default();
        let e = |e: wasp_core::suite::Error| e.to_string();
        if let Some(k) = config
            .keys("chat.rooms")
            .into_iter()
            .find(|k| !super::ROOM_KEYS.contains(k))
        {
            return Err(format!(
                "unknown key `chat.rooms.{k}`: the keys are {}",
                super::ROOM_KEYS.join(", ")
            ));
        }
        let categories: Vec<String> = config
            .get_or("chat.rooms.categories", d.categories.clone())
            .map_err(e)?;
        if categories.is_empty()
            || categories.len() > 100
            || categories.iter().any(|c| {
                c.is_empty()
                    || c.len() > 32
                    || !c
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(
                "chat.rooms.categories is 1 to 100 names of lower case letters, digits and `-`"
                    .to_owned(),
            );
        }
        let words: Vec<String> = config.get_or("chat.rooms.filter", Vec::new()).map_err(e)?;
        if words.len() > 10_000 {
            return Err("chat.rooms.filter holds at most 10000 words".to_owned());
        }
        let filter = words
            .iter()
            .map(|w| {
                filter_word(w).ok_or_else(|| format!("chat.rooms.filter: `{w}` is not one word"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let ranged = |key: &str, default: u64, lo: u64, hi: u64| -> Result<u64, String> {
            let n: u64 = config.get_or(key, default).map_err(e)?;
            if (lo..=hi).contains(&n) {
                Ok(n)
            } else {
                Err(format!("{key} must be {lo} to {hi}, not {n}"))
            }
        };
        Ok(super::RoomSettings {
            categories,
            filter,
            max: ranged("chat.rooms.max", d.max, 1, 1_000_000)?,
            max_present: ranged("chat.rooms.max_present", d.max_present, 2, 10_000)?,
            max_keep: ranged("chat.rooms.max_keep", d.max_keep, 1, 10_000_000)?,
            fanout: u32::try_from(ranged(
                "chat.rooms.fanout",
                u64::from(d.fanout),
                0,
                100_000_000,
            )?)
            .unwrap_or(u32::MAX),
        })
    }
}

/// Every room's record, once read.
pub(super) type RoomCache = Option<HashMap<ConvId, Arc<Room>>>;

/// Who is in each room now: for each account, its connections there.
pub(super) type Presence = HashMap<ConvId, HashMap<u128, Vec<u64>>>;

/// The room's record as people see it; a moderator sees its words too.
fn room_json(id: &ConvId, r: &Room, people: usize, moderator: bool) -> String {
    let moderators: Vec<String> = r.moderators.iter().map(|m| hex(*m)).collect();
    let o = Obj::new()
        .str("op", "room")
        .str("id", &id.to_string())
        .str("name", &r.name)
        .str("topic", &r.topic)
        .str("category", &r.category)
        .str("access", r.access.as_str())
        .str("role", rank_name(r.rank))
        .str("owner", &hex(r.owner))
        .strs("moderators", moderators.iter().map(String::as_str))
        .raw("persistent", if r.persistent { "true" } else { "false" })
        .num("scroll", r.scroll)
        .num("keep", r.keep)
        .str("marks", if r.advanced { "advanced" } else { "basic" })
        .num("slow", r.slow_secs)
        .num("people", people as u64);
    if moderator {
        o.strs("words", r.words.iter().map(String::as_str)).end()
    } else {
        o.end()
    }
}

fn plain(v: &Value, key: &str, max: usize, empty_ok: bool) -> Result<Option<String>, String> {
    let Some(raw) = v.get(key) else {
        return Ok(None);
    };
    let bad = || {
        error(
            "chat.bad_room",
            &format!("`{key}` is plain text of at most {max} characters."),
            None,
        )
    };
    let s = raw.as_str().ok_or_else(bad)?.trim();
    if (!empty_ok && s.is_empty()) || s.chars().count() > max || s.chars().any(char::is_control) {
        return Err(bad());
    }
    Ok(Some(s.to_owned()))
}

fn room_of(v: &Value) -> Option<ConvId> {
    v.get("room")
        .or_else(|| v.get("conversation"))?
        .as_str()?
        .parse()
        .ok()
}

fn bad_room() -> String {
    error("chat.bad_room", "`room` is a room id.", None)
}

fn not_here() -> String {
    error("chat.no_room", "There is no such room you may enter.", None)
}

fn not_allowed() -> String {
    error(
        "chat.not_allowed",
        "Your place in the room does not allow that.",
        None,
    )
}

/// Whether `text` holds one of `words` as a whole word, ignoring case.
fn filtered(text: &str, site: &[String], room: &[String]) -> bool {
    if site.is_empty() && room.is_empty() {
        return false;
    }
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .any(|w| site.contains(&w) || room.contains(&w))
}

impl super::Chat {
    /// Every room record, read from the store at first use.
    fn room_cache(&self) -> Result<std::sync::MutexGuard<'_, RoomCache>, String> {
        let mut cache = lock(&self.rooms);
        if cache.is_none() {
            let all = self.store.rooms().map_err(|_| unavailable())?;
            *cache = Some(all.into_iter().map(|(id, r)| (id, Arc::new(r))).collect());
        }
        Ok(cache)
    }

    /// The record of room `id`, when there is one.
    pub(super) fn room(&self, id: &ConvId) -> Result<Option<Arc<Room>>, String> {
        Ok(self.room_cache()?.as_ref().and_then(|c| c.get(id).cloned()))
    }

    fn keep_room(&self, id: &ConvId, r: Room) -> Result<Arc<Room>, String> {
        self.store.put_room(id, &r).map_err(|_| unavailable())?;
        let r = Arc::new(r);
        if let Some(c) = self.room_cache()?.as_mut() {
            c.insert(*id, Arc::clone(&r));
        }
        Ok(r)
    }

    /// How many people are in room `id` now.
    fn people(&self, id: &ConvId) -> usize {
        lock(&self.presence).get(id).map_or(0, HashMap::len)
    }

    /// Takes `n` deliveries from the realm's room budget: `false` when it is
    /// spent.
    fn realm_take(&self, n: u64) -> bool {
        let rate = self.settings.rooms.fanout;
        if rate == 0 {
            return true;
        }
        let burst = rate.saturating_mul(2);
        let mut b = lock(&self.realm_fanout);
        b.refill(rate, burst);
        if b.tokens >= n as f64 {
            b.tokens -= n as f64;
            true
        } else {
            false
        }
    }

    /// Sends `text` to the connections in room `id`, but `except`'s; with
    /// `budget`, only while the realm's budget lasts. The number reached.
    fn push_room(&self, id: &ConvId, text: &str, except: Option<u128>, budget: bool) -> usize {
        let targets: Vec<(u128, Vec<u64>)> = lock(&self.presence)
            .get(id)
            .map(|p| {
                p.iter()
                    .filter(|(a, _)| Some(**a) != except)
                    .map(|(a, c)| (*a, c.clone()))
                    .collect()
            })
            .unwrap_or_default();
        if budget && !self.realm_take(targets.len() as u64) {
            return 0;
        }
        for (account, conns) in &targets {
            self.push_to(*account, conns, text);
        }
        targets.len()
    }

    /// Takes `account`'s connections out of room `id`, telling the room.
    fn put_out(&self, id: &ConvId, account: u128) -> Vec<u64> {
        let gone = {
            let mut presence = lock(&self.presence);
            let Some(room) = presence.get_mut(id) else {
                return Vec::new();
            };
            let gone = room.remove(&account).unwrap_or_default();
            if room.is_empty() {
                presence.remove(id);
            }
            gone
        };
        if !gone.is_empty() {
            self.push_room(id, &presence_event("exited", id, account), None, true);
        }
        gone
    }

    /// Connection `conn` of `account` closed: out of every room it was in.
    pub(super) fn leave_rooms(&self, account: u128, conn: u64) {
        let mut emptied = Vec::new();
        {
            let mut presence = lock(&self.presence);
            presence.retain(|id, room| {
                if let Some(conns) = room.get_mut(&account) {
                    conns.retain(|c| *c != conn);
                    if conns.is_empty() {
                        room.remove(&account);
                        emptied.push(*id);
                    }
                }
                !room.is_empty()
            });
        }
        for id in emptied {
            self.push_room(&id, &presence_event("exited", &id, account), None, true);
        }
    }
}

fn presence_event(op: &str, id: &ConvId, account: u128) -> String {
    Obj::new()
        .str("op", op)
        .str("room", &id.to_string())
        .str("account", &hex(account))
        .end()
}

fn hold_event(op: &str, id: &ConvId, until: u64, by: u128) -> String {
    Obj::new()
        .str("op", op)
        .str("room", &id.to_string())
        .num("until", until)
        .str("by", &hex(by))
        .end()
}

impl ChatConn {
    /// The room ops; any other name is `chat.bad_op`.
    pub(super) fn room_op(&self, op: &str, v: &Value) -> Result<String, String> {
        match op {
            "rooms" => self.directory(v),
            "categories" => self.categories(),
            "create_room" => self.create_room(v),
            "room" => {
                let (id, r) = self.visible_room(v)?;
                Ok(room_json(
                    &id,
                    &r,
                    self.chat.people(&id),
                    self.moderates(&r),
                ))
            }
            "enter" => self.enter(v),
            "exit" => self.exit(v),
            "who" => self.who(v),
            "room_settings" => self.room_settings(v),
            "room_mute" => self.hold(v, HoldKind::Mute),
            "room_kick" => self.hold(v, HoldKind::Kick),
            "room_ban" => self.hold(v, HoldKind::Ban),
            "room_unmute" => self.lift(v, false),
            "room_unban" => self.lift(v, true),
            "room_role" => self.room_role(v),
            "room_invite" => self.room_list(v, true),
            "room_uninvite" => self.room_list(v, false),
            "delete_room" => self.delete_room(v),
            _ => Err(error("chat.bad_op", "There is no such op.", None)),
        }
    }

    /// Whether this caller moderates `r`: its owner, one of its moderators,
    /// or a site admin in a room that is not private.
    fn moderates(&self, r: &Room) -> bool {
        r.owner == self.account
            || r.moderators.contains(&self.account)
            || (self.rank >= 2 && r.access != RoomAccess::Private)
    }

    /// The room the frame names, when this caller may enter it.
    fn visible_room(&self, v: &Value) -> Result<(ConvId, Arc<Room>), String> {
        let id = room_of(v).ok_or_else(bad_room)?;
        match self.chat.room(&id)? {
            Some(r) if r.may_enter(self.account, self.rank, now_ms()) || self.moderates(&r) => {
                Ok((id, r))
            }
            _ => Err(not_here()),
        }
    }

    /// Whether this connection is in room `id`.
    fn present(&self, id: &ConvId) -> bool {
        lock(&self.chat.presence)
            .get(id)
            .and_then(|r| r.get(&self.account))
            .is_some_and(|c| c.contains(&self.id))
    }

    /// Changes room `id` under its lock, from its record as kept.
    fn change_room<T>(
        &self,
        id: &ConvId,
        f: impl FnOnce(&mut Room) -> Result<T, String>,
    ) -> Result<(T, Arc<Room>), String> {
        let chat = &self.chat;
        let _order = chat.conversation_lock(id);
        let Some(r) = chat.room(id)? else {
            return Err(not_here());
        };
        // A room this caller may neither enter nor moderate is not there.
        if !(r.may_enter(self.account, self.rank, now_ms()) || self.moderates(&r)) {
            return Err(not_here());
        }
        let mut r = (*r).clone();
        r.drop_lapsed(now_ms());
        let t = f(&mut r)?;
        let r = chat.keep_room(id, r)?;
        Ok((t, r))
    }

    fn directory(&self, v: &Value) -> Result<String, String> {
        let chat = &self.chat;
        let category = v.get("category").and_then(Value::as_str);
        let q = v
            .get("q")
            .and_then(Value::as_str)
            .map(str::to_lowercase)
            .filter(|q| !q.trim().is_empty());
        let from = number_of(v, "after").unwrap_or(0) as usize;
        let mut found: Vec<(usize, String, String)> = {
            let cache = chat.room_cache()?;
            let presence = lock(&chat.presence);
            cache
                .as_ref()
                .map(|c| {
                    c.iter()
                        .filter(|(_, r)| r.access == RoomAccess::Public && self.rank >= r.rank)
                        .filter(|(_, r)| category.is_none_or(|k| r.category == k))
                        .filter(|(_, r)| {
                            q.as_deref().is_none_or(|q| {
                                r.name.to_lowercase().contains(q)
                                    || r.topic.to_lowercase().contains(q)
                            })
                        })
                        .map(|(id, r)| {
                            let people = presence.get(id).map_or(0, HashMap::len);
                            let item = Obj::new()
                                .str("id", &id.to_string())
                                .str("name", &r.name)
                                .str("topic", &r.topic)
                                .str("category", &r.category)
                                .raw("persistent", if r.persistent { "true" } else { "false" })
                                .num("people", people as u64)
                                .end();
                            (people, r.name.to_lowercase(), item)
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        // The busiest first, then by name.
        found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let total = found.len();
        let page: Vec<String> = found
            .into_iter()
            .skip(from)
            .take(DIRECTORY_PAGE)
            .map(|(_, _, item)| item)
            .collect();
        let next = from + page.len();
        let o = Obj::new().str("op", "rooms").raw("items", &list(page));
        Ok(if next < total {
            o.num("more", next as u64).end()
        } else {
            o.null("more").end()
        })
    }

    fn categories(&self) -> Result<String, String> {
        let chat = &self.chat;
        let cache = chat.room_cache()?;
        let items = chat.settings.rooms.categories.iter().map(|k| {
            let n = cache.as_ref().map_or(0, |c| {
                c.values()
                    .filter(|r| {
                        r.access == RoomAccess::Public && self.rank >= r.rank && &r.category == k
                    })
                    .count()
            });
            Obj::new().str("name", k).num("rooms", n as u64).end()
        });
        Ok(Obj::new()
            .str("op", "categories")
            .raw("items", &list(items))
            .end())
    }

    fn create_room(&self, v: &Value) -> Result<String, String> {
        let chat = &self.chat;
        let s = &chat.settings.rooms;
        let access = match v.get("access").map(Value::as_str) {
            None => RoomAccess::Public,
            Some(Some(a)) => RoomAccess::from_name(a).ok_or_else(|| {
                error(
                    "chat.bad_room",
                    "`access` is `public`, `unlisted` or `private`.",
                    None,
                )
            })?,
            Some(None) => return Err(bad_room()),
        };
        let needs = if access == RoomAccess::Public {
            RoomRight::Public
        } else {
            RoomRight::Private
        };
        if self.limits.rooms < needs {
            return Err(error(
                "chat.not_allowed",
                "Your role may not make that kind of room.",
                None,
            ));
        }
        let name = plain(v, "name", NAME_MAX, false)?
            .ok_or_else(|| error("chat.bad_room", "A room needs a `name`.", None))?;
        let topic = plain(v, "topic", TOPIC_MAX, true)?.unwrap_or_default();
        let category = match v.get("category").and_then(Value::as_str) {
            None => s.categories[0].clone(),
            Some(k) if s.categories.iter().any(|c| c == k) => k.to_owned(),
            Some(_) => {
                return Err(error(
                    "chat.bad_room",
                    "`category` is one of the site's (`categories`).",
                    None,
                ));
            }
        };
        let rank = match v.get("role").and_then(Value::as_str) {
            None => 0,
            Some(n) => rank_of(n).filter(|r| *r <= self.rank).ok_or_else(|| {
                error(
                    "chat.bad_room",
                    "`role` is `member`, `editor` or `admin`, at most your own.",
                    None,
                )
            })?,
        };
        let persistent = v.get("persistent").and_then(Value::as_bool).unwrap_or(true);
        let _quota = lock(stripe(&chat.account_locks, self.account as u64));
        if chat.room_cache()?.as_ref().map_or(0, HashMap::len) as u64 >= s.max {
            return Err(error(
                "chat.full",
                "The site holds as many rooms as it may.",
                None,
            ));
        }
        let mut usage = chat.start_one(self.account)?;
        let id = ConvId::random().ok_or_else(unavailable)?;
        let c = Conversation {
            id,
            kind: ConvKind::Room,
            members: Vec::new(),
            last: 0,
            at_ms: 0,
        };
        if !chat.store.create(&c).map_err(|_| unavailable())? {
            return Err(unavailable());
        }
        let r = chat.keep_room(
            &id,
            Room {
                name,
                topic,
                category,
                access,
                rank,
                owner: self.account,
                moderators: Vec::new(),
                list: Vec::new(),
                persistent,
                scroll: 0,
                keep: s.max_keep.min(10_000),
                advanced: false,
                slow_secs: 0,
                words: Vec::new(),
                bans: Vec::new(),
                mutes: Vec::new(),
            },
        )?;
        usage.started += 1;
        chat.store
            .set_usage(self.account, usage)
            .map_err(|_| unavailable())?;
        Ok(room_json(&id, &r, 0, true))
    }

    fn enter(&self, v: &Value) -> Result<String, String> {
        let chat = &self.chat;
        let id = room_of(v).ok_or_else(bad_room)?;
        let Some(r) = chat.room(&id)? else {
            return Err(not_here());
        };
        if !(r.may_enter(self.account, self.rank, now_ms()) || self.moderates(&r)) {
            return Err(not_here());
        }
        let first = {
            let mut presence = lock(&chat.presence);
            let room = presence.entry(id).or_default();
            if !room.contains_key(&self.account)
                && room.len() as u64 >= chat.settings.rooms.max_present
            {
                return Err(error("chat.full", "The room is full.", None));
            }
            let conns = room.entry(self.account).or_default();
            let first = conns.is_empty();
            if !conns.contains(&self.id) {
                conns.push(self.id);
            }
            first
        };
        if first {
            chat.push_room(
                &id,
                &presence_event("entered", &id, self.account),
                Some(self.account),
                true,
            );
        }
        Ok(room_json(&id, &r, chat.people(&id), self.moderates(&r)))
    }

    fn exit(&self, v: &Value) -> Result<String, String> {
        let chat = &self.chat;
        let id = room_of(v).ok_or_else(bad_room)?;
        let last = {
            let mut presence = lock(&chat.presence);
            let mut last = false;
            if let Some(room) = presence.get_mut(&id)
                && let Some(conns) = room.get_mut(&self.account)
            {
                conns.retain(|c| *c != self.id);
                if conns.is_empty() {
                    room.remove(&self.account);
                    last = true;
                }
                if room.is_empty() {
                    presence.remove(&id);
                }
            }
            last
        };
        if last {
            chat.push_room(
                &id,
                &presence_event("exited", &id, self.account),
                None,
                true,
            );
        }
        Ok(Obj::new()
            .str("op", "exited")
            .str("room", &id.to_string())
            .str("account", &hex(self.account))
            .end())
    }

    fn who(&self, v: &Value) -> Result<String, String> {
        let id = room_of(v).ok_or_else(bad_room)?;
        if !self.present(&id) {
            return Err(error(
                "chat.not_in_room",
                "Enter the room to see who is in it.",
                None,
            ));
        }
        let mut people: Vec<u128> = lock(&self.chat.presence)
            .get(&id)
            .map(|r| r.keys().copied().collect())
            .unwrap_or_default();
        people.sort_unstable();
        let from = number_of(v, "after").unwrap_or(0) as usize;
        let page: Vec<String> = people
            .iter()
            .skip(from)
            .take(WHO_PAGE)
            .map(|a| hex(*a))
            .collect();
        let next = from + page.len();
        let o = Obj::new()
            .str("op", "who")
            .str("room", &id.to_string())
            .strs("items", page.iter().map(String::as_str));
        Ok(if next < people.len() {
            o.num("more", next as u64).end()
        } else {
            o.null("more").end()
        })
    }

    /// A message in a room: only from a connection in it, past the room's
    /// mutes, slow mode, filters and the budgets.
    pub(super) fn room_send(
        &self,
        id: &ConvId,
        r: &Room,
        v: &Value,
        nonce: Option<&str>,
    ) -> Result<String, String> {
        let chat = &self.chat;
        if !self.present(id) {
            return Err(error(
                "chat.not_in_room",
                "Enter the room to write in it.",
                None,
            ));
        }
        let now = now_ms();
        if let Some(until) = r.muted(self.account, now) {
            return Err(Obj::new()
                .str("op", "error")
                .str("code", "chat.muted")
                .str("message", "You may not write in this room now.")
                .num("until", until)
                .end());
        }
        let moderator = self.moderates(r);
        if r.slow_secs > 0 && !moderator {
            let wait = r.slow_secs * 1000;
            let last = lock(&chat.slow).get(&(*id, self.account)).copied();
            if let Some(at) = last
                && now < at + wait
            {
                return Err(Obj::new()
                    .str("op", "error")
                    .str("code", "chat.slow_mode")
                    .str("message", "The room is in slow mode.")
                    .num("retry_ms", at + wait - now)
                    .end());
            }
        }
        let body = v
            .get("body")
            .ok_or_else(|| error("chat.bad_body", "`body` is a list of spans.", None))?;
        let body = read_spans(body, self.advanced && r.advanced, chat.settings.max_length)
            .map_err(|why| error("chat.bad_body", why, None))?;
        let text: String = body
            .iter()
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        if filtered(&text, &chat.settings.rooms.filter, &r.words) {
            chat.audit(self.account, "chat.filtered", self.account, id);
            return Err(error(
                "chat.filtered",
                "The message holds a word this room does not allow.",
                None,
            ));
        }
        let others = chat.people(id).saturating_sub(1) as u64;
        let slow = |ms: u64| {
            Obj::new()
                .str("op", "error")
                .str("code", "chat.slow_down")
                .str(
                    "message",
                    "You are sending faster than you may. Wait a moment.",
                )
                .num("retry_ms", ms)
                .end()
        };
        chat.charge(self.account, others).map_err(slow)?;
        if !chat.realm_take(others) {
            return Err(slow(1000));
        }
        let mut m = Message {
            conversation: *id,
            number: 0,
            author: self.account,
            at_ms: now,
            body,
        };
        if r.persistent {
            let _quota = lock(stripe(&chat.account_locks, self.account as u64));
            let mut usage = chat.store.usage(self.account).map_err(|_| unavailable())?;
            if chat.settings.max_messages > 0 && usage.messages >= chat.settings.max_messages {
                return Err(error(
                    "chat.quota",
                    "You have sent as many messages as you may keep.",
                    None,
                ));
            }
            {
                let _numbering = chat.conversation_lock(id);
                let last = chat
                    .store
                    .conversation(id)
                    .map_err(|_| unavailable())?
                    .map_or(0, |c| c.last);
                m.number = last + 1;
                let mut kept = false;
                for _ in 0..super::NUMBER_TRIES {
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
                    .set_last(id, m.number, m.at_ms)
                    .map_err(|_| unavailable())?;
                // The room keeps its last `keep`: the one before them goes.
                if m.number > r.keep {
                    let _ = chat.store.delete_message(id, m.number - r.keep);
                }
            }
            usage.messages += 1;
            let _ = chat.store.set_usage(self.account, usage);
        } else {
            let mut numbers = lock(&chat.room_numbers);
            let n = numbers.entry(*id).or_insert(0);
            *n += 1;
            m.number = *n;
        }
        lock(&chat.slow).insert((*id, self.account), now);
        let push = Obj::new()
            .str("op", "message")
            .raw(
                "message",
                &Obj::new()
                    .str("conversation", &id.to_string())
                    .num("number", m.number)
                    .str("author", &hex(m.author))
                    .num("at", m.at_ms)
                    .raw("body", &spans_json(&m.body))
                    .end(),
            )
            .end();
        chat.push_room(id, &push, None, false);
        let o = Obj::new()
            .str("op", "sent")
            .str("conversation", &id.to_string())
            .num("number", m.number);
        Ok(match nonce {
            Some(n) => o.str("nonce", n).end(),
            None => o.end(),
        })
    }

    fn room_settings(&self, v: &Value) -> Result<String, String> {
        let id = room_of(v).ok_or_else(bad_room)?;
        let me = self.account;
        let rank = self.rank;
        let s = self.chat.settings.rooms.clone();
        let name = plain(v, "name", NAME_MAX, false)?;
        let topic = plain(v, "topic", TOPIC_MAX, true)?;
        let bad = |what: &str| error("chat.bad_room", what, None);
        let category = match v.get("category").map(Value::as_str) {
            None => None,
            Some(Some(k)) if s.categories.iter().any(|c| c == k) => Some(k.to_owned()),
            Some(_) => return Err(bad("`category` is one of the site's.")),
        };
        let access = match v.get("access").map(Value::as_str) {
            None => None,
            Some(Some(a)) => Some(
                RoomAccess::from_name(a)
                    .ok_or_else(|| bad("`access` is `public`, `unlisted` or `private`."))?,
            ),
            Some(None) => return Err(bad("`access` is a word.")),
        };
        let role =
            match v.get("role").map(Value::as_str) {
                None => None,
                Some(Some(n)) => Some(rank_of(n).filter(|r| *r <= rank).ok_or_else(|| {
                    bad("`role` is `member`, `editor` or `admin`, at most yours.")
                })?),
                Some(None) => return Err(bad("`role` is a word.")),
            };
        let num = |key: &str, hi: u64| -> Result<Option<u64>, String> {
            match v.get(key) {
                None => Ok(None),
                Some(_) => number_of(v, key)
                    .filter(|n| *n <= hi)
                    .map(Some)
                    .ok_or_else(|| bad(&format!("`{key}` is a number up to {hi}."))),
            }
        };
        let scroll = num("scroll", s.max_keep)?;
        let keep = num("keep", s.max_keep)?.map(|k| k.max(1));
        let slow = num("slow", 3600)?;
        let persistent = match v.get("persistent") {
            None => None,
            Some(p) => Some(
                p.as_bool()
                    .ok_or_else(|| bad("`persistent` is true or false."))?,
            ),
        };
        let advanced = match v.get("marks").map(Value::as_str) {
            None => None,
            Some(Some("basic")) => Some(false),
            Some(Some("advanced")) => Some(true),
            Some(_) => return Err(bad("`marks` is `basic` or `advanced`.")),
        };
        let words = match v.get("words") {
            None => None,
            Some(w) => {
                let w = w
                    .as_arr()
                    .ok_or_else(|| bad("`words` is a list of words."))?;
                if w.len() > ROOM_WORDS {
                    return Err(bad("A room's filter holds at most 100 words."));
                }
                Some(
                    w.iter()
                        .map(|x| x.as_str().and_then(filter_word))
                        .collect::<Option<Vec<_>>>()
                        .ok_or_else(|| bad("Each of `words` is one word."))?,
                )
            }
        };
        let owners_only = name.is_some()
            || category.is_some()
            || access.is_some()
            || role.is_some()
            || scroll.is_some()
            || keep.is_some()
            || persistent.is_some()
            || advanced.is_some();
        let (staff, r) = self.change_room(&id, |r| {
            let owner = r.owner == me;
            let moderator = r.moderators.contains(&me);
            let staff = !owner && !moderator && rank >= 2 && r.access != RoomAccess::Private;
            // Moderators may change the topic, slow mode and words only.
            let may = owner || staff || (moderator && !owners_only);
            if !may {
                return Err(not_allowed());
            }
            if let Some(x) = name {
                r.name = x;
            }
            if let Some(x) = topic {
                r.topic = x;
            }
            if let Some(x) = category {
                r.category = x;
            }
            if let Some(x) = access {
                r.access = x;
            }
            if let Some(x) = role {
                r.rank = x;
            }
            if let Some(x) = scroll {
                r.scroll = x;
            }
            if let Some(x) = keep {
                r.keep = x;
            }
            if let Some(x) = slow {
                r.slow_secs = x;
            }
            if let Some(x) = persistent {
                r.persistent = x;
            }
            if let Some(x) = advanced {
                r.advanced = x;
            }
            if let Some(x) = words {
                r.words = x;
            }
            Ok(staff)
        })?;
        let chat = &self.chat;
        chat.audit(
            me,
            if staff {
                "chat.staff_room_settings"
            } else {
                "chat.room_settings"
            },
            r.owner,
            &id,
        );
        let people = chat.people(&id);
        chat.push_room(&id, &room_json(&id, &r, people, false), Some(me), true);
        // Someone who may no longer enter is put out.
        let now = now_ms();
        let present: Vec<u128> = lock(&chat.presence)
            .get(&id)
            .map(|p| p.keys().copied().collect())
            .unwrap_or_default();
        for a in present {
            if !r.may_enter(a, 0, now) && r.access == RoomAccess::Private {
                chat.put_out(&id, a);
            }
        }
        Ok(room_json(&id, &r, chat.people(&id), true))
    }

    fn hold(&self, v: &Value, kind: HoldKind) -> Result<String, String> {
        let id = room_of(v).ok_or_else(bad_room)?;
        let target = super::account_of(v, "account").ok_or_else(|| {
            error(
                "chat.bad_account",
                "`account` is an account id (32 hex digits).",
                None,
            )
        })?;
        let me = self.account;
        if target == me {
            return Err(error("chat.self", "Not on yourself.", None));
        }
        let minutes = number_of(v, "minutes").unwrap_or(match kind {
            HoldKind::Kick => KICK_MINUTES,
            _ => 0,
        });
        let now = now_ms();
        let until = if minutes == 0 {
            0
        } else {
            now.saturating_add(minutes.saturating_mul(MINUTE_MS))
        };
        let rank = self.rank;
        let (staff, _) = self.change_room(&id, |r| {
            let owner = r.owner == me;
            let moderator = r.moderators.contains(&me);
            let staff = !owner && !moderator && rank >= 2 && r.access != RoomAccess::Private;
            if !(owner || moderator || staff) {
                return Err(not_allowed());
            }
            // Never the owner; a moderator never another moderator.
            if target == r.owner || (!owner && r.moderators.contains(&target)) {
                return Err(not_allowed());
            }
            let holds = match kind {
                HoldKind::Mute => &mut r.mutes,
                HoldKind::Kick | HoldKind::Ban => &mut r.bans,
            };
            holds.retain(|h| h.account != target);
            if holds.len() >= MAX_HOLDS {
                return Err(error(
                    "chat.full",
                    "The room holds as many as it may.",
                    None,
                ));
            }
            holds.push(Hold {
                account: target,
                until_ms: until,
            });
            Ok(staff)
        })?;
        let chat = &self.chat;
        let (op, action) = match (kind, staff) {
            (HoldKind::Mute, false) => ("muted", "chat.room_mute"),
            (HoldKind::Mute, true) => ("muted", "chat.staff_room_mute"),
            (HoldKind::Kick, false) => ("kicked", "chat.room_kick"),
            (HoldKind::Kick, true) => ("kicked", "chat.staff_room_kick"),
            (HoldKind::Ban, false) => ("banned", "chat.room_ban"),
            (HoldKind::Ban, true) => ("banned", "chat.staff_room_ban"),
        };
        chat.audit(me, action, target, &id);
        // The target hears it on its connections in the room, then is put
        // out of it when kicked or banned.
        let conns: Vec<u64> = lock(&chat.presence)
            .get(&id)
            .and_then(|p| p.get(&target).cloned())
            .unwrap_or_default();
        chat.push_to(target, &conns, &hold_event(op, &id, until, me));
        if kind != HoldKind::Mute {
            chat.put_out(&id, target);
        }
        Ok(Obj::new()
            .str("op", op)
            .str("room", &id.to_string())
            .str("account", &hex(target))
            .num("until", until)
            .end())
    }

    fn lift(&self, v: &Value, ban: bool) -> Result<String, String> {
        let id = room_of(v).ok_or_else(bad_room)?;
        let target = super::account_of(v, "account").ok_or_else(|| {
            error(
                "chat.bad_account",
                "`account` is an account id (32 hex digits).",
                None,
            )
        })?;
        let me = self.account;
        let rank = self.rank;
        self.change_room(&id, |r| {
            let staff = rank >= 2 && r.access != RoomAccess::Private;
            if !(r.owner == me || r.moderators.contains(&me) || staff) {
                return Err(not_allowed());
            }
            if ban {
                r.bans.retain(|h| h.account != target);
            } else {
                r.mutes.retain(|h| h.account != target);
            }
            Ok(())
        })?;
        self.chat.audit(
            me,
            if ban {
                "chat.room_unban"
            } else {
                "chat.room_unmute"
            },
            target,
            &id,
        );
        Ok(Obj::new()
            .str("op", if ban { "unbanned" } else { "unmuted" })
            .str("room", &id.to_string())
            .str("account", &hex(target))
            .end())
    }

    fn room_role(&self, v: &Value) -> Result<String, String> {
        let id = room_of(v).ok_or_else(bad_room)?;
        let target = super::account_of(v, "account").ok_or_else(|| {
            error(
                "chat.bad_account",
                "`account` is an account id (32 hex digits).",
                None,
            )
        })?;
        let moderator = match v.get("role").and_then(Value::as_str) {
            Some("moderator") => true,
            Some("member") => false,
            _ => {
                return Err(error(
                    "chat.bad_role",
                    "`role` is `moderator` or `member`.",
                    None,
                ));
            }
        };
        let me = self.account;
        let ((), r) = self.change_room(&id, |r| {
            if r.owner != me || target == me {
                return Err(not_allowed());
            }
            r.moderators.retain(|m| *m != target);
            if moderator {
                if r.moderators.len() >= 100 {
                    return Err(error(
                        "chat.full",
                        "A room has at most 100 moderators.",
                        None,
                    ));
                }
                r.moderators.push(target);
            }
            Ok(())
        })?;
        self.chat.audit(me, "chat.room_role", target, &id);
        let people = self.chat.people(&id);
        self.chat
            .push_room(&id, &room_json(&id, &r, people, false), Some(me), true);
        Ok(room_json(&id, &r, people, true))
    }

    /// Puts `account` on a private room's list, or takes it off.
    fn room_list(&self, v: &Value, on: bool) -> Result<String, String> {
        let id = room_of(v).ok_or_else(bad_room)?;
        let target = super::account_of(v, "account").ok_or_else(|| {
            error(
                "chat.bad_account",
                "`account` is an account id (32 hex digits).",
                None,
            )
        })?;
        let me = self.account;
        let chat = &self.chat;
        let cap = chat.settings.rooms.max_present;
        let (name, _) = self.change_room(&id, |r| {
            if !(r.owner == me || r.moderators.contains(&me)) {
                return Err(not_allowed());
            }
            if r.access != RoomAccess::Private {
                return Err(error(
                    "chat.bad_room",
                    "Only a private room has a list.",
                    None,
                ));
            }
            if on {
                let now = now_ms();
                let banned = r.bans.iter().any(|b| b.account == target && b.on(now));
                if banned || !chat.may_write(me, target)? {
                    return Err(cannot_write());
                }
                if !r.list.contains(&target) {
                    if r.list.len() as u64 >= cap {
                        return Err(error("chat.full", "The room's list is full.", None));
                    }
                    r.list.push(target);
                }
            } else {
                r.list.retain(|a| *a != target);
            }
            Ok(r.name.clone())
        })?;
        if on {
            chat.push(
                target,
                &Obj::new()
                    .str("op", "room_invited")
                    .str("room", &id.to_string())
                    .str("name", &name)
                    .str("by", &hex(me))
                    .end(),
            );
        } else {
            chat.put_out(&id, target);
        }
        Ok(Obj::new()
            .str("op", if on { "room_invite" } else { "room_uninvite" })
            .str("room", &id.to_string())
            .str("account", &hex(target))
            .end())
    }

    fn delete_room(&self, v: &Value) -> Result<String, String> {
        let id = room_of(v).ok_or_else(bad_room)?;
        let chat = &self.chat;
        let staff;
        {
            let _order = chat.conversation_lock(&id);
            let Some(r) = chat.room(&id)? else {
                return Err(not_here());
            };
            staff = r.owner != self.account;
            if staff && !(self.rank >= 2 && r.access != RoomAccess::Private) {
                return Err(if r.may_enter(self.account, self.rank, now_ms()) {
                    not_allowed()
                } else {
                    not_here()
                });
            }
            let last = chat
                .store
                .conversation(&id)
                .map_err(|_| unavailable())?
                .map_or(0, |c| c.last);
            chat.store
                .delete_conversation(&id, last)
                .map_err(|_| unavailable())?;
            if let Some(c) = chat.room_cache()?.as_mut() {
                c.remove(&id);
            }
        }
        chat.audit(
            self.account,
            if staff {
                "chat.staff_delete_room"
            } else {
                "chat.delete_room"
            },
            self.account,
            &id,
        );
        let closed = Obj::new()
            .str("op", "room_closed")
            .str("room", &id.to_string())
            .end();
        chat.push_room(&id, &closed, None, false);
        lock(&chat.presence).remove(&id);
        lock(&chat.room_numbers).remove(&id);
        Ok(closed)
    }
}

/// What a moderator holds someone to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HoldKind {
    Mute,
    Kick,
    Ban,
}

/// What `history` gives in a room: nothing from an ephemeral one, and no
/// further back than the room's scroll and what it keeps.
pub(super) fn floor(r: &Room, last: u64) -> Option<u64> {
    if !r.persistent {
        return None;
    }
    let kept = last.saturating_sub(r.keep).saturating_add(1).max(1);
    let scroll = match r.scroll {
        0 => 1,
        s => last.saturating_sub(s).saturating_add(1).max(1),
    };
    Some(kept.max(scroll))
}

impl Access {
    /// The room, for a room's access.
    pub(super) fn room(&self) -> Option<&Arc<Room>> {
        match self {
            Access::Room(_, r) => Some(r),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_room_record_reads_back_and_filters_match_whole_words() {
        let r = Room {
            name: "Lobby".to_owned(),
            topic: "Say \"hi\"".to_owned(),
            category: "general".to_owned(),
            access: RoomAccess::Unlisted,
            rank: 1,
            owner: 1,
            moderators: vec![2],
            list: vec![3],
            persistent: false,
            scroll: 10,
            keep: 20,
            advanced: true,
            slow_secs: 5,
            words: vec!["darn".to_owned()],
            bans: vec![Hold {
                account: 4,
                until_ms: 0,
            }],
            mutes: vec![Hold {
                account: 5,
                until_ms: 9,
            }],
        };
        assert_eq!(Room::from_json(&r.to_json()), Some(r));
        let words = vec!["darn".to_owned()];
        assert!(filtered("well, DARN it", &[], &words));
        assert!(!filtered("darning socks", &[], &words));
        assert!(!filtered("anything", &[], &[]));
        assert_eq!(filter_word("Darn"), Some("darn".to_owned()));
        assert_eq!(filter_word("two words"), None);
    }
}
