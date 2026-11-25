//! Group conversations (G-84): a name, one owner, moderators, members who
//! join by invite, bans, and the group's own settings. The roles are the
//! group's: owning a group gives nothing on the site, and a site role gives
//! nothing in someone else's group.

use std::sync::Arc;

use crate::api::{Obj, list};
use crate::json::Value;

use super::{
    Access, ChatConn, ConvId, Conversation, account_of, bad_conversation, cannot_write, conv_of,
    error, hex, lock, now_ms, number_of, stripe, unavailable,
};

/// The longest group name, in characters.
pub const NAME_MAX: usize = 100;

/// The most accounts one group may ban.
pub const MAX_BANS: usize = 1000;

/// Members in one page of `members`.
const MEMBERS_PAGE: usize = 100;

/// What a member may do in a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupRole {
    /// Writes, reads, leaves; invites when the group allows it.
    Member,
    /// Also invites, kicks and bans members.
    Moderator,
    /// Everything: there is one.
    Owner,
}

impl GroupRole {
    /// Its name in frames and records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GroupRole::Member => "member",
            GroupRole::Moderator => "moderator",
            GroupRole::Owner => "owner",
        }
    }

    fn from_name(s: &str) -> Option<GroupRole> {
        match s {
            "member" => Some(GroupRole::Member),
            "moderator" => Some(GroupRole::Moderator),
            "owner" => Some(GroupRole::Owner),
            _ => None,
        }
    }
}

/// One member of a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMember {
    /// The account.
    pub account: u128,
    /// What it may do.
    pub role: GroupRole,
    /// The conversation's last number when it joined.
    pub joined: u64,
}

/// An open invite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    /// Who is invited.
    pub account: u128,
    /// Who invited them.
    pub by: u128,
    /// When it lapses (ms since 1970).
    pub until_ms: u64,
}

/// A group's own settings, the owner's to change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupSettings {
    /// The most members and open invites together.
    pub cap: u64,
    /// Whether authors may use the advanced marks (as far as their site
    /// role allows).
    pub advanced: bool,
    /// How many messages back a member may page; 0 for all.
    pub history: u64,
    /// Whether a new member sees what came before it joined.
    pub before_join: bool,
    /// Whether any member may invite.
    pub members_invite: bool,
}

/// A group's record: who is in it, who is invited or banned, and its
/// settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Its name, plain text.
    pub name: String,
    /// Its members, the longest-standing first.
    pub members: Vec<GroupMember>,
    /// Its open invites.
    pub invited: Vec<Invite>,
    /// Accounts that may not be invited.
    pub banned: Vec<u128>,
    /// Its settings.
    pub settings: GroupSettings,
}

impl Group {
    /// The member `account`, when it is one.
    #[must_use]
    pub fn member(&self, account: u128) -> Option<&GroupMember> {
        self.members.iter().find(|m| m.account == account)
    }

    /// The owner.
    #[must_use]
    pub fn owner(&self) -> Option<u128> {
        self.members
            .iter()
            .find(|m| m.role == GroupRole::Owner)
            .map(|m| m.account)
    }

    /// The record as the stores keep it.
    #[must_use]
    pub fn to_json(&self) -> String {
        let s = &self.settings;
        let settings = Obj::new()
            .num("cap", s.cap)
            .str("marks", if s.advanced { "advanced" } else { "basic" })
            .num("history", s.history)
            .raw("before_join", if s.before_join { "true" } else { "false" })
            .raw(
                "members_invite",
                if s.members_invite { "true" } else { "false" },
            )
            .end();
        let members = list(self.members.iter().map(|m| {
            format!(
                "[\"{}\",\"{}\",{}]",
                hex(m.account),
                m.role.as_str(),
                m.joined
            )
        }));
        let invited = list(
            self.invited
                .iter()
                .map(|i| format!("[\"{}\",\"{}\",{}]", hex(i.account), hex(i.by), i.until_ms)),
        );
        let banned = list(self.banned.iter().map(|b| format!("\"{}\"", hex(*b))));
        Obj::new()
            .str("name", &self.name)
            .raw("settings", &settings)
            .raw("members", &members)
            .raw("invited", &invited)
            .raw("banned", &banned)
            .end()
    }

    /// A record from what [`Group::to_json`] wrote.
    #[must_use]
    pub fn from_json(text: &str) -> Option<Group> {
        let v = crate::json::parse(text).ok()?;
        let hex_of = |v: &Value| -> Option<u128> {
            let s = v.as_str()?;
            (s.len() == 32).then_some(())?;
            u128::from_str_radix(s, 16).ok()
        };
        let num = |v: &Value| v.as_int().and_then(|n| u64::try_from(n).ok());
        let s = v.get("settings")?;
        let settings = GroupSettings {
            cap: num(s.get("cap")?)?,
            advanced: s.get("marks")?.as_str()? == "advanced",
            history: num(s.get("history")?)?,
            before_join: s.get("before_join")?.as_bool()?,
            members_invite: s.get("members_invite")?.as_bool()?,
        };
        let mut members = Vec::new();
        for m in v.get("members")?.as_arr()? {
            let m = m.as_arr()?;
            members.push(GroupMember {
                account: hex_of(m.first()?)?,
                role: GroupRole::from_name(m.get(1)?.as_str()?)?,
                joined: num(m.get(2)?)?,
            });
        }
        let mut invited = Vec::new();
        for i in v.get("invited")?.as_arr()? {
            let i = i.as_arr()?;
            invited.push(Invite {
                account: hex_of(i.first()?)?,
                by: hex_of(i.get(1)?)?,
                until_ms: num(i.get(2)?)?,
            });
        }
        let banned = v
            .get("banned")?
            .as_arr()?
            .iter()
            .map(hex_of)
            .collect::<Option<Vec<_>>>()?;
        Some(Group {
            name: v.get("name")?.as_str()?.to_owned(),
            members,
            invited,
            banned,
            settings,
        })
    }

    /// Drops the invites that lapsed by `now`.
    fn drop_lapsed(&mut self, now: u64) {
        self.invited.retain(|i| i.until_ms > now);
    }

    /// The open invite of `account`, when there is one at `now`.
    fn invite_of(&self, account: u128, now: u64) -> Option<&Invite> {
        self.invited
            .iter()
            .find(|i| i.account == account && i.until_ms > now)
    }

    /// Places taken: members and open invites.
    fn taken(&self) -> u64 {
        (self.members.len() + self.invited.len()) as u64
    }
}

/// A group name as given: trimmed, 1 to [`NAME_MAX`] characters, no
/// control characters.
fn name_of(v: &Value) -> Result<String, String> {
    let bad = || {
        error(
            "chat.bad_name",
            "A group's name is 1 to 100 characters of text.",
            None,
        )
    };
    let name = v
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(bad)?
        .trim();
    if name.is_empty() || name.chars().count() > NAME_MAX || name.chars().any(char::is_control) {
        return Err(bad());
    }
    Ok(name.to_owned())
}

/// The group's record as members see it.
fn group_json(id: &ConvId, g: &Group) -> String {
    let s = &g.settings;
    let moderators: Vec<String> = g
        .members
        .iter()
        .filter(|m| m.role == GroupRole::Moderator)
        .map(|m| hex(m.account))
        .collect();
    let settings = Obj::new()
        .num("cap", s.cap)
        .str("marks", if s.advanced { "advanced" } else { "basic" })
        .num("history", s.history)
        .raw("before_join", if s.before_join { "true" } else { "false" })
        .raw(
            "members_invite",
            if s.members_invite { "true" } else { "false" },
        )
        .end();
    Obj::new()
        .str("op", "group")
        .str("id", &id.to_string())
        .str("name", &g.name)
        .str("owner", &g.owner().map(hex).unwrap_or_default())
        .strs("moderators", moderators.iter().map(String::as_str))
        .num("count", g.members.len() as u64)
        .raw("settings", &settings)
        .end()
}

/// What every member hears when membership changes.
fn member_event(
    id: &ConvId,
    account: u128,
    event: &str,
    by: u128,
    role: Option<GroupRole>,
) -> String {
    let o = Obj::new()
        .str("op", "member")
        .str("conversation", &id.to_string())
        .str("account", &hex(account))
        .str("event", event)
        .str("by", &hex(by));
    match role {
        Some(r) => o.str("role", r.as_str()).end(),
        None => o.end(),
    }
}

fn not_allowed() -> String {
    error(
        "chat.not_allowed",
        "Your place in the group does not allow that.",
        None,
    )
}

fn not_a_member() -> String {
    error(
        "chat.not_a_member",
        "There is no such conversation of yours.",
        None,
    )
}

fn bad_account() -> String {
    error(
        "chat.bad_account",
        "`account` is an account id (32 hex digits).",
        None,
    )
}

fn on_of(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

impl super::Chat {
    /// Sends `text` to every member of `g` with a connection open.
    fn push_group(&self, g: &Group, text: &str) {
        for a in self.online(g.members.iter().map(|m| m.account)) {
            self.push(a, text);
        }
    }

    /// Writes an audit line for a moderation step.
    fn audit(&self, by: u128, action: &'static str, account: u128, id: &ConvId) {
        crate::events::audit_with(
            &hex(by),
            action,
            &hex(account),
            &format!("realm={} conversation={id}", self.realm),
        );
    }
}

impl ChatConn {
    /// The group ops; any other name is `chat.bad_op`.
    pub(super) fn group_op(&self, op: &str, v: &Value) -> Result<String, String> {
        match op {
            "create" => self.create(v),
            "invite" => self.invite(v),
            "invites" => self.invites(),
            "join" => self.join(v),
            "decline" => self.decline(v),
            "leave" => self.leave(v),
            "kick" => self.kick(v),
            "unban" => self.unban(v),
            "role" => self.set_role(v),
            "transfer" => self.transfer(v),
            "settings" => self.group_settings(v),
            "members" => self.members(v),
            "group" => {
                let (id, g, _) = self.in_group(v)?;
                Ok(group_json(&id, &g))
            }
            _ => Err(error("chat.bad_op", "There is no such op.", None)),
        }
    }

    /// The group the frame names, when the caller is a member of it.
    fn in_group(&self, v: &Value) -> Result<(ConvId, Arc<Group>, super::GroupMember), String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        match self.chat.access(&id, self.account)? {
            Access::Group(_, g, m) => Ok((id, g, m)),
            Access::Direct(_) => Err(error(
                "chat.not_a_group",
                "That conversation is not a group.",
                None,
            )),
        }
    }

    /// Changes group `id` under its lock, from its record as kept: `f` gets
    /// the record and the conversation. With `member`, the caller must be a
    /// member.
    fn change<T>(
        &self,
        id: &ConvId,
        member: bool,
        f: impl FnOnce(&mut Group, &Conversation) -> Result<T, String>,
    ) -> Result<(T, Arc<Group>), String> {
        let chat = &self.chat;
        let _order = chat.conversation_lock(id);
        let c = match chat.store.conversation(id) {
            Ok(Some(c)) if c.group => c,
            Ok(_) => return Err(not_a_member()),
            Err(_) => return Err(unavailable()),
        };
        let Some(mut g) = chat.store.group(id).map_err(|_| unavailable())? else {
            return Err(not_a_member());
        };
        if member && g.member(self.account).is_none() {
            return Err(not_a_member());
        }
        let t = f(&mut g, &c)?;
        let g = chat.keep_group(id, g)?;
        Ok((t, g))
    }

    fn create(&self, v: &Value) -> Result<String, String> {
        let chat = &self.chat;
        if !self.limits.groups {
            return Err(error(
                "chat.not_allowed",
                "Your role may not start groups.",
                None,
            ));
        }
        let name = name_of(v)?;
        let _quota = lock(stripe(&chat.account_locks, self.account as u64));
        let mut usage = chat.start_one(self.account)?;
        let id = ConvId::random().ok_or_else(unavailable)?;
        let c = Conversation {
            id,
            group: true,
            members: Vec::new(),
            last: 0,
            at_ms: 0,
        };
        if !chat.store.create(&c).map_err(|_| unavailable())? {
            return Err(unavailable());
        }
        let g = Group {
            name,
            members: vec![GroupMember {
                account: self.account,
                role: GroupRole::Owner,
                joined: 0,
            }],
            invited: Vec::new(),
            banned: Vec::new(),
            settings: GroupSettings {
                cap: chat.settings.group_max_members.min(50),
                advanced: false,
                history: 0,
                before_join: false,
                members_invite: false,
            },
        };
        let g = chat.keep_group(&id, g)?;
        usage.started += 1;
        chat.store
            .set_usage(self.account, usage)
            .map_err(|_| unavailable())?;
        chat.store
            .index(self.account, &id)
            .map_err(|_| unavailable())?;
        Ok(group_json(&id, &g))
    }

    fn invite(&self, v: &Value) -> Result<String, String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        let target = account_of(v, "account").ok_or_else(bad_account)?;
        if target == self.account {
            return Err(error("chat.self", "You are in the group already.", None));
        }
        let chat = &self.chat;
        let me = self.account;
        let days = chat.settings.invite_days;
        let (name, _) = self.change(&id, true, |g, _| {
            let mine = g.member(me).map_or(GroupRole::Member, |m| m.role);
            if mine == GroupRole::Member && !g.settings.members_invite {
                return Err(not_allowed());
            }
            if g.member(target).is_some() {
                return Err(error(
                    "chat.already",
                    "That account is in the group already.",
                    None,
                ));
            }
            let now = now_ms();
            g.drop_lapsed(now);
            if g.banned.contains(&target) || !chat.may_write(me, target)? {
                return Err(cannot_write());
            }
            let until_ms = now.saturating_add(days.saturating_mul(DAY_MS));
            if let Some(open) = g.invited.iter_mut().find(|i| i.account == target) {
                open.until_ms = until_ms;
                open.by = me;
            } else {
                if g.taken() >= g.settings.cap {
                    return Err(error("chat.full", "The group is full.", None));
                }
                g.invited.push(Invite {
                    account: target,
                    by: me,
                    until_ms,
                });
            }
            Ok(g.name.clone())
        })?;
        chat.store
            .set_invited(target, &id, true)
            .map_err(|_| unavailable())?;
        chat.push(
            target,
            &Obj::new()
                .str("op", "invited")
                .str("conversation", &id.to_string())
                .str("name", &name)
                .str("by", &hex(me))
                .end(),
        );
        Ok(Obj::new()
            .str("op", "invite")
            .str("conversation", &id.to_string())
            .str("account", &hex(target))
            .end())
    }

    fn invites(&self) -> Result<String, String> {
        let chat = &self.chat;
        let now = now_ms();
        let mut items = Vec::new();
        for id in chat
            .store
            .invites_of(self.account)
            .map_err(|_| unavailable())?
        {
            let open = chat
                .group(&id)?
                .and_then(|g| g.invite_of(self.account, now).cloned().map(|i| (g, i)));
            match open {
                Some((g, i)) => items.push(
                    Obj::new()
                        .str("conversation", &id.to_string())
                        .str("name", &g.name)
                        .str("by", &hex(i.by))
                        .num("until", i.until_ms)
                        .end(),
                ),
                // Lapsed, taken back, or the group is gone.
                None => {
                    let _ = chat.store.set_invited(self.account, &id, false);
                }
            }
        }
        Ok(Obj::new()
            .str("op", "invites")
            .raw("items", &list(items))
            .end())
    }

    fn join(&self, v: &Value) -> Result<String, String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        let me = self.account;
        let no_invite = || {
            error(
                "chat.not_invited",
                "There is no open invite of yours to that group.",
                None,
            )
        };
        let ((), g) = self
            .change(&id, false, |g, c| {
                if g.member(me).is_some() {
                    return Err(error("chat.already", "You are in the group already.", None));
                }
                let now = now_ms();
                if g.invite_of(me, now).is_none() || g.banned.contains(&me) {
                    return Err(no_invite());
                }
                g.invited.retain(|i| i.account != me);
                g.members.push(GroupMember {
                    account: me,
                    role: GroupRole::Member,
                    joined: c.last,
                });
                Ok(())
            })
            .map_err(|e| {
                if e.contains("chat.not_a_member") {
                    no_invite()
                } else {
                    e
                }
            })?;
        let chat = &self.chat;
        let _ = chat.store.set_invited(me, &id, false);
        chat.store.index(me, &id).map_err(|_| unavailable())?;
        chat.push_group(&g, &member_event(&id, me, "joined", me, None));
        Ok(group_json(&id, &g))
    }

    fn decline(&self, v: &Value) -> Result<String, String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        let me = self.account;
        // Whether or not there was one: the answer is the same.
        let _ = self.change(&id, false, |g, _| {
            g.invited.retain(|i| i.account != me);
            Ok(())
        });
        let _ = self.chat.store.set_invited(me, &id, false);
        Ok(Obj::new()
            .str("op", "declined")
            .str("conversation", &id.to_string())
            .end())
    }

    fn leave(&self, v: &Value) -> Result<String, String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        let me = self.account;
        let ((owner, last), g) = self.change(&id, true, |g, c| {
            let was = g.member(me).map(|m| m.role);
            g.members.retain(|m| m.account != me);
            // The owner's place goes to the longest-standing moderator, else
            // the longest-standing member.
            let mut owner = None;
            if was == Some(GroupRole::Owner) {
                let next = g
                    .members
                    .iter()
                    .position(|m| m.role == GroupRole::Moderator)
                    .or(if g.members.is_empty() { None } else { Some(0) });
                if let Some(i) = next {
                    g.members[i].role = GroupRole::Owner;
                    owner = Some(g.members[i].account);
                }
            }
            Ok((owner, c.last))
        })?;
        let chat = &self.chat;
        let _ = chat.store.unindex(me, &id);
        if g.members.is_empty() {
            // The last one out: the group and its messages go.
            lock(&chat.groups).remove(&id);
            for invite in &g.invited {
                let _ = chat.store.set_invited(invite.account, &id, false);
            }
            chat.store
                .delete_conversation(&id, last)
                .map_err(|_| unavailable())?;
        } else {
            chat.push_group(&g, &member_event(&id, me, "left", me, None));
            if let Some(o) = owner {
                chat.push_group(
                    &g,
                    &member_event(&id, o, "owner", me, Some(GroupRole::Owner)),
                );
            }
        }
        Ok(Obj::new()
            .str("op", "left")
            .str("conversation", &id.to_string())
            .end())
    }

    fn kick(&self, v: &Value) -> Result<String, String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        let target = account_of(v, "account").ok_or_else(bad_account)?;
        let ban = on_of(v, "ban").unwrap_or(false);
        let me = self.account;
        if target == me {
            return Err(error("chat.self", "To go, leave the group.", None));
        }
        let (was_member, g) = self.change(&id, true, |g, _| {
            let mine = g.member(me).map_or(GroupRole::Member, |m| m.role);
            let theirs = g.member(target).map(|m| m.role);
            let may = match mine {
                GroupRole::Owner => true,
                GroupRole::Moderator => theirs.is_none_or(|r| r == GroupRole::Member),
                GroupRole::Member => false,
            };
            if !may {
                return Err(not_allowed());
            }
            g.members.retain(|m| m.account != target);
            g.invited.retain(|i| i.account != target);
            if ban && !g.banned.contains(&target) {
                if g.banned.len() >= MAX_BANS {
                    return Err(error("chat.full", "The group's ban list is full.", None));
                }
                g.banned.push(target);
            }
            Ok(theirs.is_some())
        })?;
        let chat = &self.chat;
        let _ = chat.store.unindex(target, &id);
        let _ = chat.store.set_invited(target, &id, false);
        chat.audit(me, if ban { "chat.ban" } else { "chat.kick" }, target, &id);
        if was_member {
            chat.push(
                target,
                &Obj::new()
                    .str("op", "removed")
                    .str("conversation", &id.to_string())
                    .str("by", &hex(me))
                    .end(),
            );
            chat.push_group(&g, &member_event(&id, target, "kicked", me, None));
        }
        Ok(Obj::new()
            .str("op", "kicked")
            .str("conversation", &id.to_string())
            .str("account", &hex(target))
            .raw("ban", if ban { "true" } else { "false" })
            .end())
    }

    fn unban(&self, v: &Value) -> Result<String, String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        let target = account_of(v, "account").ok_or_else(bad_account)?;
        let me = self.account;
        self.change(&id, true, |g, _| {
            if g.member(me).is_none_or(|m| m.role == GroupRole::Member) {
                return Err(not_allowed());
            }
            g.banned.retain(|b| *b != target);
            Ok(())
        })?;
        self.chat.audit(me, "chat.unban", target, &id);
        Ok(Obj::new()
            .str("op", "unbanned")
            .str("conversation", &id.to_string())
            .str("account", &hex(target))
            .end())
    }

    fn set_role(&self, v: &Value) -> Result<String, String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        let target = account_of(v, "account").ok_or_else(bad_account)?;
        let role = match v.get("role").and_then(Value::as_str) {
            Some("moderator") => GroupRole::Moderator,
            Some("member") => GroupRole::Member,
            _ => {
                return Err(error(
                    "chat.bad_role",
                    "`role` is `moderator` or `member`.",
                    None,
                ));
            }
        };
        let me = self.account;
        let ((), g) = self.change(&id, true, |g, _| {
            if g.owner() != Some(me) {
                return Err(not_allowed());
            }
            let Some(m) = g.members.iter_mut().find(|m| m.account == target) else {
                return Err(not_a_member_of());
            };
            if m.role == GroupRole::Owner {
                return Err(error(
                    "chat.self",
                    "To hand the group on, transfer it.",
                    None,
                ));
            }
            m.role = role;
            Ok(())
        })?;
        self.chat.audit(me, "chat.role", target, &id);
        self.chat
            .push_group(&g, &member_event(&id, target, "role", me, Some(role)));
        Ok(Obj::new()
            .str("op", "role")
            .str("conversation", &id.to_string())
            .str("account", &hex(target))
            .str("role", role.as_str())
            .end())
    }

    fn transfer(&self, v: &Value) -> Result<String, String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        let target = account_of(v, "account").ok_or_else(bad_account)?;
        let me = self.account;
        if target == me {
            return Err(error("chat.self", "The group is yours already.", None));
        }
        let ((), g) = self.change(&id, true, |g, _| {
            if g.owner() != Some(me) {
                return Err(not_allowed());
            }
            if g.member(target).is_none() {
                return Err(not_a_member_of());
            }
            for m in &mut g.members {
                if m.account == target {
                    m.role = GroupRole::Owner;
                } else if m.account == me {
                    m.role = GroupRole::Moderator;
                }
            }
            Ok(())
        })?;
        self.chat.audit(me, "chat.transfer", target, &id);
        self.chat.push_group(
            &g,
            &member_event(&id, target, "owner", me, Some(GroupRole::Owner)),
        );
        Ok(group_json(&id, &g))
    }

    fn group_settings(&self, v: &Value) -> Result<String, String> {
        let id = conv_of(v).ok_or_else(bad_conversation)?;
        let me = self.account;
        let ceiling = self.chat.settings.group_max_members;
        let name = match v.get("name") {
            Some(_) => Some(name_of(v)?),
            None => None,
        };
        let bad = |what: &str| error("chat.bad_settings", what, None);
        let cap = match v.get("cap") {
            None => None,
            Some(c) => Some(
                c.as_int()
                    .and_then(|n| u64::try_from(n).ok())
                    .filter(|n| (2..=ceiling).contains(n))
                    .ok_or_else(|| bad("`cap` is 2 up to the site's most members."))?,
            ),
        };
        let advanced = match v.get("marks").map(Value::as_str) {
            None => None,
            Some(Some("basic")) => Some(false),
            Some(Some("advanced")) => Some(true),
            Some(_) => return Err(bad("`marks` is `basic` or `advanced`.")),
        };
        let history = match v.get("history") {
            None => None,
            Some(_) => Some(
                number_of(v, "history").ok_or_else(|| bad("`history` is a number, 0 for all."))?,
            ),
        };
        let before_join = match v.get("before_join") {
            None => None,
            Some(b) => Some(
                b.as_bool()
                    .ok_or_else(|| bad("`before_join` is true or false."))?,
            ),
        };
        let members_invite = match v.get("members_invite") {
            None => None,
            Some(b) => Some(
                b.as_bool()
                    .ok_or_else(|| bad("`members_invite` is true or false."))?,
            ),
        };
        let ((), g) = self.change(&id, true, |g, _| {
            if g.owner() != Some(me) {
                return Err(not_allowed());
            }
            if let Some(cap) = cap {
                if cap < g.taken() {
                    return Err(bad("`cap` is below the members and open invites."));
                }
                g.settings.cap = cap;
            }
            if let Some(n) = name {
                g.name = n;
            }
            if let Some(a) = advanced {
                g.settings.advanced = a;
            }
            if let Some(h) = history {
                g.settings.history = h;
            }
            if let Some(b) = before_join {
                g.settings.before_join = b;
            }
            if let Some(m) = members_invite {
                g.settings.members_invite = m;
            }
            Ok(())
        })?;
        self.chat.audit(me, "chat.settings", me, &id);
        let record = group_json(&id, &g);
        self.chat.push_group(&g, &record);
        Ok(record)
    }

    fn members(&self, v: &Value) -> Result<String, String> {
        let (id, g, _) = self.in_group(v)?;
        let from = number_of(v, "after").unwrap_or(0) as usize;
        let page: Vec<String> = g
            .members
            .iter()
            .skip(from)
            .take(MEMBERS_PAGE)
            .map(|m| {
                Obj::new()
                    .str("account", &hex(m.account))
                    .str("role", m.role.as_str())
                    .num("joined", m.joined)
                    .end()
            })
            .collect();
        let next = from + page.len();
        let o = Obj::new()
            .str("op", "members")
            .str("conversation", &id.to_string())
            .raw("items", &list(page));
        Ok(if next < g.members.len() {
            o.num("more", next as u64).end()
        } else {
            o.null("more").end()
        })
    }
}

fn not_a_member_of() -> String {
    error(
        "chat.not_in_group",
        "That account is not in the group.",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_reads_back_as_written() {
        let g = Group {
            name: "Team \"one\"".to_owned(),
            members: vec![
                GroupMember {
                    account: 1,
                    role: GroupRole::Owner,
                    joined: 0,
                },
                GroupMember {
                    account: 2,
                    role: GroupRole::Moderator,
                    joined: 7,
                },
            ],
            invited: vec![Invite {
                account: 3,
                by: 2,
                until_ms: 99,
            }],
            banned: vec![4],
            settings: GroupSettings {
                cap: 10,
                advanced: true,
                history: 5,
                before_join: true,
                members_invite: false,
            },
        };
        assert_eq!(Group::from_json(&g.to_json()), Some(g));
        assert_eq!(Group::from_json("{}"), None);
    }
}
