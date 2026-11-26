//! The messenger's store on nex-db (G-83): one content site per realm
//! (`wasp-chat`, or `wasp-chat-<realm>`), an entity per conversation, per
//! message, per read marker, per mute, per block and per account's usage, and
//! an index entry per member authored by its account.

use std::sync::Arc;

use super::{NexDb, StoreError, nex};
use crate::chat::store::{ChatStore, Conversation, Usage};
use crate::chat::{ConvId, Group, Message, Room};

const CONV_KIND: &str = "chat_conv";
const MEMBER_KIND: &str = "chat_member";
const MESSAGE_KIND: &str = "chat_msg";
const READ_KIND: &str = "chat_read";
const MUTE_KIND: &str = "chat_mute";
const BLOCK_KIND: &str = "chat_block";
const USAGE_KIND: &str = "chat_usage";
const GROUP_KIND: &str = "chat_group";
const INVITE_KIND: &str = "chat_invite";
const ROOM_KIND: &str = "chat_room";

/// The messenger's store for one realm.
#[derive(Clone, Debug)]
pub struct NexChat {
    db: NexDb,
    site: Arc<str>,
}

fn hex(account: u128) -> String {
    format!("{account:032x}")
}

fn account_id(account: u128) -> nex_db::AccountId {
    nex_db::AccountId::from_bytes(account.to_be_bytes())
}

impl NexChat {
    /// The store for `realm` (`users`, nex-db's default, or a realm of its
    /// own).
    #[must_use]
    pub fn new(db: NexDb, realm: &str) -> NexChat {
        let site = if realm == super::DEFAULT_REALM {
            "wasp-chat".to_owned()
        } else {
            format!("wasp-chat-{realm}")
        };
        NexChat {
            db,
            site: Arc::from(site),
        }
    }

    fn content(&self) -> nex_db::Content<'_> {
        self.db.db().content()
    }

    /// The published entry at `path`, when there is one.
    fn entry(&self, path: &str) -> Result<Option<(nex_db::EntityId, nex_db::Entry)>, StoreError> {
        let content = self.content();
        let Some(route) = content.resolve(&self.site, path).map_err(nex)? else {
            return Ok(None);
        };
        let rid = route.entity();
        Ok(content.get(rid).map_err(nex)?.map(|e| (rid, e)))
    }

    fn text(entry: &nex_db::Entry, name: &str) -> String {
        entry
            .field(name)
            .and_then(nex_db::Value::as_text)
            .unwrap_or("")
            .to_owned()
    }

    fn number(entry: &nex_db::Entry, name: &str) -> u64 {
        Self::text(entry, name).parse().unwrap_or(0)
    }

    /// A new entity at `path`: `false` when the path is taken.
    fn put(
        &self,
        kind: &str,
        path: &str,
        author: Option<u128>,
        fields: &[(&str, String)],
    ) -> Result<bool, StoreError> {
        let mut entity = nex_db::Entity::new(kind)
            .site(self.site.as_ref())
            .path(path);
        if let Some(a) = author {
            entity = entity.author(account_id(a));
        }
        for (k, v) in fields {
            entity = entity.field(*k, v.as_str());
        }
        match self.content().put(entity) {
            Ok(_) => Ok(true),
            Err(nex_db::Error::AlreadyExists { .. }) => Ok(false),
            Err(e) => Err(nex(e)),
        }
    }

    /// Makes the entity at `path` hold exactly `fields`, keeping no
    /// history: nex-db keeps a revision of every changed publish, so a
    /// record changed again and again (a group's members, a read marker, a
    /// conversation's last number) is never published over. The old entity
    /// is deleted, with its revisions, and the new one put, in one commit.
    /// Nothing is written when the entity already holds `fields`.
    fn upsert(
        &self,
        kind: &str,
        path: &str,
        author: Option<u128>,
        fields: &[(&str, String)],
    ) -> Result<(), StoreError> {
        let mut entity = nex_db::Entity::new(kind)
            .site(self.site.as_ref())
            .path(path);
        if let Some(a) = author {
            entity = entity.author(account_id(a));
        }
        for (k, v) in fields {
            entity = entity.field(*k, v.as_str());
        }
        // Another writer of the same path may come between the read and
        // the commit: read again and retry.
        for _ in 0..4 {
            let result = match self.entry(path)? {
                Some((_, e)) if fields.iter().all(|(k, v)| Self::text(&e, k) == *v) => {
                    return Ok(());
                }
                Some((rid, _)) => self
                    .db
                    .db()
                    .commit(|tx| {
                        let mut c = tx.content();
                        c.delete(rid)?;
                        c.put(entity.clone())
                    })
                    .map(|_| ()),
                None => self.content().put(entity.clone()).map(|_| ()),
            };
            match result {
                Ok(()) => return Ok(()),
                Err(
                    nex_db::Error::AlreadyExists { .. }
                    | nex_db::Error::Conflict
                    | nex_db::Error::Invalid { .. },
                ) => {}
                Err(e) => return Err(nex(e)),
            }
        }
        Err(StoreError::new(
            crate::content::StoreErrorKind::Conflict,
            "another writer kept changing the same record",
        ))
    }

    fn remove(&self, path: &str) -> Result<(), StoreError> {
        if let Some((rid, _)) = self.entry(path)? {
            self.content().delete(rid).map_err(nex)?;
        }
        Ok(())
    }
}

impl ChatStore for NexChat {
    fn conversation(&self, id: &ConvId) -> Result<Option<Conversation>, StoreError> {
        let Some((_, e)) = self.entry(&format!("/c/{id}"))? else {
            return Ok(None);
        };
        let members = Self::text(&e, "members")
            .split_whitespace()
            .filter_map(|h| u128::from_str_radix(h, 16).ok())
            .collect();
        Ok(Some(Conversation {
            id: *id,
            kind: crate::chat::store::ConvKind::from_name(&Self::text(&e, "kind")),
            members,
            last: Self::number(&e, "last"),
            at_ms: Self::number(&e, "at"),
        }))
    }

    fn create(&self, c: &Conversation) -> Result<bool, StoreError> {
        let members = c
            .members
            .iter()
            .map(|m| hex(*m))
            .collect::<Vec<_>>()
            .join(" ");
        self.put(
            CONV_KIND,
            &format!("/c/{}", c.id),
            None,
            &[
                ("kind", c.kind.as_str().to_owned()),
                ("members", members),
                ("last", "0".to_owned()),
                ("at", "0".to_owned()),
            ],
        )
    }

    fn index(&self, account: u128, id: &ConvId) -> Result<(), StoreError> {
        // Published again, the entry moves to the front of the listing.
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        self.upsert(
            MEMBER_KIND,
            &format!("/a/{}/{id}", hex(account)),
            Some(account),
            &[("conversation", id.to_string()), ("at", at.to_string())],
        )
    }

    fn conversations_of(
        &self,
        account: u128,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<ConvId>, Option<String>), StoreError> {
        let content = self.content();
        let page = match after {
            None => content
                .list(
                    &nex_db::Listing::latest(MEMBER_KIND)
                        .updated()
                        .site(self.site.as_ref())
                        .by_author(account_id(account))
                        .limit(limit),
                )
                .map_err(nex)?,
            Some(text) => {
                let cursor = nex_db::Cursor::parse(text)
                    .map_err(|_| StoreError::invalid("not a place in the list"))?;
                content.next_page(&cursor).map_err(nex)?
            }
        };
        // Only this account's entries, whatever a cursor says.
        let prefix = format!("/a/{}/", hex(account));
        let ids = page
            .items()
            .iter()
            .filter_map(|item| {
                item.route()
                    .filter(|(site, _)| *site == &*self.site)
                    .and_then(|(_, p)| p.strip_prefix(&prefix))
                    .and_then(|h| h.parse::<ConvId>().ok())
            })
            .collect();
        Ok((ids, page.next().map(ToString::to_string)))
    }

    fn append(&self, m: &Message) -> Result<bool, StoreError> {
        self.put(
            MESSAGE_KIND,
            &format!("/c/{}/m/{:020}", m.conversation, m.number),
            Some(m.author),
            &[
                ("author", hex(m.author)),
                ("at", m.at_ms.to_string()),
                ("body", crate::chat::spans_json(&m.body)),
            ],
        )
    }

    fn set_last(&self, id: &ConvId, number: u64, at_ms: u64) -> Result<(), StoreError> {
        let Some((_, e)) = self.entry(&format!("/c/{id}"))? else {
            return Ok(());
        };
        if number <= Self::number(&e, "last") {
            return Ok(());
        }
        self.upsert(
            CONV_KIND,
            &format!("/c/{id}"),
            None,
            &[
                ("kind", Self::text(&e, "kind")),
                ("members", Self::text(&e, "members")),
                ("last", number.to_string()),
                ("at", at_ms.to_string()),
            ],
        )
    }

    fn message(&self, id: &ConvId, number: u64) -> Result<Option<Message>, StoreError> {
        let Some((_, e)) = self.entry(&format!("/c/{id}/m/{number:020}"))? else {
            return Ok(None);
        };
        let body = crate::chat::spans_from_json(&Self::text(&e, "body")).unwrap_or_default();
        Ok(Some(Message {
            conversation: *id,
            number,
            author: u128::from_str_radix(&Self::text(&e, "author"), 16).unwrap_or(0),
            at_ms: Self::number(&e, "at"),
            body,
        }))
    }

    fn read_marker(&self, id: &ConvId, account: u128) -> Result<u64, StoreError> {
        Ok(self
            .entry(&format!("/c/{id}/r/{}", hex(account)))?
            .map_or(0, |(_, e)| Self::number(&e, "n")))
    }

    fn set_read(&self, id: &ConvId, account: u128, number: u64) -> Result<(), StoreError> {
        self.upsert(
            READ_KIND,
            &format!("/c/{id}/r/{}", hex(account)),
            Some(account),
            &[("n", number.to_string())],
        )
    }

    fn muted(&self, id: &ConvId, account: u128) -> Result<bool, StoreError> {
        Ok(self
            .entry(&format!("/c/{id}/mute/{}", hex(account)))?
            .is_some())
    }

    fn set_muted(&self, id: &ConvId, account: u128, on: bool) -> Result<(), StoreError> {
        let path = format!("/c/{id}/mute/{}", hex(account));
        if on {
            self.upsert(MUTE_KIND, &path, Some(account), &[("on", "1".to_owned())])
        } else {
            self.remove(&path)
        }
    }

    fn blocked(&self, who: u128, whom: u128) -> Result<bool, StoreError> {
        Ok(self
            .entry(&format!("/b/{}/{}", hex(who), hex(whom)))?
            .is_some())
    }

    fn set_blocked(&self, who: u128, whom: u128, on: bool) -> Result<(), StoreError> {
        let path = format!("/b/{}/{}", hex(who), hex(whom));
        if on {
            self.upsert(BLOCK_KIND, &path, Some(who), &[("on", "1".to_owned())])
        } else {
            self.remove(&path)
        }
    }

    fn blocks_of(&self, who: u128) -> Result<Vec<u128>, StoreError> {
        let content = self.content();
        let mut page = content
            .list(
                &nex_db::Listing::latest(BLOCK_KIND)
                    .site(self.site.as_ref())
                    .by_author(account_id(who))
                    .limit(1000),
            )
            .map_err(nex)?;
        let prefix = format!("/b/{}/", hex(who));
        let mut out = Vec::new();
        loop {
            for item in page.items() {
                if let Some(a) = item
                    .route()
                    .and_then(|(_, p)| p.strip_prefix(&prefix))
                    .and_then(|h| u128::from_str_radix(h, 16).ok())
                {
                    out.push(a);
                }
            }
            if out.len() >= 10_000 {
                break;
            }
            match page.next() {
                Some(c) => page = content.next_page(c).map_err(nex)?,
                None => break,
            }
        }
        Ok(out)
    }

    fn usage(&self, account: u128) -> Result<Usage, StoreError> {
        Ok(self
            .entry(&format!("/q/{}", hex(account)))?
            .map(|(_, e)| Usage {
                started: Self::number(&e, "started"),
                messages: Self::number(&e, "messages"),
            })
            .unwrap_or_default())
    }

    fn set_usage(&self, account: u128, usage: Usage) -> Result<(), StoreError> {
        self.upsert(
            USAGE_KIND,
            &format!("/q/{}", hex(account)),
            Some(account),
            &[
                ("started", usage.started.to_string()),
                ("messages", usage.messages.to_string()),
            ],
        )
    }

    fn group(&self, id: &ConvId) -> Result<Option<Group>, StoreError> {
        Ok(self
            .entry(&format!("/c/{id}/g"))?
            .and_then(|(_, e)| Group::from_json(&Self::text(&e, "record"))))
    }

    fn put_group(&self, id: &ConvId, group: &Group) -> Result<(), StoreError> {
        self.upsert(
            GROUP_KIND,
            &format!("/c/{id}/g"),
            None,
            &[("record", group.to_json())],
        )
    }

    fn unindex(&self, account: u128, id: &ConvId) -> Result<(), StoreError> {
        self.remove(&format!("/a/{}/{id}", hex(account)))
    }

    fn set_invited(&self, account: u128, id: &ConvId, on: bool) -> Result<(), StoreError> {
        let path = format!("/i/{}/{id}", hex(account));
        if on {
            self.upsert(
                INVITE_KIND,
                &path,
                Some(account),
                &[("conversation", id.to_string())],
            )
        } else {
            self.remove(&path)
        }
    }

    fn invites_of(&self, account: u128) -> Result<Vec<ConvId>, StoreError> {
        let page = self
            .content()
            .list(
                &nex_db::Listing::latest(INVITE_KIND)
                    .site(self.site.as_ref())
                    .by_author(account_id(account))
                    .limit(1000),
            )
            .map_err(nex)?;
        let prefix = format!("/i/{}/", hex(account));
        Ok(page
            .items()
            .iter()
            .filter_map(|item| {
                item.route()
                    .and_then(|(_, p)| p.strip_prefix(&prefix))
                    .and_then(|h| h.parse::<ConvId>().ok())
            })
            .collect())
    }

    fn delete_conversation(&self, id: &ConvId) -> Result<(), StoreError> {
        self.remove(&format!("/c/{id}"))?;
        self.remove(&format!("/c/{id}/g"))?;
        self.remove(&format!("/c/{id}/room"))
    }

    fn forget_member(&self, id: &ConvId, account: u128) -> Result<(), StoreError> {
        self.remove(&format!("/c/{id}/r/{}", hex(account)))?;
        self.remove(&format!("/c/{id}/mute/{}", hex(account)))
    }

    fn room(&self, id: &ConvId) -> Result<Option<Room>, StoreError> {
        Ok(self
            .entry(&format!("/c/{id}/room"))?
            .and_then(|(_, e)| Room::from_json(&Self::text(&e, "record"))))
    }

    fn put_room(&self, id: &ConvId, room: &Room) -> Result<(), StoreError> {
        self.upsert(
            ROOM_KIND,
            &format!("/c/{id}/room"),
            None,
            &[("record", room.to_json())],
        )
    }

    fn rooms(&self) -> Result<Vec<(ConvId, Room)>, StoreError> {
        let content = self.content();
        let mut page = content
            .list(
                &nex_db::Listing::latest(ROOM_KIND)
                    .site(self.site.as_ref())
                    .limit(1000),
            )
            .map_err(nex)?;
        let mut out = Vec::new();
        loop {
            for item in page.items() {
                let id = item
                    .route()
                    .and_then(|(_, p)| p.strip_prefix("/c/"))
                    .and_then(|p| p.strip_suffix("/room"))
                    .and_then(|h| h.parse::<ConvId>().ok());
                let record = item
                    .field("record")
                    .and_then(nex_db::Value::as_text)
                    .and_then(Room::from_json);
                if let (Some(id), Some(r)) = (id, record) {
                    out.push((id, r));
                }
            }
            if out.len() >= 1_000_000 {
                break;
            }
            match page.next() {
                Some(c) => page = content.next_page(c).map_err(nex)?,
                None => break,
            }
        }
        Ok(out)
    }

    fn delete_messages(&self, id: &ConvId, from: u64, to: u64) -> Result<(), StoreError> {
        for n in from..=to {
            self.remove(&format!("/c/{id}/m/{n:020}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::{Group, GroupMember, GroupRole, GroupSettings};

    fn group(name: &str, banned: Vec<u128>) -> Group {
        Group {
            name: name.to_owned(),
            members: vec![GroupMember {
                account: 1,
                role: GroupRole::Owner,
                joined: 0,
            }],
            invited: Vec::new(),
            banned,
            settings: GroupSettings {
                cap: 50,
                advanced: false,
                history: 0,
                before_join: false,
                members_invite: false,
            },
        }
    }

    #[test]
    fn records_are_overwritten_without_history() {
        let db = NexDb::open_temporary().expect("db");
        let chat = NexChat::new(db, super::super::DEFAULT_REALM);
        let id = ConvId([7; 16]);
        let revisions = |chat: &NexChat, path: &str| {
            let (rid, _) = chat.entry(path).expect("read").expect("there");
            chat.content().revisions(rid).expect("revisions").len()
        };
        // A record changed again and again keeps one revision, never a
        // history that grows with each change.
        for n in 0..20u128 {
            chat.put_group(&id, &group("Team", (0..n).collect()))
                .expect("put");
        }
        let path = format!("/c/{id}/g");
        assert_eq!(revisions(&chat, &path), 1);
        assert_eq!(
            chat.group(&id).expect("read").map(|g| g.banned.len()),
            Some(19)
        );
        // Writing what is there already writes nothing.
        let (before, _) = chat.entry(&path).expect("read").expect("there");
        chat.put_group(&id, &group("Team", (0..19).collect()))
            .expect("put");
        let (after, _) = chat.entry(&path).expect("read").expect("there");
        assert_eq!(before, after, "the same entity, untouched");
        // So does every hot record: a read marker, a usage count.
        for n in 1..=20 {
            chat.set_read(&id, 2, n).expect("read marker");
            chat.set_usage(
                2,
                crate::chat::Usage {
                    started: 1,
                    messages: n,
                },
            )
            .expect("usage");
        }
        assert_eq!(revisions(&chat, &format!("/c/{id}/r/{:032x}", 2)), 1);
        assert_eq!(revisions(&chat, &format!("/q/{:032x}", 2)), 1);
        assert_eq!(chat.read_marker(&id, 2).expect("read"), 20);
        // What a leaver kept goes.
        chat.forget_member(&id, 2).expect("forget");
        assert_eq!(chat.read_marker(&id, 2).expect("read"), 0);
    }
}
