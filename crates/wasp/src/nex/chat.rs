//! The messenger's store on nex-db (G-83): one content site per realm
//! (`wasp-chat`, or `wasp-chat-<realm>`), an entity per conversation, per
//! message, per read marker, per mute and per block, and an index entry per
//! member authored by its account.

use std::sync::Arc;

use nex_db::Patch;

use super::{NexDb, StoreError, nex};
use crate::chat::store::{ChatStore, Conversation};
use crate::chat::{ConvId, Message};

const CONV_KIND: &str = "chat_conv";
const MEMBER_KIND: &str = "chat_member";
const MESSAGE_KIND: &str = "chat_msg";
const READ_KIND: &str = "chat_read";
const MUTE_KIND: &str = "chat_mute";
const BLOCK_KIND: &str = "chat_block";

/// The most conversations an account's list reads.
const MAX_CONVERSATIONS: usize = 10_000;

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

    /// Writes `fields` to the entity at `path`, making it when there is none.
    fn upsert(
        &self,
        kind: &str,
        path: &str,
        author: Option<u128>,
        fields: &[(&str, String)],
    ) -> Result<(), StoreError> {
        let content = self.content();
        if let Some((rid, _)) = self.entry(path)? {
            let patch = fields
                .iter()
                .fold(Patch::new(), |p, (k, v)| p.set(*k, v.as_str()));
            content.save_draft(rid, patch).map_err(nex)?;
            content.publish(rid).map_err(nex)?;
            return Ok(());
        }
        let mut entity = nex_db::Entity::new(kind)
            .site(self.site.as_ref())
            .path(path);
        if let Some(a) = author {
            entity = entity.author(account_id(a));
        }
        for (k, v) in fields {
            entity = entity.field(*k, v.as_str());
        }
        match content.put(entity) {
            Ok(_) | Err(nex_db::Error::AlreadyExists { .. }) => Ok(()),
            Err(e) => Err(nex(e)),
        }
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
        Ok(Some(Conversation { id: *id, members }))
    }

    fn create(&self, c: &Conversation) -> Result<(), StoreError> {
        if self.entry(&format!("/c/{}", c.id))?.is_some() {
            return Ok(());
        }
        let members = c
            .members
            .iter()
            .map(|m| hex(*m))
            .collect::<Vec<_>>()
            .join(" ");
        self.upsert(
            CONV_KIND,
            &format!("/c/{}", c.id),
            None,
            &[("members", members), ("last", "0".to_owned())],
        )?;
        for m in &c.members {
            self.upsert(
                MEMBER_KIND,
                &format!("/a/{}/{}", hex(*m), c.id),
                Some(*m),
                &[("conversation", c.id.to_string())],
            )?;
        }
        Ok(())
    }

    fn conversations_of(&self, account: u128) -> Result<Vec<ConvId>, StoreError> {
        let content = self.content();
        let mut page = content
            .list(
                &nex_db::Listing::latest(MEMBER_KIND)
                    .site(self.site.as_ref())
                    .by_author(account_id(account))
                    .limit(1000),
            )
            .map_err(nex)?;
        let prefix = format!("/a/{}/", hex(account));
        let mut out = Vec::new();
        loop {
            for item in page.items() {
                if let Some(id) = item
                    .route()
                    .and_then(|(_, p)| p.strip_prefix(&prefix))
                    .and_then(|h| h.parse::<ConvId>().ok())
                {
                    out.push(id);
                }
            }
            if out.len() >= MAX_CONVERSATIONS {
                break;
            }
            match page.next() {
                Some(c) => page = content.next_page(c).map_err(nex)?,
                None => break,
            }
        }
        Ok(out)
    }

    fn last_number(&self, id: &ConvId) -> Result<u64, StoreError> {
        Ok(self
            .entry(&format!("/c/{id}"))?
            .and_then(|(_, e)| Self::text(&e, "last").parse().ok())
            .unwrap_or(0))
    }

    fn append(&self, m: &Message) -> Result<(), StoreError> {
        let id = m.conversation;
        self.upsert(
            MESSAGE_KIND,
            &format!("/c/{id}/m/{:020}", m.number),
            Some(m.author),
            &[
                ("author", hex(m.author)),
                ("at", m.at_ms.to_string()),
                ("body", crate::chat::spans_json(&m.body)),
            ],
        )?;
        self.upsert(
            CONV_KIND,
            &format!("/c/{id}"),
            None,
            &[("last", m.number.to_string())],
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
            at_ms: Self::text(&e, "at").parse().unwrap_or(0),
            body,
        }))
    }

    fn read_marker(&self, id: &ConvId, account: u128) -> Result<u64, StoreError> {
        Ok(self
            .entry(&format!("/c/{id}/r/{}", hex(account)))?
            .and_then(|(_, e)| Self::text(&e, "n").parse().ok())
            .unwrap_or(0))
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
}
