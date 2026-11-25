//! Where the messenger keeps its conversations: a backend-neutral trait, so
//! the messenger is tied to no one database (G-83), and a store in memory.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

use crate::content::StoreError;

use super::{ConvId, Group, Message, Span};

/// One conversation: its id, its members, and its last message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conversation {
    /// Its id.
    pub id: ConvId,
    /// Whether it is a group (its members are in its group record).
    pub group: bool,
    /// A direct conversation's two members, in order; empty for a group.
    pub members: Vec<u128>,
    /// The number of its last message; 0 for none.
    pub last: u64,
    /// When its last message was sent (ms since 1970); 0 for none.
    pub at_ms: u64,
}

/// What one account has used of its quotas.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Conversations it started.
    pub started: u64,
    /// Messages it sent.
    pub messages: u64,
}

/// The messenger's storage. Every call is one account's or one
/// conversation's. Numbering is the caller's: `append` is told the number
/// and keeps the message only while that number is free, so a number is
/// never written twice, even by two processes.
pub trait ChatStore: Send + Sync + 'static {
    /// The conversation `id`, when there is one.
    fn conversation(&self, id: &ConvId) -> Result<Option<Conversation>, StoreError>;
    /// Keeps `c` when there is no conversation with its id yet: `false`
    /// when there was one (nothing changes then).
    fn create(&self, c: &Conversation) -> Result<bool, StoreError>;
    /// Puts conversation `id` at the front of `account`'s list, adding it
    /// when it is not there.
    fn index(&self, account: u128, id: &ConvId) -> Result<(), StoreError>;
    /// One page of `account`'s list, the most recent first, from `after`
    /// (what the page before gave): the ids, and where the next page starts.
    ///
    /// # Errors
    ///
    /// [`StoreErrorKind::Invalid`](crate::content::StoreErrorKind) when
    /// `after` is not one.
    fn conversations_of(
        &self,
        account: u128,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<ConvId>, Option<String>), StoreError>;
    /// Keeps `message` when its number is free in its conversation: `false`
    /// when the number is taken (nothing is written then).
    fn append(&self, message: &Message) -> Result<bool, StoreError>;
    /// The conversation's last message is `number`, sent at `at_ms`; a
    /// lower number than the one kept changes nothing.
    fn set_last(&self, id: &ConvId, number: u64, at_ms: u64) -> Result<(), StoreError>;
    /// Message `number` of the conversation.
    fn message(&self, id: &ConvId, number: u64) -> Result<Option<Message>, StoreError>;
    /// The last message `account` read there; 0 for none.
    fn read_marker(&self, id: &ConvId, account: u128) -> Result<u64, StoreError>;
    /// `account` read up to `number` there.
    fn set_read(&self, id: &ConvId, account: u128, number: u64) -> Result<(), StoreError>;
    /// Whether `account` muted the conversation.
    fn muted(&self, id: &ConvId, account: u128) -> Result<bool, StoreError>;
    /// Mutes or unmutes it for `account`.
    fn set_muted(&self, id: &ConvId, account: u128, on: bool) -> Result<(), StoreError>;
    /// Whether `who` blocked `whom`.
    fn blocked(&self, who: u128, whom: u128) -> Result<bool, StoreError>;
    /// `who` blocks or unblocks `whom`.
    fn set_blocked(&self, who: u128, whom: u128, on: bool) -> Result<(), StoreError>;
    /// What `account` has used of its quotas.
    fn usage(&self, account: u128) -> Result<Usage, StoreError>;
    /// Keeps what `account` has used.
    fn set_usage(&self, account: u128, usage: Usage) -> Result<(), StoreError>;
    /// The record of group `id`, when there is one.
    fn group(&self, id: &ConvId) -> Result<Option<Group>, StoreError>;
    /// Keeps group `id`'s record.
    fn put_group(&self, id: &ConvId, group: &Group) -> Result<(), StoreError>;
    /// Takes conversation `id` out of `account`'s list.
    fn unindex(&self, account: u128, id: &ConvId) -> Result<(), StoreError>;
    /// Notes, or forgets, that `account` holds an invite to group `id`.
    fn set_invited(&self, account: u128, id: &ConvId, on: bool) -> Result<(), StoreError>;
    /// The groups `account` holds invites to (at most 1,000).
    fn invites_of(&self, account: u128) -> Result<Vec<ConvId>, StoreError>;
    /// Deletes conversation `id`: its record, its group record, and its
    /// messages up to `last`.
    fn delete_conversation(&self, id: &ConvId, last: u64) -> Result<(), StoreError>;
}

/// Everything in memory: gone at a restart. For tests and trials.
#[derive(Debug, Default)]
pub struct MemoryChat {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    conversations: HashMap<ConvId, Conversation>,
    messages: HashMap<ConvId, BTreeMap<u64, Message>>,
    /// Each account's list: conversation and when it last moved up.
    lists: HashMap<u128, HashMap<ConvId, u64>>,
    tick: u64,
    read: HashMap<(ConvId, u128), u64>,
    muted: BTreeSet<(ConvId, u128)>,
    blocked: BTreeSet<(u128, u128)>,
    usage: HashMap<u128, Usage>,
    groups: HashMap<ConvId, Group>,
    invites: BTreeSet<(u128, ConvId)>,
}

impl MemoryChat {
    /// An empty store.
    #[must_use]
    pub fn new() -> MemoryChat {
        MemoryChat::default()
    }

    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut inner)
    }
}

impl ChatStore for MemoryChat {
    fn conversation(&self, id: &ConvId) -> Result<Option<Conversation>, StoreError> {
        Ok(self.with(|i| i.conversations.get(id).cloned()))
    }

    fn create(&self, c: &Conversation) -> Result<bool, StoreError> {
        Ok(self.with(|i| {
            if i.conversations.contains_key(&c.id) {
                return false;
            }
            i.conversations.insert(c.id, c.clone());
            true
        }))
    }

    fn index(&self, account: u128, id: &ConvId) -> Result<(), StoreError> {
        self.with(|i| {
            i.tick += 1;
            let tick = i.tick;
            i.lists.entry(account).or_default().insert(*id, tick);
        });
        Ok(())
    }

    fn conversations_of(
        &self,
        account: u128,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<ConvId>, Option<String>), StoreError> {
        let from = match after {
            None => 0,
            Some(a) => a
                .parse::<usize>()
                .map_err(|_| StoreError::invalid("not a place in the list"))?,
        };
        Ok(self.with(|i| {
            let mut all: Vec<(u64, ConvId)> = i
                .lists
                .get(&account)
                .map(|l| l.iter().map(|(id, t)| (*t, *id)).collect())
                .unwrap_or_default();
            all.sort_by(|a, b| b.cmp(a));
            let page: Vec<ConvId> = all
                .iter()
                .skip(from)
                .take(limit)
                .map(|(_, id)| *id)
                .collect();
            let next = (from + page.len() < all.len()).then(|| (from + page.len()).to_string());
            (page, next)
        }))
    }

    fn append(&self, message: &Message) -> Result<bool, StoreError> {
        Ok(self.with(|i| {
            let m = i.messages.entry(message.conversation).or_default();
            if m.contains_key(&message.number) {
                return false;
            }
            m.insert(message.number, message.clone());
            true
        }))
    }

    fn set_last(&self, id: &ConvId, number: u64, at_ms: u64) -> Result<(), StoreError> {
        self.with(|i| {
            if let Some(c) = i.conversations.get_mut(id)
                && number > c.last
            {
                c.last = number;
                c.at_ms = at_ms;
            }
        });
        Ok(())
    }

    fn message(&self, id: &ConvId, number: u64) -> Result<Option<Message>, StoreError> {
        Ok(self.with(|i| i.messages.get(id).and_then(|m| m.get(&number)).cloned()))
    }

    fn read_marker(&self, id: &ConvId, account: u128) -> Result<u64, StoreError> {
        Ok(self.with(|i| i.read.get(&(*id, account)).copied().unwrap_or(0)))
    }

    fn set_read(&self, id: &ConvId, account: u128, number: u64) -> Result<(), StoreError> {
        self.with(|i| {
            i.read.insert((*id, account), number);
        });
        Ok(())
    }

    fn muted(&self, id: &ConvId, account: u128) -> Result<bool, StoreError> {
        Ok(self.with(|i| i.muted.contains(&(*id, account))))
    }

    fn set_muted(&self, id: &ConvId, account: u128, on: bool) -> Result<(), StoreError> {
        self.with(|i| {
            if on {
                i.muted.insert((*id, account));
            } else {
                i.muted.remove(&(*id, account));
            }
        });
        Ok(())
    }

    fn blocked(&self, who: u128, whom: u128) -> Result<bool, StoreError> {
        Ok(self.with(|i| i.blocked.contains(&(who, whom))))
    }

    fn set_blocked(&self, who: u128, whom: u128, on: bool) -> Result<(), StoreError> {
        self.with(|i| {
            if on {
                i.blocked.insert((who, whom));
            } else {
                i.blocked.remove(&(who, whom));
            }
        });
        Ok(())
    }

    fn usage(&self, account: u128) -> Result<Usage, StoreError> {
        Ok(self.with(|i| i.usage.get(&account).copied().unwrap_or_default()))
    }

    fn set_usage(&self, account: u128, usage: Usage) -> Result<(), StoreError> {
        self.with(|i| {
            i.usage.insert(account, usage);
        });
        Ok(())
    }

    fn group(&self, id: &ConvId) -> Result<Option<Group>, StoreError> {
        Ok(self.with(|i| i.groups.get(id).cloned()))
    }

    fn put_group(&self, id: &ConvId, group: &Group) -> Result<(), StoreError> {
        self.with(|i| {
            i.groups.insert(*id, group.clone());
        });
        Ok(())
    }

    fn unindex(&self, account: u128, id: &ConvId) -> Result<(), StoreError> {
        self.with(|i| {
            if let Some(l) = i.lists.get_mut(&account) {
                l.remove(id);
            }
        });
        Ok(())
    }

    fn set_invited(&self, account: u128, id: &ConvId, on: bool) -> Result<(), StoreError> {
        self.with(|i| {
            if on {
                i.invites.insert((account, *id));
            } else {
                i.invites.remove(&(account, *id));
            }
        });
        Ok(())
    }

    fn invites_of(&self, account: u128) -> Result<Vec<ConvId>, StoreError> {
        Ok(self.with(|i| {
            i.invites
                .iter()
                .filter(|(a, _)| *a == account)
                .map(|(_, id)| *id)
                .take(1000)
                .collect()
        }))
    }

    fn delete_conversation(&self, id: &ConvId, _last: u64) -> Result<(), StoreError> {
        self.with(|i| {
            i.conversations.remove(id);
            i.messages.remove(id);
            i.groups.remove(id);
            for l in i.lists.values_mut() {
                l.remove(id);
            }
        });
        Ok(())
    }
}

/// `body` as the JSON a store keeps it in.
#[must_use]
pub fn body_json(body: &[Span]) -> String {
    super::spans_json(body)
}
