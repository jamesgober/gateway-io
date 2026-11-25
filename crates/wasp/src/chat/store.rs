//! Where the messenger keeps its conversations: a backend-neutral trait, so
//! the messenger is tied to no one database (G-83), and a store in memory.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

use crate::content::StoreError;

use super::{ConvId, Message, Span};

/// One conversation: its id and its members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conversation {
    /// Its id.
    pub id: ConvId,
    /// Its members' accounts, in order.
    pub members: Vec<u128>,
}

/// The messenger's storage. Every call is one account's or one
/// conversation's; numbering a message is the caller's job, under the
/// conversation's lock, so `append` is told the number to write.
pub trait ChatStore: Send + Sync + 'static {
    /// The conversation `id`, when there is one.
    fn conversation(&self, id: &ConvId) -> Result<Option<Conversation>, StoreError>;
    /// Keeps `c` (again: nothing changes when it is there already).
    fn create(&self, c: &Conversation) -> Result<(), StoreError>;
    /// The conversations `account` is a member of.
    fn conversations_of(&self, account: u128) -> Result<Vec<ConvId>, StoreError>;
    /// The number of the conversation's last message; 0 for none.
    fn last_number(&self, id: &ConvId) -> Result<u64, StoreError>;
    /// Keeps `message` (its number is the last one plus one).
    fn append(&self, message: &Message) -> Result<(), StoreError>;
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
    read: HashMap<(ConvId, u128), u64>,
    muted: BTreeSet<(ConvId, u128)>,
    blocked: BTreeSet<(u128, u128)>,
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

    fn create(&self, c: &Conversation) -> Result<(), StoreError> {
        self.with(|i| {
            i.conversations.entry(c.id).or_insert_with(|| c.clone());
        });
        Ok(())
    }

    fn conversations_of(&self, account: u128) -> Result<Vec<ConvId>, StoreError> {
        Ok(self.with(|i| {
            i.conversations
                .values()
                .filter(|c| c.members.contains(&account))
                .map(|c| c.id)
                .collect()
        }))
    }

    fn last_number(&self, id: &ConvId) -> Result<u64, StoreError> {
        Ok(self.with(|i| {
            i.messages
                .get(id)
                .and_then(|m| m.keys().next_back().copied())
                .unwrap_or(0)
        }))
    }

    fn append(&self, message: &Message) -> Result<(), StoreError> {
        self.with(|i| {
            i.messages
                .entry(message.conversation)
                .or_default()
                .insert(message.number, message.clone());
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
}

/// `body` as the JSON a store keeps it in.
#[must_use]
pub fn body_json(body: &[Span]) -> String {
    super::spans_json(body)
}
