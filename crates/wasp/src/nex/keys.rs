//! API keys: credentials for programs, made and revoked by an account on its
//! security page.
//!
//! nex-db keeps each key as a keyed digest with its account, id, scopes and
//! dates, answers whether a key's text counts, and lists an account's keys
//! (`api_keys`). wasp's account directory keeps only what nex-db does not:
//! each key's label, at `/<account>/k/<key id>`, never the key.

use std::time::{Duration, SystemTime};

use wasp_core::{PermSet, SessionId, UserId};

use super::{NexAuth, StoreError, account_of, hex_of, nex};

/// The permission only a session cookie carries: the account pages, the
/// admin pages and signing out need it, so no API key ever reaches them.
pub const SESSION: PermSet = PermSet(1 << 8);

/// A scope an API key may have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    /// Its name (`account:read`).
    pub name: &'static str,
    /// What it allows, for the form.
    pub label: &'static str,
    bit: u8,
    perms: PermSet,
}

/// Every scope a key may have.
pub const SCOPES: &[Scope] = &[
    Scope {
        name: "account:read",
        label: "Read the account: who it is and its roles",
        bit: 1,
        perms: crate::site_nex::MEMBER,
    },
    Scope {
        name: "chat",
        label: "Read and send the account's messages",
        bit: 2,
        perms: crate::site_nex::MEMBER,
    },
];

/// A set of scopes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scopes(u8);

impl Scopes {
    /// The scopes named in `names`; an unknown name is refused.
    pub fn parse<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Scopes, String> {
        let mut bits = 0;
        for name in names {
            let scope = SCOPES
                .iter()
                .find(|s| s.name == name)
                .ok_or_else(|| format!("There is no scope `{name}`."))?;
            bits |= scope.bit;
        }
        Ok(Scopes(bits))
    }

    /// The scopes a stored key has. A name no longer known grants nothing.
    #[must_use]
    pub fn of_stored(names: &[String]) -> Scopes {
        Scopes(
            SCOPES
                .iter()
                .filter(|s| names.iter().any(|n| n == s.name))
                .fold(0, |bits, s| bits | s.bit),
        )
    }

    /// Whether the set has the scope `name`.
    #[must_use]
    pub fn has(self, name: &str) -> bool {
        SCOPES.iter().any(|s| s.name == name && self.0 & s.bit != 0)
    }

    /// The names in the set, in [`SCOPES`] order.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        SCOPES
            .iter()
            .filter(|s| self.0 & s.bit != 0)
            .map(|s| s.name)
            .collect()
    }

    /// The permissions the set lets through: a key acts with its account's
    /// roles cut down to these.
    #[must_use]
    pub fn perms(self) -> PermSet {
        PermSet(
            SCOPES
                .iter()
                .filter(|s| self.0 & s.bit != 0)
                .fold(0, |bits, s| bits | s.perms.0),
        )
    }
}

/// How long a new key lasts, in days: the choices on the form.
pub const EXPIRIES: &[u32] = &[30, 90, 365];

/// The expiry the form starts at, in days.
pub const DEFAULT_EXPIRY: u32 = 90;

/// The most keys one account holds, expired ones counted until revoked.
pub const MAX_KEYS: usize = 20;

/// The longest label, in characters.
pub const MAX_LABEL: usize = 64;

/// The directory's key records.
const KEY_KIND: &str = "api_key";

/// One key of an account, for its page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRow {
    /// nex-db's id for it (32 hex digits), for the revoke button.
    pub id: String,
    /// Its label.
    pub label: String,
    /// Its scopes.
    pub scopes: Vec<String>,
    /// When it was made.
    pub created: SystemTime,
    /// When it stops working.
    pub expires: SystemTime,
}

/// A key just made: its row, and its text, shown once.
pub struct NewKey {
    /// The key's row.
    pub row: KeyRow,
    /// The key's text.
    pub text: String,
}

impl std::fmt::Debug for NewKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewKey")
            .field("row", &self.row)
            .finish_non_exhaustive()
    }
}

impl Drop for NewKey {
    fn drop(&mut self) {
        // Not a guarantee (the page held a copy), only no copy kept here.
        let mut bytes = std::mem::take(&mut self.text).into_bytes();
        bytes.iter_mut().for_each(|b| *b = 0);
        std::hint::black_box(&bytes);
    }
}

/// The id a request signed in with key `id` carries: the bouncer charges
/// it, and the recheck cache keeps the account's roles under it. Apart from
/// every session's id (a digest of another input).
pub(super) fn key_session(id: nex_db::ApiKeyId) -> SessionId {
    let digest = crypt_io::hash::blake3(format!("wasp api key {id}").as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    SessionId(u128::from_le_bytes(b))
}

/// `label` trimmed, or why it is refused.
fn checked_label(label: &str) -> Result<String, String> {
    let label = label.trim();
    if label.is_empty() {
        return Err("Give the key a label, so you know what uses it.".to_owned());
    }
    if label.chars().count() > MAX_LABEL {
        return Err(format!("A label is at most {MAX_LABEL} characters."));
    }
    if label.chars().any(char::is_control) {
        return Err("A label is one line of text.".to_owned());
    }
    Ok(label.to_owned())
}

impl NexAuth {
    /// The keys of `user`, newest first.
    pub fn api_keys(&self, user: UserId) -> Result<Vec<KeyRow>, StoreError> {
        let account = account_of(user);
        let mut rows: Vec<KeyRow> = self
            .auth()?
            .api_keys(account)
            .map_err(nex)?
            .into_iter()
            .filter(|k| k.revoked_at().is_none())
            .map(|k| {
                let id = k.id().to_string();
                Ok(KeyRow {
                    label: self.key_label(account, &id)?,
                    scopes: k.scopes().to_vec(),
                    created: k.created_at(),
                    // Every key wasp makes has an expiry.
                    expires: k.expires_at().unwrap_or(SystemTime::UNIX_EPOCH),
                    id,
                })
            })
            .collect::<Result<_, StoreError>>()?;
        rows.sort_by_key(|r| std::cmp::Reverse(r.created));
        Ok(rows)
    }

    /// The label wasp keeps for key `id` of `account`, or empty.
    fn key_label(&self, account: nex_db::AccountId, id: &str) -> Result<String, StoreError> {
        let content = self.db.db().content();
        let path = format!("/{}/k/{id}", hex_of(account));
        let Some(route) = content.resolve(&self.directory, &path).map_err(nex)? else {
            return Ok(String::new());
        };
        Ok(content
            .get(route.entity())
            .map_err(nex)?
            .and_then(|r| {
                r.field("label")
                    .and_then(nex_db::Value::as_text)
                    .map(str::to_owned)
            })
            .unwrap_or_default())
    }

    /// Makes a key for `user`: `label`, `scopes`, lasting `days` (one of
    /// [`EXPIRIES`]). `Ok(Err(why))` when the form breaks a rule.
    pub fn create_api_key(
        &self,
        user: UserId,
        label: &str,
        scopes: Scopes,
        days: u32,
    ) -> Result<Result<NewKey, String>, StoreError> {
        let label = match checked_label(label) {
            Ok(l) => l,
            Err(why) => return Ok(Err(why)),
        };
        if !EXPIRIES.contains(&days) {
            return Ok(Err("Choose how long the key lasts.".to_owned()));
        }
        if self.api_keys(user)?.len() >= MAX_KEYS {
            return Ok(Err(format!(
                "An account holds at most {MAX_KEYS} keys. Revoke one you no longer use first."
            )));
        }
        let account = account_of(user);
        let created = SystemTime::now();
        let expires = created + Duration::from_secs(u64::from(days) * 86_400);
        let names = scopes.names();
        let key = self
            .auth()?
            .create_api_key(account, &names, Some(expires))
            .map_err(nex)?;
        let id = key.id();
        let content = self.db.db().content();
        let record = nex_db::Entity::new(KEY_KIND)
            .site(self.directory.as_ref())
            .path(format!("/{}/k/{id}", hex_of(account)))
            .author(account)
            .field("label", label.as_str());
        if let Err(e) = content.put(record) {
            // A key the list cannot show must not work.
            let _ = self.auth()?.revoke_api_key(id);
            return Err(nex(e));
        }
        Ok(Ok(NewKey {
            row: KeyRow {
                id: id.to_string(),
                label,
                scopes: names.iter().map(|s| (*s).to_owned()).collect(),
                created,
                expires,
            },
            text: key.as_str().to_owned(),
        }))
    }

    /// Revokes every key of `user`; how many.
    pub fn revoke_api_keys(&self, user: UserId) -> Result<usize, StoreError> {
        let mut n = 0;
        for key in self.api_keys(user)? {
            if self.revoke_api_key(user, &key.id)?.is_some() {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Revokes `user`'s key `id` (32 hex digits) and drops it from the list:
    /// `None` when `user` has no such key (another account's key is never
    /// touched), else its label.
    pub fn revoke_api_key(&self, user: UserId, id: &str) -> Result<Option<String>, StoreError> {
        let Ok(kid) = id.parse::<nex_db::ApiKeyId>() else {
            return Ok(None);
        };
        let account = account_of(user);
        // nex-db says whose key it is: another account's key, or one revoked
        // already, is no key of this account's.
        let auth = self.auth()?;
        let own = auth
            .api_keys(account)
            .map_err(nex)?
            .iter()
            .any(|k| k.id() == kid && k.revoked_at().is_none());
        if !own {
            return Ok(None);
        }
        let label = self.key_label(account, &kid.to_string())?;
        auth.revoke_api_key(kid).map_err(nex)?;
        // What the key opened (a WebSocket) ends with it.
        self.revoker.session(key_session(kid).0);
        let content = self.db.db().content();
        let path = format!("/{}/k/{kid}", hex_of(account));
        if let Some(route) = content.resolve(&self.directory, &path).map_err(nex)? {
            let _ = content.delete(route.entity());
        }
        Ok(Some(label))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_parse_and_cut_permissions() {
        assert_eq!(Scopes::parse([]).expect("none"), Scopes::default());
        let read = Scopes::parse(["account:read"]).expect("known");
        assert!(read.has("account:read"));
        assert_eq!(read.names(), ["account:read"]);
        assert_eq!(read.perms(), crate::site_nex::MEMBER);
        assert!(Scopes::parse(["account:write"]).is_err());
        assert_eq!(
            Scopes::of_stored(&["gone:scope".into(), "account:read".into()]),
            read
        );
        assert!(!Scopes::default().perms().contains(crate::site_nex::MEMBER));
        assert_eq!(Scopes::default().perms(), PermSet::NONE);
    }

    #[test]
    fn labels_are_one_short_line() {
        assert_eq!(checked_label("  deploy bot ").as_deref(), Ok("deploy bot"));
        assert!(checked_label("   ").is_err());
        assert!(checked_label("a\nb").is_err());
        assert!(checked_label(&"x".repeat(MAX_LABEL)).is_ok());
        assert!(checked_label(&"x".repeat(MAX_LABEL + 1)).is_err());
    }
}
