//! What an account does to itself, and what an administrator does to
//! accounts: change a password, sign out everywhere, two-step sign-in (TOTP
//! and recovery codes, through nex-db), remembered devices, and disable,
//! enable, remove.
//!
//! The account directory (`wasp-accounts`) holds, beside each account's
//! identifier, two fields wasp keeps itself: `totp` (`on` while two-step
//! sign-in is on) and `devices_after` (Unix milliseconds: a device
//! remembered at or before it no longer skips the code).

use std::time::{Duration, SystemTime};

use nex_db::Patch;
use wasp_core::UserId;

use super::{DIRECTORY, MAX_ENTRIES, NexAuth, StoreError, StoreErrorKind, account_of, hex_of, nex};
use crate::policy::Rules;

/// Wrong codes per account, counted toward `[auth.lockout]`: nex-db counts
/// wrong passwords itself, and a wrong code here locks the account the same
/// way.
#[derive(Debug, Default)]
pub(super) struct Failures(
    std::sync::Mutex<std::collections::HashMap<UserId, (std::time::Instant, u32)>>,
);

impl Failures {
    /// Counts one wrong code: `true` when that reaches `attempts` within
    /// `window`.
    fn count(&self, user: UserId, attempts: u32, window: Duration) -> bool {
        let mut map = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = std::time::Instant::now();
        if map.len() >= MAX_ENTRIES {
            map.retain(|_, (since, _)| now.duration_since(*since) < window);
        }
        let entry = map.entry(user).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        if entry.1 >= attempts {
            map.remove(&user);
            return true;
        }
        false
    }

    fn clear(&self, user: UserId) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&user);
    }
}

/// How a code at the second step went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeCheck {
    /// A good code from the authenticator app.
    Code,
    /// A good recovery code, now used up.
    Recovery,
    /// Wrong.
    Wrong,
    /// The account is locked out, suspended, or banned.
    Blocked,
}

/// One account as the administrator's list shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRow {
    /// The account.
    pub user: UserId,
    /// Its email (lower case).
    pub identifier: String,
    /// Its roles, by name.
    pub roles: Vec<String>,
    /// `active`, `disabled`, `locked`, `banned`, or `pending`.
    pub standing: &'static str,
    /// Whether two-step sign-in is on.
    pub totp: bool,
}

/// The suspension reason a disable writes.
const DISABLED: u32 = 2;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Whether `code` is an authenticator app's code (six digits) rather than a
/// recovery code.
fn app_code(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

impl NexAuth {
    /// The directory entry of `user`: its entity and published fields.
    fn entry(&self, user: UserId) -> Result<Option<(nex_db::EntityId, nex_db::Entry)>, StoreError> {
        let content = self.db.db().content();
        let path = format!("/{}", hex_of(account_of(user)));
        let Some(route) = content.resolve(DIRECTORY, &path).map_err(nex)? else {
            return Ok(None);
        };
        let rid = route.entity();
        Ok(content.get(rid).map_err(nex)?.map(|e| (rid, e)))
    }

    fn field(&self, user: UserId, name: &str) -> Result<Option<String>, StoreError> {
        Ok(self.entry(user)?.and_then(|(_, e)| {
            e.field(name)
                .and_then(nex_db::Value::as_text)
                .map(str::to_owned)
        }))
    }

    fn set_field(&self, user: UserId, name: &str, value: &str) -> Result<(), StoreError> {
        let Some((rid, _)) = self.entry(user)? else {
            return Err(StoreError::new(
                StoreErrorKind::Invalid,
                "the account is not in the directory",
            ));
        };
        let content = self.db.db().content();
        content
            .save_draft(rid, Patch::new().set(name, value))
            .map_err(nex)?;
        content.publish(rid).map_err(nex)?;
        Ok(())
    }

    /// The email `user` signs in with, when the directory knows it.
    pub fn identifier_of(&self, user: UserId) -> Result<Option<String>, StoreError> {
        self.field(user, "identifier")
    }

    /// Whether `user` has two-step sign-in on.
    pub fn totp_on(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(self.field(user, "totp")?.as_deref() == Some("on"))
    }

    /// Whether a device remembered for `user` at `set_at` (Unix
    /// milliseconds) still skips the code under `rules`.
    pub fn remembered(&self, user: UserId, set_at: u64, rules: &Rules) -> Result<bool, StoreError> {
        if rules.every_login || rules.remember.is_zero() {
            return Ok(false);
        }
        let after: u64 = self
            .field(user, "devices_after")?
            .and_then(|t| t.parse().ok())
            .unwrap_or(0);
        let remember = u64::try_from(rules.remember.as_millis()).unwrap_or(u64::MAX);
        Ok(set_at > after && now_ms() < set_at.saturating_add(remember))
    }

    /// Every device remembered for `user` until now asks for a code again.
    pub fn forget_devices(&self, user: UserId) -> Result<(), StoreError> {
        self.set_field(user, "devices_after", &now_ms().to_string())
    }

    /// Whether `user` may sign in now: active, or not yet verified (not
    /// locked out, disabled, banned, or gone).
    pub fn may_sign_in(&self, user: UserId) -> Result<bool, StoreError> {
        Ok(matches!(
            self.db
                .db()
                .auth()
                .standing(account_of(user))
                .map_err(nex)?,
            Some(nex_db::Standing::Active | nex_db::Standing::PendingVerification)
        ))
    }

    /// The second step of a sign-in: a code from the authenticator app, or
    /// a recovery code. Wrong codes count toward the lockout.
    pub fn check_code(&self, user: UserId, code: &str) -> Result<CodeCheck, StoreError> {
        let account = account_of(user);
        let auth = self.db.db().auth();
        if !self.may_sign_in(user)? {
            return Ok(CodeCheck::Blocked);
        }
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let good = if app_code(&code) {
            self.app_code_good(account, &code)?
                .then_some(CodeCheck::Code)
        } else if !code.is_empty() && code.len() <= 32 {
            auth.use_recovery_code(account, &code)
                .map_err(nex)?
                .then_some(CodeCheck::Recovery)
        } else {
            None
        };
        if let Some(good) = good {
            self.failures.clear(user);
            return Ok(good);
        }
        let l = self.policy().lockout;
        if self.failures.count(user, l.attempts, l.window) {
            let until = SystemTime::now() + l.duration;
            auth.set_standing(account, nex_db::Standing::LockedOut { until }, None)
                .map_err(nex)?;
            return Ok(CodeCheck::Blocked);
        }
        Ok(CodeCheck::Wrong)
    }

    #[cfg(feature = "mfa")]
    fn app_code_good(&self, account: nex_db::AccountId, code: &str) -> Result<bool, StoreError> {
        self.db.db().auth().check_totp(account, code).map_err(nex)
    }

    #[cfg(not(feature = "mfa"))]
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn app_code_good(&self, _account: nex_db::AccountId, _code: &str) -> Result<bool, StoreError> {
        Ok(false)
    }

    /// Whether `password` is `user`'s password now.
    pub fn password_is(&self, user: UserId, password: &str) -> Result<bool, StoreError> {
        let Some(identifier) = self.identifier_of(user)? else {
            return Ok(false);
        };
        Ok(matches!(
            self.db
                .db()
                .auth()
                .verify_password(&identifier, password)
                .map_err(nex)?,
            nex_db::PasswordCheck::Verified(a) | nex_db::PasswordCheck::NeedsSecondFactor { account: a }
                if a == account_of(user)
        ))
    }

    /// Changes `user`'s password: `current` must be its password now and
    /// `new` must keep its rules. Every session of the account ends and the
    /// remembered devices are forgotten; the new session's cookie value comes
    /// back. `Ok(Err(why))` when it is refused, in words for the person.
    pub fn change_password(
        &self,
        user: UserId,
        current: &str,
        new: &str,
    ) -> Result<Result<String, String>, StoreError> {
        if !self.password_is(user, current)? {
            return Ok(Err("The current password is not right.".to_owned()));
        }
        if let Some(why) = self.rules(user)?.refuse(new) {
            return Ok(Err(why));
        }
        let auth = self.db.db().auth();
        let hashed = auth.hash_password(new).map_err(nex)?;
        let account = account_of(user);
        auth.set_password(account, &hashed).map_err(nex)?;
        let _ = auth.revoke_all(account).map_err(nex)?;
        self.forget_devices(user)?;
        self.open_session(user).map(Ok)
    }

    /// Ends every session `user` holds (this one too) and forgets its
    /// remembered devices; how many sessions ended.
    pub fn sign_out_everywhere(&self, user: UserId) -> Result<u32, StoreError> {
        let ended = self
            .db
            .db()
            .auth()
            .revoke_all(account_of(user))
            .map_err(nex)?;
        self.forget_devices(user)?;
        Ok(ended)
    }

    /// Starts two-step sign-in for `user`: the secret to type into an
    /// authenticator app, and the `otpauth://` link a QR code would carry.
    /// Codes are not asked for until one is confirmed.
    #[cfg(feature = "mfa")]
    pub fn start_totp(
        &self,
        user: UserId,
        issuer: &str,
    ) -> Result<(crypt_io::Zeroizing<String>, crypt_io::Zeroizing<String>), StoreError> {
        let label = self.identifier_of(user)?.unwrap_or_default();
        let enrollment = self
            .db
            .db()
            .auth()
            .add_totp(account_of(user))
            .map_err(nex)?;
        Ok((enrollment.secret(), enrollment.uri(issuer, &label)))
    }

    /// Confirms two-step sign-in with a code from the app: the recovery
    /// codes to show once (`[auth.mfa] recovery_codes` of them), or `None`
    /// when the code is wrong. Remembered devices are forgotten.
    #[cfg(feature = "mfa")]
    pub fn confirm_totp(
        &self,
        user: UserId,
        code: &str,
    ) -> Result<Option<Vec<String>>, StoreError> {
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        let account = account_of(user);
        let auth = self.db.db().auth();
        if !app_code(&code) || !auth.confirm_totp(account, &code).map_err(nex)? {
            return Ok(None);
        }
        self.set_field(user, "totp", "on")?;
        self.forget_devices(user)?;
        self.recovery_codes(user).map(Some)
    }

    /// New recovery codes for `user`, replacing the old ones: the ones to
    /// show (nex-db makes ten; the rest are never shown, so never usable).
    pub fn recovery_codes(&self, user: UserId) -> Result<Vec<String>, StoreError> {
        let show = self.policy().recovery_codes;
        let codes = self
            .db
            .db()
            .auth()
            .new_recovery_codes(account_of(user))
            .map_err(nex)?;
        Ok(codes.codes().take(show).map(str::to_owned).collect())
    }

    /// Turns two-step sign-in off for `user`.
    #[cfg(feature = "mfa")]
    pub fn remove_totp(&self, user: UserId) -> Result<(), StoreError> {
        let _ = self
            .db
            .db()
            .auth()
            .remove_totp(account_of(user))
            .map_err(nex)?;
        self.set_field(user, "totp", "")?;
        self.forget_devices(user)
    }

    /// Every account, for the administrator.
    pub fn account_rows(&self) -> Result<Vec<AccountRow>, StoreError> {
        let auth = self.db.db().auth();
        let mut rows = Vec::new();
        for (identifier, user) in self.accounts()? {
            let account = account_of(user);
            let (_, roles) = self.roles_of(account)?;
            let standing = match auth.standing(account).map_err(nex)? {
                Some(nex_db::Standing::Active) => "active",
                Some(nex_db::Standing::PendingVerification) => "pending",
                Some(nex_db::Standing::LockedOut { .. }) => "locked",
                Some(nex_db::Standing::Suspended { .. }) => "disabled",
                Some(nex_db::Standing::Banned { .. }) => "banned",
                Some(_) | None => continue,
            };
            rows.push(AccountRow {
                user,
                identifier,
                roles,
                standing,
                totp: self.totp_on(user)?,
            });
        }
        rows.sort_by(|a, b| a.identifier.cmp(&b.identifier));
        Ok(rows)
    }

    /// Disables `user` until enabled: every session it holds ends, and its
    /// remembered devices are forgotten.
    pub fn disable(&self, user: UserId, by: UserId) -> Result<(), StoreError> {
        let auth = self.db.db().auth();
        let account = account_of(user);
        auth.set_standing(
            account,
            nex_db::Standing::Suspended {
                until: None,
                reason: DISABLED,
            },
            Some(account_of(by)),
        )
        .map_err(nex)?;
        let _ = auth.revoke_all(account).map_err(nex)?;
        self.forget_devices(user)
    }

    /// Lets `user` sign in again after a disable or a lockout: `false`, and
    /// nothing changed, for any other standing (a ban, an unverified account
    /// stay as they are).
    pub fn enable(&self, user: UserId, by: UserId) -> Result<bool, StoreError> {
        let auth = self.db.db().auth();
        let account = account_of(user);
        if !matches!(
            auth.standing(account).map_err(nex)?,
            Some(nex_db::Standing::Suspended { .. } | nex_db::Standing::LockedOut { .. })
        ) {
            return Ok(false);
        }
        self.failures.clear(user);
        auth.set_standing(account, nex_db::Standing::Active, Some(account_of(by)))
            .map_err(nex)?;
        Ok(true)
    }

    /// Removes `user`: the account, its sessions and secrets, and its
    /// directory entry.
    pub fn remove(&self, user: UserId) -> Result<(), StoreError> {
        self.db
            .db()
            .auth()
            .erase_account(account_of(user))
            .map_err(nex)?;
        if let Some((rid, _)) = self.entry(user)? {
            self.db.db().content().delete(rid).map_err(nex)?;
        }
        Ok(())
    }
}
