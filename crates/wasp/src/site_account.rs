//! The account and sign-in security routes on the nex-db site. Every page
//! here renders from the admin theme, is never cached, and carries the admin
//! pages' content security policy.
//!
//! | Path | Who | What |
//! |---|---|---|
//! | `POST /sign-in` | guests | the password; then a session, or the second step |
//! | `GET`, `POST /sign-in/code` | guests mid sign-in | a code from the app, or a recovery code |
//! | `GET`, `POST /sign-in/setup` | guests mid sign-in | two-step set-up a role requires |
//! | `GET /account/security` | signed in | password, two-step sign-in, sessions, API keys |
//! | `POST /account/password` | signed in | changes the password; every other session ends |
//! | `POST /account/sign-out-everywhere` | signed in | ends every session of the account |
//! | `POST /account/forget-devices` | signed in | remembered devices ask for a code again |
//! | `GET`, `POST /account/two-factor` | signed in | turns two-step sign-in on (then the recovery codes) |
//! | `POST /account/two-factor/off` | signed in | turns it off (with the password) |
//! | `POST /account/recovery-codes` | signed in | new recovery codes (with the password) |
//! | `POST /account/keys` | signed in, with the API on | makes an API key (its text shown once) |
//! | `POST /account/keys/revoke` | signed in, with the API on | revokes one of the account's keys |
//! | `GET /admin/accounts` | `admin` | every account |
//! | `POST /admin/accounts/disable`, `enable`, `remove` | `admin` | never the viewer's own account or the boot account |
//!
//! Between the two steps of a sign-in the browser holds `__Host-nexstep`:
//! the account, the step, when it ends (five minutes), and a random nonce,
//! sealed with a key derived from the master secret and bound to the
//! visitor's pre-session cookie. A step is good once: completing it spends
//! its nonce, and the set-up step refuses an account that already has
//! two-step sign-in on or may not sign in. "Remember this device" sets `__Host-nexdev`: the account and when
//! it was set, sealed with another derived key.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crypt_io::Zeroizing;
use wasp_core::{PermSet, Rule, Subject, UserId};
use web_net::form_net::{self, Secret};
use web_net::{get, post};

use crate::nex::{
    CodeCheck, NexAuth, PRE_COOKIE, PasswordStep, SESSION, SESSION_COOKIE, SignInFrom, cookie,
};
use crate::policy::MfaMode;
use crate::site::{Pages, query_value};
use crate::site_nex::{ADMIN, Attempts, EDITOR, NexCx, NexRoute, hash_slot};
use crate::theme::{ADMIN_CSP, AccountView, Choice, KeyView, ScopeView, Security, SessionView};

/// The half-done sign-in's cookie.
pub const STEP_COOKIE: &str = "__Host-nexstep";

/// The remembered device's cookie.
pub const DEVICE_COOKIE: &str = "__Host-nexdev";

/// How long the second step of a sign-in waits for its code.
const STEP_TTL: Duration = Duration::from_secs(5 * 60);

/// Whether this build has two-step sign-in.
const MFA_BUILT: bool = cfg!(feature = "mfa");

/// Any account signed in with a session cookie (never an API key).
const SIGNED_IN: Rule = Rule::needs(6, SESSION);

/// The accounts page's rule.
const ADMINING: Rule = Rule::needs(7, PermSet(ADMIN.0 | SESSION.0));

const STEP_AAD: &[u8] = b"wasp sign-in step v1";
const DEVICE_AAD: &[u8] = b"wasp device v1";

/// The two sealed cookies' keys, derived from the master secret.
#[derive(Clone)]
pub struct CookieKeys {
    step: Arc<Zeroizing<[u8; 32]>>,
    device: Arc<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for CookieKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CookieKeys(..)")
    }
}

impl CookieKeys {
    /// The keys, from two derived keys.
    #[must_use]
    pub fn new(step: Zeroizing<[u8; 32]>, device: Zeroizing<[u8; 32]>) -> CookieKeys {
        CookieKeys {
            step: Arc::new(step),
            device: Arc::new(device),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.len() > 1024 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Option<String> {
    crypt_io::Crypt::new()
        .seal_with_aad(key, plain, aad)
        .ok()
        .map(|s| hex(&s))
}

fn open(key: &[u8; 32], aad: &[u8], text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let sealed = unhex(text)?;
    crypt_io::Crypt::new()
        .open_with_aad(key, &sealed, aad)
        .ok()
        .map(Zeroizing::new)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Which second step a half-done sign-in is at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Code = 1,
    Setup = 2,
}

/// A half-done sign-in's nonce: spent when the step completes.
type Nonce = [u8; 16];

/// The nonces of completed steps, kept until their cookies have expired.
#[derive(Debug, Default)]
pub(crate) struct Spent(std::sync::Mutex<std::collections::HashMap<Nonce, std::time::Instant>>);

/// Completed steps remembered at once; past it (after the expired ones go)
/// a completion is refused for now rather than forgotten.
const SPENT_CAP: usize = 100_000;

impl Spent {
    fn is_spent(&self, nonce: &Nonce) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(nonce)
    }

    /// Spends `nonce`: `false` when it was spent already, or when the set
    /// is full of live steps.
    fn spend(&self, nonce: Nonce) -> bool {
        let mut map = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= SPENT_CAP {
            map.retain(|_, at| at.elapsed() < STEP_TTL);
            if map.len() >= SPENT_CAP {
                return false;
            }
        }
        map.insert(nonce, std::time::Instant::now()).is_none()
    }
}

fn step_cookie(keys: &CookieKeys, step: Step, user: UserId, binding: &[u8]) -> Option<String> {
    let random = crypt_io::generate_key().ok()?;
    let mut plain = Vec::with_capacity(41 + binding.len());
    plain.push(step as u8);
    plain.extend_from_slice(&user.0.to_be_bytes());
    plain.extend_from_slice(&(now_secs() + STEP_TTL.as_secs()).to_be_bytes());
    plain.extend_from_slice(&random[..16]);
    plain.extend_from_slice(binding);
    let value = seal(&keys.step, STEP_AAD, &plain)?;
    Some(format!(
        "{STEP_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        STEP_TTL.as_secs()
    ))
}

fn clear(name: &str) -> String {
    format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

/// The half-done sign-in this visitor holds at `want`, when it is still
/// good, not spent, and bound to the visitor's pre-session cookie.
fn read_step(
    cx: &NexCx<'_>,
    keys: &CookieKeys,
    spent: &Spent,
    want: Step,
) -> Option<(UserId, Nonce)> {
    let binding = web_net::Identity::csrf_binding(cx.identity())?;
    let value = cx.header("cookie").and_then(|h| cookie(h, STEP_COOKIE))?;
    let plain = open(&keys.step, STEP_AAD, value)?;
    let (head, rest) = plain.split_at_checked(41)?;
    let user = UserId(u128::from_be_bytes(head.get(1..17)?.try_into().ok()?));
    let until = u64::from_be_bytes(head.get(17..25)?.try_into().ok()?);
    let nonce: Nonce = head.get(25..41)?.try_into().ok()?;
    (head[0] == want as u8 && rest == binding && now_secs() < until && !spent.is_spent(&nonce))
        .then_some((user, nonce))
}

fn device_cookie(keys: &CookieKeys, user: UserId, remember: Duration) -> Option<String> {
    let mut plain = Vec::with_capacity(24);
    plain.extend_from_slice(&user.0.to_be_bytes());
    let now_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    plain.extend_from_slice(&now_ms.to_be_bytes());
    let value = seal(&keys.device, DEVICE_AAD, &plain)?;
    Some(format!(
        "{DEVICE_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        remember.as_secs()
    ))
}

/// The account and the time (Unix milliseconds) this browser was
/// remembered for it, if it was.
fn read_device(cx: &NexCx<'_>, keys: &CookieKeys) -> Option<(UserId, u64)> {
    let value = cx.header("cookie").and_then(|h| cookie(h, DEVICE_COOKIE))?;
    let plain = open(&keys.device, DEVICE_AAD, value)?;
    let user = UserId(u128::from_be_bytes(plain.get(..16)?.try_into().ok()?));
    let at = u64::from_be_bytes(plain.get(16..24)?.try_into().ok()?);
    Some((user, at))
}

form_net::form! {
    /// The sign-in form.
    struct SignInForm {
        email: String,
        password: Secret,
    }
    ignore = ["csrf_token"];
}

form_net::form! {
    /// The second step.
    struct CodeForm {
        code: String,
        remember: bool,
    }
    ignore = ["csrf_token"];
}

form_net::form! {
    /// The password change.
    struct PasswordForm {
        current: Secret,
        new: Secret,
        again: Secret,
    }
    ignore = ["csrf_token"];
}

form_net::form! {
    /// Turning two-step sign-in on from the account page: the code, and the
    /// password, so a borrowed session cannot.
    struct EnrollForm {
        code: String,
        password: Secret,
    }
    ignore = ["csrf_token"];
}

form_net::form! {
    /// A form that only asks for the password.
    struct PasswordOnly {
        password: Secret,
    }
    ignore = ["csrf_token"];
}

form_net::form! {
    /// A session's revoke button.
    struct SessionForm {
        session: String,
    }
    ignore = ["csrf_token"];
}

form_net::form! {
    /// A key's revoke button.
    struct KeyRevokeForm {
        key: String,
    }
    ignore = ["csrf_token"];
}

/// The make-a-key form: a label, how many days, any number of `scope` boxes,
/// and the current password (web-net checked its `csrf_token` before the
/// handler).
#[derive(Debug, Default)]
struct KeyForm {
    label: String,
    days: String,
    scopes: Vec<String>,
    password: Zeroizing<String>,
}

#[derive(Default)]
struct KeyFormBuilder {
    form: KeyForm,
    seen: (bool, bool, bool),
}

impl form_net::FormBuilder for KeyFormBuilder {
    type Output = KeyForm;

    fn text(&mut self, name: &str, value: &str) -> Result<(), form_net::FormError> {
        use form_net::{ExtractError, FormError};
        let refuse = |reason| FormError::Extract {
            reason,
            field: None,
        };
        match name {
            "csrf_token" => {}
            "label" if !self.seen.0 => {
                self.seen.0 = true;
                value.clone_into(&mut self.form.label);
            }
            "days" if !self.seen.1 => {
                self.seen.1 = true;
                value.clone_into(&mut self.form.days);
            }
            "password" if !self.seen.2 => {
                self.seen.2 = true;
                self.form.password = Zeroizing::new(value.to_owned());
            }
            "scope" => {
                if self.form.scopes.len() >= crate::nex::SCOPES.len() {
                    return Err(refuse(ExtractError::Invalid("too many scopes")));
                }
                self.form.scopes.push(value.to_owned());
            }
            "label" | "days" | "password" => return Err(refuse(ExtractError::Duplicate)),
            _ => return Err(refuse(ExtractError::Unknown)),
        }
        Ok(())
    }

    fn file(
        &mut self,
        _name: &str,
        _file: form_net::FileValue<'_>,
    ) -> Result<(), form_net::FormError> {
        Err(form_net::FormError::Extract {
            reason: form_net::ExtractError::WrongKind,
            field: None,
        })
    }

    fn finish(self) -> Result<KeyForm, form_net::FormError> {
        Ok(self.form)
    }
}

impl form_net::FromForm for KeyForm {
    type Builder = KeyFormBuilder;
}

form_net::form! {
    /// An administrator's button on one account.
    struct AccountForm {
        account: String,
        confirm: bool,
    }
    ignore = ["csrf_token"];
}

fn store(_: crate::content::StoreError) -> web_net::Error {
    web_net::Error::unavailable("auth.unavailable")
}

/// Where this request signs in from.
fn from(cx: &NexCx<'_>) -> SignInFrom {
    let ua = cx
        .header("user-agent")
        .and_then(|h| std::str::from_utf8(h).ok());
    SignInFrom::new(ua, cx.request().client().addr())
}

/// `t` as `2026-11-20 14:05 UTC`.
fn when(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Days to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

fn me(cx: &NexCx<'_>) -> Result<UserId, web_net::Error> {
    match cx.identity().identity.subject() {
        Subject::User(u) => Ok(u),
        _ => Err(web_net::Error::forbidden("account.signed_out")),
    }
}

/// Never cached, and under the admin pages' content security policy.
fn guard(cx: &mut NexCx<'_>) {
    cx.set_header("cache-control", "no-store");
    cx.set_header("content-security-policy", ADMIN_CSP);
}

/// The sign-in form, shown again with a message (from the site's sign-in
/// route).
pub(crate) type ShowSignIn =
    Arc<dyn Fn(&mut NexCx<'_>, &str, &str) -> web_net::Result + Send + Sync>;

/// What the account routes share.
#[derive(Clone)]
pub(crate) struct Accounts {
    /// The authenticator.
    pub(crate) auth: NexAuth,
    /// The pages.
    pub(crate) pages: Pages,
    /// The sealed cookies' keys.
    pub(crate) keys: CookieKeys,
    /// Sign-in attempts per client address.
    pub(crate) attempts: Arc<Attempts>,
    /// Passwords being hashed now.
    pub(crate) hashing: Arc<std::sync::atomic::AtomicUsize>,
    /// The boot account (`auth.admin`), never disabled or removed from here.
    pub(crate) boot: Option<String>,
    /// The sign-in form.
    pub(crate) show: ShowSignIn,
    /// The completed sign-in steps.
    pub(crate) spent: Arc<Spent>,
    /// The site has the API: accounts make and revoke keys here.
    pub(crate) api: bool,
}

impl Accounts {
    /// The account security view, with every address filled in.
    fn view(&self, cx: &mut NexCx<'_>, user: UserId) -> Result<Security, web_net::Error> {
        let a = &self.auth;
        let rules = a.rules(user).map_err(store)?;
        let perms = cx.identity().identity.perms();
        Ok(Security {
            identifier: a.identifier_of(user).map_err(store)?.unwrap_or_default(),
            csrf: cx.csrf_token()?,
            password: cx.url("/account/password")?,
            everywhere: cx.url("/account/sign-out-everywhere")?,
            devices: cx.url("/account/forget-devices")?,
            two_factor: cx.url("/account/two-factor")?,
            two_factor_off: cx.url("/account/two-factor/off")?,
            new_codes: cx.url("/account/recovery-codes")?,
            totp: a.totp_on(user).map_err(store)?,
            offered: MFA_BUILT && rules.mfa != MfaMode::Off,
            required: rules.mfa == MfaMode::Required,
            min_length: i64::try_from(rules.min_length).unwrap_or(i64::MAX),
            editor: perms.contains(EDITOR),
            admin: perms.contains(ADMIN),
            sessions: Arc::new(
                a.sessions_of(
                    user,
                    cx.identity()
                        .identity
                        .session()
                        .unwrap_or(wasp_core::SessionId(0)),
                )
                .map_err(store)?
                .into_iter()
                .map(|s| {
                    Arc::new(SessionView {
                        id: s.id,
                        device: if s.device.is_empty() {
                            "Unknown device".to_owned()
                        } else {
                            s.device
                        },
                        address: s.address,
                        signed_in: when(s.signed_in),
                        last_used: when(s.last_used),
                        current: s.current,
                    })
                })
                .collect(),
            ),
            revoke: cx.url("/account/sessions/revoke")?,
            revoke_others: cx.url("/account/sessions/revoke-others")?,
            ..self.keys_view(cx, user)?
        })
    }

    /// The API keys part of the view (empty without the API).
    fn keys_view(&self, cx: &NexCx<'_>, user: UserId) -> Result<Security, web_net::Error> {
        if !self.api {
            return Ok(Security::default());
        }
        let now = SystemTime::now();
        Ok(Security {
            api: true,
            keys: Arc::new(
                self.auth
                    .api_keys(user)
                    .map_err(store)?
                    .into_iter()
                    .map(|k| {
                        Arc::new(KeyView {
                            id: k.id,
                            label: k.label,
                            scopes: k.scopes.join(", "),
                            created: when(k.created),
                            expires: when(k.expires),
                            expired: k.expires <= now,
                        })
                    })
                    .collect(),
            ),
            key_create: cx.url("/account/keys")?,
            key_revoke: cx.url("/account/keys/revoke")?,
            scopes: Arc::new(
                crate::nex::SCOPES
                    .iter()
                    .map(|s| {
                        Arc::new(ScopeView {
                            name: s.name.to_owned(),
                            label: s.label.to_owned(),
                        })
                    })
                    .collect(),
            ),
            expiries: Arc::new(
                crate::nex::EXPIRIES
                    .iter()
                    .map(|d| {
                        Arc::new(Choice {
                            value: d.to_string(),
                            selected: *d == crate::nex::DEFAULT_EXPIRY,
                        })
                    })
                    .collect(),
            ),
            max_keys: i64::try_from(crate::nex::MAX_KEYS).unwrap_or(i64::MAX),
            ..Security::default()
        })
    }

    fn security_page(
        &self,
        cx: &mut NexCx<'_>,
        user: UserId,
        error: &str,
        notice: &str,
    ) -> web_net::Result {
        guard(cx);
        let view = Security {
            error: error.to_owned(),
            notice: notice.to_owned(),
            ..self.view(cx, user)?
        };
        cx.render_named(
            "admin/security",
            &self.pages.security_page("Security", view),
        )
    }

    /// Whether `user` may set two-step sign-in up at sign-in: it may sign
    /// in, and has no two-step sign-in on yet.
    #[cfg_attr(not(feature = "mfa"), allow(dead_code))]
    fn setup_allowed(&self, user: UserId) -> Result<bool, web_net::Error> {
        Ok(self.auth.may_sign_in(user).map_err(store)?
            && !self.auth.totp_on(user).map_err(store)?)
    }

    /// The email of `user`, for an audit line.
    fn who(&self, user: UserId) -> String {
        self.auth
            .identifier_of(user)
            .ok()
            .flatten()
            .unwrap_or_else(|| format!("{:032x}", user.0))
    }

    /// The end of a sign-in: the session, the half-done sign-in and the
    /// pre-session cookies cleared, the device remembered when asked, then
    /// `next`.
    fn finish(
        &self,
        cx: &mut NexCx<'_>,
        user: UserId,
        remember: bool,
    ) -> Result<(), web_net::Error> {
        let set = self.auth.open_session(user, &from(cx)).map_err(store)?;
        cx.set_header("set-cookie", set);
        cx.set_header("set-cookie", clear(PRE_COOKIE));
        cx.set_header("set-cookie", clear(STEP_COOKIE));
        if remember {
            let rules = self.auth.rules(user).map_err(store)?;
            if !rules.every_login
                && !rules.remember.is_zero()
                && let Some(c) = device_cookie(&self.keys, user, rules.remember)
            {
                cx.set_header("set-cookie", c);
            }
        }
        Ok(())
    }

    /// `path`, keeping this request's `next`.
    fn with_next(cx: &NexCx<'_>, path: &str) -> Result<String, web_net::Error> {
        Ok(match cx.next_path()? {
            Some(next) => format!("{path}?next={}", query_value(&cx.url(&next)?)),
            None => path.to_owned(),
        })
    }

    /// Counts one attempt from the client's address: `false` past the
    /// limit.
    fn admit(&self, cx: &NexCx<'_>) -> bool {
        let l = self.auth.policy().lockout;
        cx.request().client().addr().is_none_or(|client| {
            self.attempts.admit(
                client,
                std::time::Instant::now(),
                l.address_attempts,
                l.address_window,
            )
        })
    }
}

/// The sign-in POST and its second steps.
fn sign_in_routes(acc: &Accounts) -> Vec<NexRoute> {
    let s = acc.clone();
    let sign_in_post: NexRoute = post("/sign-in", move |cx: &mut NexCx<'_>| {
        let next = cx.next_path()?.unwrap_or_else(|| "/account".to_owned());
        if !cx.identity().identity.is_guest() {
            return cx.redirect(303, &next);
        }
        let form: SignInForm = cx.form()?;
        if !s.admit(cx) {
            cx.status(429);
            cx.set_header("retry-after", "600");
            return (s.show)(
                cx,
                "Too many sign-in attempts from your address. Please wait a few minutes, then try again.",
                &form.email,
            );
        }
        // Argon2id runs here, on this worker, at most a few at once.
        let Some(_slot) = hash_slot(&s.hashing) else {
            cx.set_header("retry-after", "2");
            return Err(web_net::Error::unavailable("auth.busy"));
        };
        let binding = web_net::Identity::csrf_binding(cx.identity())
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        match s
            .auth
            .check_password(&form.email, form.password.expose())
            .map_err(store)?
        {
            PasswordStep::Done(user) => {
                s.finish(cx, user, false)?;
                cx.redirect(303, &next)
            }
            PasswordStep::Code(user) => {
                let rules = s.auth.rules(user).map_err(store)?;
                if let Some((who, at)) = read_device(cx, &s.keys)
                    && who == user
                    && s.auth.remembered(user, at, &rules).map_err(store)?
                {
                    s.finish(cx, user, false)?;
                    return cx.redirect(303, &next);
                }
                let set = step_cookie(&s.keys, Step::Code, user, &binding)
                    .ok_or_else(|| web_net::Error::internal("sign_in.seal"))?;
                cx.set_header("set-cookie", set);
                let to = Accounts::with_next(cx, "/sign-in/code")?;
                cx.redirect(303, &to)
            }
            PasswordStep::Setup(user) => {
                let set = step_cookie(&s.keys, Step::Setup, user, &binding)
                    .ok_or_else(|| web_net::Error::internal("sign_in.seal"))?;
                cx.set_header("set-cookie", set);
                let to = Accounts::with_next(cx, "/sign-in/setup")?;
                cx.redirect(303, &to)
            }
            PasswordStep::Refused => {
                cx.status(401);
                (s.show)(
                    cx,
                    "Those sign-in details are not right. Please try again.",
                    &form.email,
                )
            }
        }
    })
    .public()
    .template("sign-in")
    .name("sign-in-post");

    let code_page = |s: &Accounts, cx: &mut NexCx<'_>, user: UserId, error: &str| {
        guard(cx);
        let rules = s.auth.rules(user).map_err(store)?;
        let days = if rules.every_login {
            0
        } else {
            rules.remember.as_secs().div_ceil(86_400)
        };
        let view = Security {
            csrf: cx.csrf_token()?,
            error: error.to_owned(),
            action: cx.url(&Accounts::with_next(cx, "/sign-in/code")?)?,
            remember_days: i64::try_from(days).unwrap_or(0),
            ..Security::default()
        };
        cx.render_named("admin/code", &s.pages.security_page("Sign-in code", view))
    };

    let s = acc.clone();
    let code_get: NexRoute = get("/sign-in/code", move |cx: &mut NexCx<'_>| {
        let Some((user, _)) = read_step(cx, &s.keys, &s.spent, Step::Code) else {
            return cx.redirect(303, "/sign-in");
        };
        code_page(&s, cx, user, "")
    })
    .public()
    .template("admin/code")
    .name("sign-in-code");

    let s = acc.clone();
    let code_post: NexRoute = post("/sign-in/code", move |cx: &mut NexCx<'_>| {
        let Some((user, nonce)) = read_step(cx, &s.keys, &s.spent, Step::Code) else {
            return cx.redirect(303, "/sign-in");
        };
        let form: CodeForm = cx.form()?;
        if !s.admit(cx) {
            cx.status(429);
            cx.set_header("retry-after", "600");
            return code_page(
                &s,
                cx,
                user,
                "Too many attempts from your address. Please wait a few minutes, then try again.",
            );
        }
        let check = s.auth.check_code(user, &form.code).map_err(store)?;
        if matches!(
            check,
            CodeCheck::Code | CodeCheck::Recovery | CodeCheck::Blocked
        ) && !s.spent.spend(nonce)
        {
            // Spent by another request at the same moment.
            return cx.redirect(303, "/sign-in");
        }
        match check {
            CodeCheck::Code => {
                s.finish(cx, user, form.remember)?;
                let next = cx.next_path()?.unwrap_or_else(|| "/account".to_owned());
                cx.redirect(303, &next)
            }
            CodeCheck::Recovery => {
                s.finish(cx, user, form.remember)?;
                let who = s.who(user);
                crate::events::audit(&who, "recovery_code_used", &who);
                cx.redirect(303, "/account/security?used=recovery")
            }
            CodeCheck::Wrong => {
                cx.status(401);
                code_page(&s, cx, user, "That code is not right. Please try again.")
            }
            CodeCheck::Blocked => {
                cx.set_header("set-cookie", clear(STEP_COOKIE));
                cx.status(401);
                (s.show)(
                    cx,
                    "Those sign-in details are not right. Please try again.",
                    "",
                )
            }
        }
    })
    .public()
    .template("admin/code")
    .name("sign-in-code-post");

    let mut routes = vec![sign_in_post, code_get, code_post];
    routes.extend(setup_routes(acc));
    routes
}

/// Two-step set-up at sign-in, for a role that requires it.
#[cfg(feature = "mfa")]
fn setup_routes(acc: &Accounts) -> Vec<NexRoute> {
    let setup_page = |s: &Accounts,
                      cx: &mut NexCx<'_>,
                      user: UserId,
                      fresh: bool,
                      error: &str|
     -> web_net::Result {
        guard(cx);
        let (secret, uri) = if fresh {
            let (secret, uri) = s
                .auth
                .start_totp(user, s.pages.site_name())
                .map_err(store)?;
            (secret.to_string(), uri.to_string())
        } else {
            (String::new(), String::new())
        };
        let view = Security {
            csrf: cx.csrf_token()?,
            error: error.to_owned(),
            action: cx.url(&Accounts::with_next(cx, "/sign-in/setup")?)?,
            two_factor: cx.url(&Accounts::with_next(cx, "/sign-in/setup")?)?,
            required: true,
            secret,
            uri,
            ..Security::default()
        };
        cx.render_named(
            "admin/two-factor",
            &s.pages.security_page("Set up two-step sign-in", view),
        )
    };

    let s = acc.clone();
    let get_setup: NexRoute = get("/sign-in/setup", move |cx: &mut NexCx<'_>| {
        let Some((user, _)) = read_step(cx, &s.keys, &s.spent, Step::Setup) else {
            return cx.redirect(303, "/sign-in");
        };
        if !s.setup_allowed(user)? {
            cx.set_header("set-cookie", clear(STEP_COOKIE));
            return cx.redirect(303, "/sign-in");
        }
        setup_page(&s, cx, user, true, "")
    })
    .public()
    .template("admin/two-factor")
    .name("sign-in-setup");

    let s = acc.clone();
    let post_setup: NexRoute = post("/sign-in/setup", move |cx: &mut NexCx<'_>| {
        let Some((user, nonce)) = read_step(cx, &s.keys, &s.spent, Step::Setup) else {
            return cx.redirect(303, "/sign-in");
        };
        if !s.setup_allowed(user)? {
            cx.set_header("set-cookie", clear(STEP_COOKIE));
            return cx.redirect(303, "/sign-in");
        }
        let form: CodeForm = cx.form()?;
        if !s.admit(cx) {
            cx.status(429);
            return setup_page(
                &s,
                cx,
                user,
                false,
                "Too many attempts from your address. Please wait a few minutes, then try again.",
            );
        }
        match s.auth.confirm_totp(user, &form.code).map_err(store)? {
            Some(codes) => {
                if !s.spent.spend(nonce) {
                    return cx.redirect(303, "/sign-in");
                }
                s.finish(cx, user, false)?;
                let who = s.who(user);
                crate::events::audit(&who, "two_step_on", &who);
                let next = cx.next_path()?.unwrap_or_else(|| "/account".to_owned());
                guard(cx);
                let view = Security {
                    codes,
                    next: cx.url(&next)?,
                    notice: "Two-step sign-in is on, and you are signed in.".to_owned(),
                    ..Security::default()
                };
                cx.render_named(
                    "admin/codes",
                    &s.pages.security_page("Your recovery codes", view),
                )
            }
            None => {
                cx.status(422);
                setup_page(
                    &s,
                    cx,
                    user,
                    false,
                    "That code is not right. Check the time on your phone, then type the code the app shows now.",
                )
            }
        }
    })
    .public()
    .template("admin/two-factor")
    .name("sign-in-setup-post");

    vec![get_setup, post_setup]
}

#[cfg(not(feature = "mfa"))]
fn setup_routes(_acc: &Accounts) -> Vec<NexRoute> {
    Vec::new()
}

/// The signed-in account's own security routes.
fn own_routes(acc: &Accounts) -> Vec<NexRoute> {
    let s = acc.clone();
    let page: NexRoute = get("/account/security", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let notice = if cx.query("used")?.as_deref() == Some("recovery") {
            "You signed in with a recovery code, and it is now used up. If you lost your authenticator app, turn two-step sign-in off and on again with a new one, and make new recovery codes."
        } else {
            ""
        };
        s.security_page(cx, user, "", notice)
    })
    .allow(SIGNED_IN)
    .template("admin/security")
    .name("account-security");

    let s = acc.clone();
    let password: NexRoute = post("/account/password", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let form: PasswordForm = cx.form()?;
        if form.new.expose() != form.again.expose() {
            cx.status(422);
            return s.security_page(cx, user, "The two new passwords are not the same.", "");
        }
        let Some(_slot) = hash_slot(&s.hashing) else {
            cx.set_header("retry-after", "2");
            return Err(web_net::Error::unavailable("auth.busy"));
        };
        match s
            .auth
            .change_password(user, form.current.expose(), form.new.expose(), &from(cx))
            .map_err(store)?
        {
            Ok(set) => {
                cx.set_header("set-cookie", set);
                let who = s.who(user);
                crate::events::audit(&who, "password_changed", &who);
                s.security_page(
                    cx,
                    user,
                    "",
                    "Your password is changed. You are signed out everywhere else, and your API keys are revoked.",
                )
            }
            Err(why) => {
                cx.status(422);
                s.security_page(cx, user, &why, "")
            }
        }
    })
    .allow(SIGNED_IN)
    .template("admin/security")
    .name("account-password");

    let s = acc.clone();
    let everywhere: NexRoute = post("/account/sign-out-everywhere", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let who = s.who(user);
        s.auth.sign_out_everywhere(user).map_err(store)?;
        crate::events::audit(&who, "signed_out_everywhere", &who);
        cx.set_header("set-cookie", clear(SESSION_COOKIE));
        cx.set_header("set-cookie", clear(DEVICE_COOKIE));
        cx.redirect(303, "/")
    })
    .allow(SIGNED_IN)
    .name("account-sign-out-everywhere");

    let s = acc.clone();
    let devices: NexRoute = post("/account/forget-devices", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        s.auth.forget_devices(user).map_err(store)?;
        let who = s.who(user);
        crate::events::audit(&who, "devices_forgotten", &who);
        cx.set_header("set-cookie", clear(DEVICE_COOKIE));
        s.security_page(
            cx,
            user,
            "",
            "Every remembered device asks for a code again.",
        )
    })
    .allow(SIGNED_IN)
    .template("admin/security")
    .name("account-forget-devices");

    let s = acc.clone();
    let revoke: NexRoute = post("/account/sessions/revoke", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let form: SessionForm = cx.form()?;
        let who = s.who(user);
        if s.auth
            .revoke_session(user, form.session.trim())
            .map_err(store)?
        {
            crate::events::audit(&who, "session_revoked", &who);
            s.security_page(cx, user, "", "That session is signed out.")
        } else {
            cx.status(404);
            s.security_page(cx, user, "That session has already ended.", "")
        }
    })
    .allow(SIGNED_IN)
    .template("admin/security")
    .name("account-session-revoke");

    let s = acc.clone();
    let others: NexRoute = post(
        "/account/sessions/revoke-others",
        move |cx: &mut NexCx<'_>| {
            let user = me(cx)?;
            let this = cx
                .identity()
                .identity
                .session()
                .ok_or_else(|| web_net::Error::forbidden("account.no_session"))?;
            let n = s.auth.revoke_others(user, this).map_err(store)?;
            let who = s.who(user);
            crate::events::audit(&who, "other_sessions_revoked", &who);
            let notice = match n {
                0 => "There were no other sessions.".to_owned(),
                1 => "One other session is signed out.".to_owned(),
                n => format!("{n} other sessions are signed out."),
            };
            s.security_page(cx, user, "", &notice)
        },
    )
    .allow(SIGNED_IN)
    .template("admin/security")
    .name("account-session-revoke-others");

    let mut routes = vec![page, password, everywhere, devices, revoke, others];
    routes.extend(two_factor_routes(acc));
    if acc.api {
        routes.extend(key_routes(acc));
    }
    routes
}

/// Making and revoking API keys.
fn key_routes(acc: &Accounts) -> Vec<NexRoute> {
    let s = acc.clone();
    let make: NexRoute = post("/account/keys", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let form: KeyForm = cx.form()?;
        let refused = |cx: &mut NexCx<'_>, why: &str| {
            cx.status(422);
            s.security_page(cx, user, why, "")
        };
        let scopes = match crate::nex::Scopes::parse(form.scopes.iter().map(String::as_str)) {
            Ok(scopes) => scopes,
            Err(why) => return refused(cx, &why),
        };
        let Ok(days) = form.days.trim().parse::<u32>() else {
            return refused(cx, "Choose how long the key lasts.");
        };
        // The password, so a session someone else got hold of cannot make
        // a key that outlives it.
        let Some(_slot) = hash_slot(&s.hashing) else {
            cx.set_header("retry-after", "2");
            return Err(web_net::Error::unavailable("auth.busy"));
        };
        if form.password.is_empty() || !s.auth.password_is(user, &form.password).map_err(store)? {
            return refused(cx, "The password is not right.");
        }
        match s
            .auth
            .create_api_key(user, &form.label, scopes, days)
            .map_err(store)?
        {
            Ok(new) => {
                let who = s.who(user);
                crate::events::audit_with(
                    &who,
                    "api_key_made",
                    &who,
                    &format!("{} {}", new.row.id, new.row.label),
                );
                guard(cx);
                let view = Security {
                    notice: format!(
                        "Made the key {}. It works until {}.",
                        new.row.label,
                        when(new.row.expires)
                    ),
                    new_key: new.text.clone(),
                    ..s.view(cx, user)?
                };
                cx.render_named("admin/security", &s.pages.security_page("Security", view))
            }
            Err(why) => refused(cx, &why),
        }
    })
    .allow(SIGNED_IN)
    .template("admin/security")
    .name("account-key-make");

    let s = acc.clone();
    let revoke: NexRoute = post("/account/keys/revoke", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let form: KeyRevokeForm = cx.form()?;
        let id = form.key.trim();
        match s.auth.revoke_api_key(user, id).map_err(store)? {
            Some(label) => {
                let who = s.who(user);
                crate::events::audit_with(&who, "api_key_revoked", &who, &format!("{id} {label}"));
                s.security_page(
                    cx,
                    user,
                    "",
                    &format!("Revoked the key {label}. It no longer works."),
                )
            }
            None => {
                cx.status(404);
                s.security_page(
                    cx,
                    user,
                    "That key is not one of yours, or it was revoked already.",
                    "",
                )
            }
        }
    })
    .allow(SIGNED_IN)
    .template("admin/security")
    .name("account-key-revoke");

    vec![make, revoke]
}

/// Turning two-step sign-in on and off, and new recovery codes.
#[cfg(feature = "mfa")]
fn two_factor_routes(acc: &Accounts) -> Vec<NexRoute> {
    let enroll_page = |s: &Accounts,
                       cx: &mut NexCx<'_>,
                       user: UserId,
                       fresh: bool,
                       error: &str|
     -> web_net::Result {
        guard(cx);
        let (secret, uri) = if fresh {
            let (secret, uri) = s
                .auth
                .start_totp(user, s.pages.site_name())
                .map_err(store)?;
            (secret.to_string(), uri.to_string())
        } else {
            (String::new(), String::new())
        };
        let view = Security {
            error: error.to_owned(),
            action: cx.url("/account/two-factor")?,
            ask_password: true,
            secret,
            uri,
            ..s.view(cx, user)?
        };
        cx.render_named(
            "admin/two-factor",
            &s.pages.security_page("Turn on two-step sign-in", view),
        )
    };

    let s = acc.clone();
    let start: NexRoute = get("/account/two-factor", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let rules = s.auth.rules(user).map_err(store)?;
        if rules.mfa == MfaMode::Off {
            return Err(web_net::Error::not_found("account.two_factor_off"));
        }
        if s.auth.totp_on(user).map_err(store)? {
            return cx.redirect(303, "/account/security");
        }
        enroll_page(&s, cx, user, true, "")
    })
    .allow(SIGNED_IN)
    .template("admin/two-factor")
    .name("account-two-factor");

    let s = acc.clone();
    let confirm: NexRoute = post("/account/two-factor", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let form: EnrollForm = cx.form()?;
        if s.auth.rules(user).map_err(store)?.mfa == MfaMode::Off {
            return Err(web_net::Error::not_found("account.two_factor_off"));
        }
        if s.auth.totp_on(user).map_err(store)? {
            return cx.redirect(303, "/account/security");
        }
        let Some(_slot) = hash_slot(&s.hashing) else {
            cx.set_header("retry-after", "2");
            return Err(web_net::Error::unavailable("auth.busy"));
        };
        if !s
            .auth
            .password_is(user, form.password.expose())
            .map_err(store)?
        {
            cx.status(422);
            return enroll_page(&s, cx, user, false, "The password is not right.");
        }
        match s.auth.confirm_totp(user, &form.code).map_err(store)? {
            Some(codes) => {
                let who = s.who(user);
                crate::events::audit(&who, "two_step_on", &who);
                guard(cx);
                let view = Security {
                    codes,
                    next: cx.url("/account/security")?,
                    notice: "Two-step sign-in is on.".to_owned(),
                    ..s.view(cx, user)?
                };
                cx.render_named(
                    "admin/codes",
                    &s.pages.security_page("Your recovery codes", view),
                )
            }
            None => {
                cx.status(422);
                enroll_page(
                    &s,
                    cx,
                    user,
                    false,
                    "That code is not right. Check the time on your phone, then type the code the app shows now.",
                )
            }
        }
    })
    .allow(SIGNED_IN)
    .template("admin/two-factor")
    .name("account-two-factor-post");

    let s = acc.clone();
    let off: NexRoute = post("/account/two-factor/off", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let form: PasswordOnly = cx.form()?;
        if s.auth.rules(user).map_err(store)?.mfa == MfaMode::Required {
            cx.status(403);
            return s.security_page(
                cx,
                user,
                "Your account needs two-step sign-in: it cannot be turned off.",
                "",
            );
        }
        let Some(_slot) = hash_slot(&s.hashing) else {
            cx.set_header("retry-after", "2");
            return Err(web_net::Error::unavailable("auth.busy"));
        };
        if !s
            .auth
            .password_is(user, form.password.expose())
            .map_err(store)?
        {
            cx.status(422);
            return s.security_page(cx, user, "The password is not right.", "");
        }
        s.auth.remove_totp(user).map_err(store)?;
        let who = s.who(user);
        crate::events::audit(&who, "two_step_off", &who);
        cx.set_header("set-cookie", clear(DEVICE_COOKIE));
        s.security_page(cx, user, "", "Two-step sign-in is off.")
    })
    .allow(SIGNED_IN)
    .template("admin/security")
    .name("account-two-factor-off");

    let s = acc.clone();
    let codes: NexRoute = post("/account/recovery-codes", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        let form: PasswordOnly = cx.form()?;
        if !s.auth.totp_on(user).map_err(store)? {
            return cx.redirect(303, "/account/security");
        }
        let Some(_slot) = hash_slot(&s.hashing) else {
            cx.set_header("retry-after", "2");
            return Err(web_net::Error::unavailable("auth.busy"));
        };
        if !s
            .auth
            .password_is(user, form.password.expose())
            .map_err(store)?
        {
            cx.status(422);
            return s.security_page(cx, user, "The password is not right.", "");
        }
        let codes = s.auth.recovery_codes(user).map_err(store)?;
        let who = s.who(user);
        crate::events::audit(&who, "recovery_codes_made", &who);
        guard(cx);
        let view = Security {
            codes,
            next: cx.url("/account/security")?,
            notice: "New recovery codes. The old ones no longer work.".to_owned(),
            ..s.view(cx, user)?
        };
        cx.render_named(
            "admin/codes",
            &s.pages.security_page("Your recovery codes", view),
        )
    })
    .allow(SIGNED_IN)
    .template("admin/codes")
    .name("account-recovery-codes");

    vec![start, confirm, off, codes]
}

#[cfg(not(feature = "mfa"))]
fn two_factor_routes(_acc: &Accounts) -> Vec<NexRoute> {
    Vec::new()
}

/// The administrator's account routes.
fn admin_routes(acc: &Accounts) -> Vec<NexRoute> {
    let list = |s: &Accounts,
                cx: &mut NexCx<'_>,
                user: UserId,
                error: &str,
                notice: &str|
     -> web_net::Result {
        guard(cx);
        let boot = s.boot.as_deref().map(|b| b.trim().to_lowercase());
        let rows = s.auth.account_rows().map_err(store)?;
        let accounts = rows
            .into_iter()
            .map(|r| {
                Arc::new(AccountView {
                    id: format!("{:032x}", r.user.0),
                    managed: r.user != user && boot.as_deref() != Some(r.identifier.as_str()),
                    identifier: r.identifier,
                    roles: r.roles.join(", "),
                    standing: r.standing.to_owned(),
                    totp: r.totp,
                })
            })
            .collect();
        let view = Security {
            error: error.to_owned(),
            notice: notice.to_owned(),
            accounts: Arc::new(accounts),
            disable: cx.url("/admin/accounts/disable")?,
            enable: cx.url("/admin/accounts/enable")?,
            remove: cx.url("/admin/accounts/remove")?,
            ..s.view(cx, user)?
        };
        cx.render_named("admin/accounts", &s.pages.security_page("Accounts", view))
    };

    let s = acc.clone();
    let page: NexRoute = get("/admin/accounts", move |cx: &mut NexCx<'_>| {
        let user = me(cx)?;
        list(&s, cx, user, "", "")
    })
    .allow(ADMINING)
    .template("admin/accounts")
    .name("admin-accounts");

    let action = |path: &'static str, name: &'static str, what: &'static str| {
        let s = acc.clone();
        post(path, move |cx: &mut NexCx<'_>| {
            let user = me(cx)?;
            let form: AccountForm = cx.form()?;
            let target = u128::from_str_radix(form.account.trim(), 16)
                .ok()
                .filter(|_| form.account.trim().len() == 32)
                .map(UserId)
                .ok_or_else(|| web_net::Error::unprocessable("admin.account"))?;
            let Some(identifier) = s.auth.identifier_of(target).map_err(store)? else {
                return Err(web_net::Error::not_found("admin.unknown_account"));
            };
            let boot = s
                .boot
                .as_deref()
                .is_some_and(|b| b.trim().eq_ignore_ascii_case(&identifier));
            if target == user || boot {
                cx.status(403);
                return list(
                    &s,
                    cx,
                    user,
                    "Your own account and the boot account cannot be changed here.",
                    "",
                );
            }
            let notice = match what {
                "disable" => {
                    s.auth.disable(target, user).map_err(store)?;
                    "account_disabled"
                }
                "enable" => {
                    if !s.auth.enable(target, user).map_err(store)? {
                        cx.status(422);
                        return list(
                            &s,
                            cx,
                            user,
                            "Only a disabled or locked account can be enabled here.",
                            "",
                        );
                    }
                    "account_enabled"
                }
                _ => {
                    if !form.confirm {
                        cx.status(422);
                        return list(&s, cx, user, "Tick the box to confirm the removal.", "");
                    }
                    s.auth.remove(target).map_err(store)?;
                    "account_removed"
                }
            };
            crate::events::audit(&s.who(user), notice, &identifier);
            cx.redirect(303, "/admin/accounts")
        })
        .allow(ADMINING)
        .template("admin/accounts")
        .name(name)
    };

    vec![
        page,
        action(
            "/admin/accounts/disable",
            "admin-accounts-disable",
            "disable",
        ),
        action("/admin/accounts/enable", "admin-accounts-enable", "enable"),
        action("/admin/accounts/remove", "admin-accounts-remove", "remove"),
    ]
}

/// Every account and sign-in security route.
#[must_use]
pub(crate) fn routes(acc: &Accounts) -> Vec<NexRoute> {
    let mut all = sign_in_routes(acc);
    all.extend(own_routes(acc));
    all.extend(admin_routes(acc));
    all
}
