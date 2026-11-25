//! The site behind nex-db (`auth.store = "nex"`): accounts and sessions are
//! durable, the core authenticates with [`NexAuth`], and web-net authorizes
//! routes through the core's access gate and checks every form's CSRF token
//! with its own engine.
//!
//! A guest's first visit to the sign-in page sets a pre-session cookie and
//! comes back to it, so the sign-in form's token is bound to that visitor;
//! a signed-in visitor's tokens are bound to the session.
//!
//! The content editor is here too, for accounts with the `editor` role:
//!
//! | Path | What |
//! |---|---|
//! | `GET /admin` | every entry, with links to edit it and to write a new one |
//! | `GET /admin/new/post`, `/admin/new/page` | an empty entry form (a post is dated today) |
//! | `GET /admin/edit/:slug` | the entry form, filled in |
//! | `POST /admin/save` | saves (422 with the form again when a rule is broken), then 303 to the entry |
//! | `POST /admin/delete` | removes the entry, then 303 to `/admin` |
//!
//! Every form carries web-net's CSRF token; the editor's pages are never
//! cached (`Cache-Control: no-store`).

use std::sync::Arc;

use gateway_io::{Caller, WebGate};
use wasp_core::{Access, Decision, Identity, PermSet, Rule};
use web_net::form_net;
use web_net::{App, Context, Denial, Gate, Request, Route, get, post};

use crate::content::{Content, Draft, Entry, Kind, Meta, SaveError, StoreError};
use crate::nex::{NexAuth, NexToken, PRE_COOKIE, SESSION, SESSION_COOKIE, Via, cookie};
use crate::site::{Pages, SiteSettings, configure, content_routes, query_value};
use crate::site_account::{Accounts, CookieKeys};
use crate::theme::{Choice, Editor, FieldInput, Form, SiteEngine};

/// The permission the account page needs (the `member` role's bit).
pub const MEMBER: PermSet = PermSet(1);

/// The permission the content editor needs (the `editor` role's bit).
pub const EDITOR: PermSet = PermSet(2);

/// The permission the accounts page needs (the `admin` role's bit).
pub const ADMIN: PermSet = PermSet(4);

/// The editor's rule.
const EDITING: Rule = Rule::needs(4, PermSet(EDITOR.0 | SESSION.0));

/// The account page's rule: a member, signed in with a session cookie.
const MEMBER_PAGE: Rule = Rule::needs(2, PermSet(MEMBER.0 | SESSION.0));

/// Who a request is from, as web-net sees it on this site.
#[derive(Clone, Copy, Debug)]
pub struct NexWho {
    /// The core's identity stamp.
    pub identity: Identity,
    token: NexToken,
}

impl NexWho {
    /// How the caller came in: a browser, or a program with an API key.
    #[must_use]
    pub fn via(&self) -> Via {
        self.token.via()
    }
}

impl web_net::Identity for NexWho {
    fn is_guest(&self) -> bool {
        self.identity.is_guest()
    }

    fn csrf_binding(&self) -> Option<&[u8]> {
        let b = self.token.binding();
        (!b.is_empty()).then_some(b)
    }
}

/// web-net's gate for the site: the core authenticated (with [`NexAuth`]);
/// routes are authorized by the core's access gate.
#[derive(Clone, Debug)]
pub struct NexGate {
    access: Access,
}

impl Gate for NexGate {
    type Identity = NexWho;
    type Rule = Rule;

    fn authenticate(&self, _req: &Request<'_>) -> Result<NexWho, Denial> {
        Err(Denial::with_status(500, "gateway.authenticates_in_core"))
    }

    fn authorize(&self, who: &NexWho, rule: &Rule, _req: &Request<'_>) -> Result<(), Denial> {
        match self.access.check(&who.identity, rule) {
            Decision::Allow => Ok(()),
            Decision::Deny(refusal) => Err(match refusal.status {
                401 => Denial::sign_in("access.sign_in"),
                404 => Denial::hidden("access.hidden"),
                _ => Denial::forbidden("access.forbidden"),
            }),
        }
    }
}

impl WebGate for NexGate {
    fn with_identity<R>(caller: &Caller<'_>, f: impl FnOnce(&NexWho) -> R) -> Option<R> {
        let token = caller
            .token::<NexToken>()
            .copied()
            .unwrap_or_else(NexToken::empty);
        Some(f(&NexWho {
            identity: *caller.identity(),
            token,
        }))
    }
}

/// A handler's context on this site.
pub type NexCx<'a> = Context<'a, NexWho, SiteEngine>;

/// The site's app type.
pub type NexApp = App<NexGate, SiteEngine>;

/// A route on this site.
pub type NexRoute = Route<NexWho, Rule, SiteEngine>;

/// The entry form (web-net checked its `csrf_token` before the handler):
/// the built-in fields, the search and sharing fields, and the declared
/// custom fields (`f_<name>`), each at most once. Written by hand so the
/// custom fields, which the configuration declares, come through; any other
/// name is refused.
#[derive(Debug, Default)]
struct EntryForm {
    kind: String,
    slug: String,
    was: String,
    title: String,
    summary: String,
    date: String,
    body: String,
    meta: Meta,
    fields: Vec<(String, String)>,
}

/// The most custom fields one save carries.
const FORM_FIELDS: usize = 2 * crate::content::MAX_FIELDS;

#[derive(Default)]
struct EntryFormBuilder {
    form: EntryForm,
    seen: std::collections::HashSet<String>,
}

impl form_net::FormBuilder for EntryFormBuilder {
    type Output = EntryForm;

    fn text(&mut self, name: &str, value: &str) -> Result<(), form_net::FormError> {
        use form_net::{ExtractError, FormError};
        let refuse = |reason| FormError::Extract {
            reason,
            field: None,
        };
        if name == "csrf_token" {
            return Ok(());
        }
        if !self.seen.insert(name.to_owned()) {
            return Err(refuse(ExtractError::Duplicate));
        }
        let f = &mut self.form;
        let slot = match name {
            "kind" => &mut f.kind,
            "slug" => &mut f.slug,
            "was" => &mut f.was,
            "title" => &mut f.title,
            "summary" => &mut f.summary,
            "date" => &mut f.date,
            "body" => &mut f.body,
            other => {
                if let Some(m) = f.meta.get_mut(other) {
                    m
                } else if let Some(custom) = other.strip_prefix(crate::content::FIELD_PREFIX) {
                    if f.fields.len() >= FORM_FIELDS {
                        return Err(refuse(ExtractError::Invalid("too many fields")));
                    }
                    f.fields.push((custom.to_owned(), value.to_owned()));
                    return Ok(());
                } else {
                    return Err(refuse(ExtractError::Unknown));
                }
            }
        };
        value.clone_into(slot);
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

    fn finish(self) -> Result<EntryForm, form_net::FormError> {
        for required in ["kind", "slug", "title", "body"] {
            if !self.seen.contains(required) {
                return Err(form_net::FormError::Extract {
                    reason: form_net::ExtractError::Missing,
                    field: Some(match required {
                        "kind" => "kind",
                        "slug" => "slug",
                        "title" => "title",
                        _ => "body",
                    }),
                });
            }
        }
        Ok(self.form)
    }
}

impl form_net::FromForm for EntryForm {
    type Builder = EntryFormBuilder;
}

impl EntryForm {
    /// The search and sharing fields as typed.
    fn meta(&self) -> Meta {
        self.meta.clone()
    }
}

form_net::form! {
    /// The delete button.
    struct DeleteForm {
        slug: String,
    }
    ignore = ["csrf_token"];
}

/// The editor's view for this request: every entry, the form's addresses,
/// and the token; the entry fields empty.
fn editor(cx: &mut NexCx<'_>, pages: &Pages) -> Result<Editor, web_net::Error> {
    // Never kept by a browser or a cache in front of the site, and held to
    // the admin pages' own content security policy.
    cx.set_header("cache-control", "no-store");
    cx.set_header("content-security-policy", crate::theme::ADMIN_CSP);
    Ok(Editor {
        entries: Arc::new(pages.content.snapshot().all()),
        save: cx.url("/admin/save")?,
        delete: cx.url("/admin/delete")?,
        new_post: cx.url("/admin/new/post")?,
        new_page: cx.url("/admin/new/page")?,
        csrf: cx.csrf_token()?,
        admin: cx.identity().identity.perms().contains(ADMIN),
        ..Editor::default()
    })
}

/// The editor with the declared fields of `kind`, filled from `values`.
fn with_fields(editor: Editor, pages: &Pages, kind: Kind, values: &[(String, String)]) -> Editor {
    let snapshot = pages.content.snapshot();
    let inputs = snapshot
        .fields()
        .of(kind)
        .iter()
        .map(|d| {
            let value = values
                .iter()
                .find(|(n, _)| *n == d.name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            Arc::new(FieldInput {
                name: format!("{}{}", crate::content::FIELD_PREFIX, d.name),
                label: d.label.clone(),
                kind: d.kind.as_str().to_owned(),
                options: d
                    .options
                    .iter()
                    .map(|o| Choice {
                        value: o.clone(),
                        selected: *o == value,
                    })
                    .collect(),
                value,
                required: d.required,
                help: d.help.clone(),
            })
        })
        .collect();
    Editor {
        fields: Arc::new(inputs),
        ..editor
    }
}

/// The editor's form filled in from a stored entry.
fn filled(editor: Editor, entry: &Entry) -> Editor {
    Editor {
        existing: true,
        kind: entry.kind.clone(),
        slug: entry.slug.clone(),
        was: entry.slug.clone(),
        title: entry.title.clone(),
        summary: entry.summary.clone(),
        date: entry.date.clone(),
        body: entry.text.clone(),
        meta: entry.meta.clone(),
        ..editor
    }
}

/// A store failure as the editor sees it: 503 when it may pass, else 500.
fn store_failed(e: &StoreError) -> web_net::Error {
    if e.is_retryable() {
        web_net::Error::unavailable("content.unavailable")
    } else {
        web_net::Error::internal("content.store")
    }
}

/// The site path of an entry, for the redirect after a save.
fn path_of(kind: Kind, slug: &str) -> String {
    match kind {
        Kind::Post => format!("/posts/{slug}"),
        Kind::Page => format!("/{slug}"),
    }
}

/// The content editor's routes.
fn editor_routes(pages: &Pages) -> [NexRoute; 5] {
    let p = pages.clone();
    let list: NexRoute = get("/admin", move |cx: &mut NexCx<'_>| {
        let view = editor(cx, &p)?;
        cx.render(&p.editor_page("Content", view))
    })
    .allow(EDITING)
    .template("admin/list")
    .name("admin");

    let p = pages.clone();
    let new_entry: NexRoute = get("/admin/new/:kind", move |cx: &mut NexCx<'_>| {
        let kind = cx.param("kind")?.into_owned();
        let (title, date) = match kind.as_str() {
            "post" => ("New post", crate::content::today()),
            "page" => ("New page", String::new()),
            _ => return Err(web_net::Error::not_found("admin.kind")),
        };
        let of = if kind == "post" {
            Kind::Post
        } else {
            Kind::Page
        };
        let view = with_fields(
            Editor {
                kind,
                date,
                ..editor(cx, &p)?
            },
            &p,
            of,
            &[],
        );
        cx.render(&p.editor_page(title, view))
    })
    .allow(EDITING)
    .template("admin/edit")
    .name("admin-new");

    let p = pages.clone();
    let edit: NexRoute = get("/admin/edit/:slug", move |cx: &mut NexCx<'_>| {
        let slug = cx.param("slug")?.into_owned();
        let Some(entry) = p.content.snapshot().find(&slug) else {
            return Err(crate::site::fail(
                cx,
                404,
                "admin.unknown",
                "No post or page has that slug. It may have been renamed or removed.",
            ));
        };
        let values: Vec<(String, String)> = entry
            .fields
            .iter()
            .map(|f| (f.name.clone(), f.value.clone()))
            .collect();
        let of = if entry.kind == "post" {
            Kind::Post
        } else {
            Kind::Page
        };
        let view = with_fields(filled(editor(cx, &p)?, &entry), &p, of, &values);
        cx.render(&p.editor_page(&format!("Edit {}", entry.title), view))
    })
    .allow(EDITING)
    .template("admin/edit")
    .name("admin-edit");

    let p = pages.clone();
    let save: NexRoute = post("/admin/save", move |cx: &mut NexCx<'_>| {
        let form: EntryForm = cx.form()?;
        let kind = match form.kind.as_str() {
            "post" => Kind::Post,
            "page" => Kind::Page,
            _ => return Err(web_net::Error::unprocessable("admin.kind")),
        };
        let draft = Draft {
            kind,
            slug: form.slug.trim(),
            title: form.title.trim(),
            summary: form.summary.trim(),
            body: &form.body,
            date: form.date.trim(),
            meta: form.meta(),
            fields: form.fields.clone(),
        };
        let was = form.was.trim();
        match p.content.save(&draft, (!was.is_empty()).then_some(was)) {
            Ok(()) => cx.redirect(303, &path_of(kind, draft.slug)),
            Err(SaveError::Invalid(why)) => {
                // The form again, as it was typed, with the reason.
                let view = Editor {
                    error: why.0,
                    existing: !was.is_empty(),
                    kind: form.kind.clone(),
                    slug: form.slug.clone(),
                    was: form.was.clone(),
                    title: form.title.clone(),
                    summary: form.summary.clone(),
                    date: form.date.clone(),
                    body: form.body.clone(),
                    meta: form.meta(),
                    ..editor(cx, &p)?
                };
                let view = with_fields(view, &p, kind, &form.fields);
                cx.status(422);
                cx.render(&p.editor_page("Not saved", view))
            }
            Err(SaveError::Store(e)) => Err(store_failed(&e)),
        }
    })
    .allow(EDITING)
    .template("admin/edit")
    .name("admin-save");

    let p = pages.clone();
    let delete: NexRoute = post("/admin/delete", move |cx: &mut NexCx<'_>| {
        let form: DeleteForm = cx.form()?;
        p.content
            .remove(form.slug.trim())
            .map_err(|e| store_failed(&e))?;
        cx.redirect(303, "/admin")
    })
    .allow(EDITING)
    .name("admin-delete");

    [list, new_entry, edit, save, delete]
}

/// Client addresses tracked at once; past it the stalest entries go.
const TRACKED: usize = 10_000;

/// Passwords hashed at once (Argon2id, tens of milliseconds each): a flood
/// of sign-ins holds at most this many workers, and the rest answer 503.
pub const HASHING: usize = 2;

/// Sign-in attempts per client address (`auth.lockout.address_attempts`
/// per `address_window`): past it the address waits, before any password is
/// hashed.
#[derive(Debug, Default)]
pub(crate) struct Attempts(
    std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (std::time::Instant, u32)>>,
);

impl Attempts {
    /// Counts one attempt from `client`: `false` when it is over `limit`
    /// within `window`.
    pub(crate) fn admit(
        &self,
        client: std::net::IpAddr,
        now: std::time::Instant,
        limit: u32,
        window: std::time::Duration,
    ) -> bool {
        let mut map = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= TRACKED && !map.contains_key(&client) {
            map.retain(|_, (since, _)| now.duration_since(*since) < window);
            if map.len() >= TRACKED {
                let stalest = map
                    .iter()
                    .min_by_key(|(_, (since, _))| *since)
                    .map(|(a, _)| *a);
                if let Some(a) = stalest {
                    map.remove(&a);
                }
            }
        }
        let entry = map.entry(client).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= limit
    }
}

/// A slot for hashing one password, given back when dropped.
pub(crate) struct HashSlot<'a>(&'a std::sync::atomic::AtomicUsize);

pub(crate) fn hash_slot(busy: &std::sync::atomic::AtomicUsize) -> Option<HashSlot<'_>> {
    use std::sync::atomic::Ordering;
    let mut n = busy.load(Ordering::Acquire);
    while n < HASHING {
        match busy.compare_exchange_weak(n, n + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(HashSlot(busy)),
            Err(now) => n = now,
        }
    }
    None
}

impl Drop for HashSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn random_hex() -> Result<String, web_net::Error> {
    let bytes = crypt_io::generate_key().map_err(|_| web_net::Error::internal("random"))?;
    Ok(bytes[..16].iter().map(|b| format!("{b:02x}")).collect())
}

/// The keys the nex-db site derives from the master secret, and its boot
/// account.
#[derive(Debug)]
pub struct SiteKeys {
    /// The forms' CSRF key.
    pub csrf: crypt_io::Zeroizing<[u8; 32]>,
    /// The sealed sign-in cookies' keys.
    pub cookies: CookieKeys,
    /// The boot account (`auth.admin`), never disabled or removed from the
    /// accounts page.
    pub boot: Option<String>,
}

/// Builds the site behind nex-db's accounts.
pub fn build(
    auth: NexAuth,
    access: Access,
    content: Content,
    engine: SiteEngine,
    settings: &SiteSettings,
    keys: SiteKeys,
    ready: impl Fn() -> bool + Send + Sync + 'static,
) -> Result<NexApp, String> {
    let csrf_key = keys.csrf;
    let boot = keys.boot;
    // A theme without the messenger's page still serves the socket.
    let chat_page = web_net::Render::template(&engine, "chat").is_some();
    let pages = Pages::new(settings, content);
    // The key outlives a restart (`crate::secret`): a form opened before it
    // still posts after it.
    let csrf = web_net::csrf_sec::Csrf::new(*csrf_key).map_err(|e| format!("csrf: {e}"))?;
    let builder = configure(
        App::with_gate(NexGate { access }).render(engine).csrf(csrf),
        settings,
        ready,
    );

    let p = pages.clone();
    let account: NexRoute = get("/account", move |cx: &mut NexCx<'_>| {
        let user = match cx.identity().identity.subject() {
            wasp_core::Subject::User(u) => format!("{:032x}", u.0),
            _ => String::new(),
        };
        let form = Form {
            action: cx.url("/sign-out")?,
            csrf: cx.csrf_token()?,
            user,
            editor: cx.identity().identity.perms().contains(EDITOR),
            ..Form::default()
        };
        cx.render(&p.page("Account", None, "", Some(form)))
    })
    .allow(MEMBER_PAGE)
    .template("account")
    .name("account");

    let https_sign_in = settings.https_sign_in;
    let sign_in_form = {
        let p = pages.clone();
        move |cx: &mut NexCx<'_>, error: &str, email: &str| -> web_net::Result {
            // The form posts back here, keeping where to go after.
            let mut back = "/sign-in".to_owned();
            if let Some(next) = cx.next_path()? {
                back.push_str("?next=");
                back.push_str(&query_value(&cx.url(&next)?));
            }
            if https_sign_in && cx.request().scheme().as_str() != "https" {
                // The browser keeps no Secure cookie from a plain http page:
                // signing in works over https only.
                let url = format!("https://{}{}", cx.request().host(), cx.url(&back)?);
                return cx.redirect_external(303, &url);
            }
            if web_net::Identity::csrf_binding(cx.identity()).is_none() {
                if cx.query("cookies")?.is_some() {
                    // Came back without the cookie: the browser refuses it.
                    cx.status(400);
                    let form = Form {
                        error: "Signing in needs cookies. Please allow cookies for this site, then try again."
                            .to_owned(),
                        ..Form::default()
                    };
                    return cx.render(&p.page("Sign in", None, "", Some(form)));
                }
                // The first visit: a pre-session cookie, then the same page
                // (marked, so a browser that refuses the cookie is told
                // instead of sent round again), so the form's token is bound
                // to this visitor.
                let pre = random_hex()?;
                cx.set_header(
                    "set-cookie",
                    format!("{PRE_COOKIE}={pre}; Path=/; Secure; HttpOnly; SameSite=Lax"),
                );
                let again = if back.contains('?') {
                    format!("{back}&cookies=1")
                } else {
                    format!("{back}?cookies=1")
                };
                return cx.redirect(303, &again);
            }
            let action = cx.url(&back)?;
            let form = Form {
                action,
                csrf: cx.csrf_token()?,
                error: error.to_owned(),
                email: email.to_owned(),
                ..Form::default()
            };
            cx.render(&p.page("Sign in", None, "", Some(form)))
        }
    };

    let show = sign_in_form.clone();
    let sign_in: NexRoute = get("/sign-in", move |cx: &mut NexCx<'_>| {
        if !cx.identity().identity.is_guest() {
            let next = cx.next_path()?.unwrap_or_else(|| "/account".to_owned());
            return cx.redirect(303, &next);
        }
        show(cx, "", "")
    })
    .public()
    .template("sign-in")
    .name("sign-in");

    let accounts = Accounts {
        auth: auth.clone(),
        pages: pages.clone(),
        keys: keys.cookies,
        attempts: Arc::new(Attempts::default()),
        hashing: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        boot,
        show: Arc::new(sign_in_form),
        spent: Arc::default(),
        api: settings.api.enabled,
    };
    let a = auth;
    let sign_out: NexRoute = post("/sign-out", move |cx: &mut NexCx<'_>| {
        if let Some(token) = cx
            .header("cookie")
            .and_then(|h| cookie(h, SESSION_COOKIE))
            .map(str::to_owned)
        {
            let clear = a
                .sign_out(&token)
                .map_err(|_| web_net::Error::unavailable("auth.unavailable"))?;
            cx.set_header("set-cookie", clear);
        }
        cx.redirect(303, "/")
    })
    .allow(Rule::needs(3, SESSION))
    .name("sign-out");

    let [home, post_page, about, page] = content_routes::<NexWho, Rule>(&pages);
    let [list, new_entry, edit, save, delete] = editor_routes(&pages);
    let mut builder = builder
        .route(home)
        .route(post_page)
        .route(about)
        .route(page)
        .route(list)
        .route(new_entry)
        .route(edit)
        .route(save)
        .route(delete)
        .route(account)
        .route(sign_in)
        .route(sign_out);
    for route in crate::site_account::routes(&accounts) {
        builder = builder.route(route);
    }
    if settings.api.enabled {
        for route in crate::api::routes(&settings.api, &pages, &accounts.auth) {
            builder = builder.route(route);
        }
    }
    // The messenger's page, when the messenger is on and the theme has one.
    if let Some(socket) = settings.chat.as_ref().filter(|_| chat_page) {
        let socket = format!("{}{socket}", settings.base.trim_end_matches('/'));
        let p = pages.clone();
        let chat_page: NexRoute = get("/chat", move |cx: &mut NexCx<'_>| {
            let mut view = p.page("Messages", None, "", None);
            view.chat.clone_from(&socket);
            cx.set_header("cache-control", "no-store");
            cx.render(&view)
        })
        .allow(MEMBER_PAGE)
        .template("chat")
        .name("chat");
        builder = builder.route(chat_page);
    }
    builder.build().map_err(|e| format!("site: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    #[test]
    fn an_address_gets_its_attempts_per_window_and_no_more() {
        let a = Attempts::default();
        let ip: IpAddr = "198.51.100.7".parse().expect("ip");
        let other: IpAddr = "198.51.100.8".parse().expect("ip");
        let t = Instant::now();
        let window = Duration::from_secs(600);
        for _ in 0..10 {
            assert!(a.admit(ip, t, 10, window));
        }
        assert!(!a.admit(ip, t, 10, window), "over the limit");
        assert!(
            a.admit(other, t, 10, window),
            "another address is not affected"
        );
        assert!(
            a.admit(ip, t + window + Duration::from_secs(1), 10, window),
            "a new window"
        );
    }

    #[test]
    fn hashing_slots_are_bounded_and_given_back() {
        let busy = std::sync::atomic::AtomicUsize::new(0);
        let held: Vec<_> = (0..HASHING)
            .map(|_| hash_slot(&busy).expect("slot"))
            .collect();
        assert!(hash_slot(&busy).is_none(), "all slots in use");
        drop(held);
        assert!(hash_slot(&busy).is_some());
    }
}
