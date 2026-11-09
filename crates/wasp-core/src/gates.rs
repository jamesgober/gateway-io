//! The gates seam: authentication in the core, authorization at the router.
//!
//! The traits decide; the core moves the passport. An [`Authenticator`] reads
//! the inspected request and returns an identity (or a refusal for a ban); the
//! core writes the identity stamp and turns the passport into
//! `Passport<Identified>`. An [`Authorizer`] reads the identified request, its
//! identity, and the matched route's [`Rule`], and allows or denies; [`Access`]
//! writes the access stamp and turns it into `Passport<Cleared>`. No
//! implementation of either trait can produce a passport of the next stage
//! itself, so a gate that forgets to run, or a stub that tries to skip one,
//! cannot hand a service an unchecked passport.

use std::any::Any;
use std::sync::Arc;

use crate::identity::{Identity, PermSet};
use crate::passport::{Exit, Passport, RequestView};
use crate::profile::Profile;
use crate::slot::{AccessStamp, Refusal};
use crate::stage::{Cleared, Identified};

/// What authentication decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authentication {
    /// The request continues with this identity (a guest when the credential
    /// was missing or did not check out: a bad credential alone never stops a
    /// request).
    Identified(Identity),
    /// Banned (timed or permanent): refused here, before any service code.
    Refused(Refusal),
}

/// The gate's own identity token, kept in the passport for services that
/// authorize with the gate directly (the web service hands it to web-net).
pub type GateToken = Box<dyn Any + Send + Sync>;

/// What authentication hands to the rest of the request besides its decision.
///
/// - a `Set-Cookie` value the response must carry, whatever the outcome (an
///   answer, a refusal, a cached page): for example clearing the cookie of a
///   session that no longer exists;
/// - the gate's own identity token ([`keep`](Self::keep)), for services that
///   authorize with the gate itself.
///
/// The cookie buffer is reused per passport and wiped with it; the token is
/// dropped when the passport returns to the pool.
#[derive(Debug)]
pub struct AuthOut {
    cookie: Vec<u8>,
    token: Option<GateToken>,
}

impl AuthOut {
    pub(crate) fn from_parts(mut cookie: Vec<u8>) -> AuthOut {
        cookie.clear();
        AuthOut {
            cookie,
            token: None,
        }
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, Option<GateToken>) {
        (self.cookie, self.token)
    }

    /// Sets the `Set-Cookie` value (the field value only, without the name).
    pub fn set_cookie(&mut self, value: &[u8]) {
        self.cookie.clear();
        self.cookie.extend_from_slice(value);
    }

    /// Whether a cookie was set.
    #[must_use]
    pub fn has_cookie(&self) -> bool {
        !self.cookie.is_empty()
    }

    /// Keeps the gate's own identity token with the request (replacing one
    /// kept before).
    pub fn keep<T: Any + Send + Sync>(&mut self, token: T) {
        self.token = Some(Box::new(token));
    }

    /// Whether a token was kept.
    #[must_use]
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }
}

/// Authentication: the ID check, run by the core once per request.
pub trait Authenticator: Send + Sync + 'static {
    /// Reads the credential where `profile.locator` says it is and decides.
    /// A `Set-Cookie` the response must carry, and the gate's own identity
    /// token, go into `out`. Must not block on the network: a remote store
    /// answers from local state when it is unreachable.
    fn authenticate(
        &self,
        request: RequestView<'_>,
        profile: &Profile,
        out: &mut AuthOut,
    ) -> Authentication;
}

/// The first authenticator: every request is a guest. Correct, only minimal:
/// nothing can be signed in, so nothing is wrongly trusted.
#[derive(Clone, Copy, Debug, Default)]
pub struct EveryoneGuest;

impl Authenticator for EveryoneGuest {
    #[inline]
    fn authenticate(
        &self,
        _request: RequestView<'_>,
        _profile: &Profile,
        _out: &mut AuthOut,
    ) -> Authentication {
        Authentication::Identified(Identity::guest())
    }
}

/// A compiled route rule: who may use the route. The access gate compiles
/// configuration into these at boot; the router holds them per route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    id: u32,
    guests: bool,
    needs: PermSet,
}

impl Rule {
    /// Anyone, guests included.
    #[must_use]
    pub const fn public(id: u32) -> Rule {
        Rule {
            id,
            guests: true,
            needs: PermSet::NONE,
        }
    }

    /// Signed-in accounts holding every permission in `needs`.
    #[must_use]
    pub const fn needs(id: u32, needs: PermSet) -> Rule {
        Rule {
            id,
            guests: false,
            needs,
        }
    }

    /// The rule's id, written into the access stamp.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Whether guests may use the route.
    #[must_use]
    pub const fn allows_guests(&self) -> bool {
        self.guests
    }

    /// The permissions a signed-in account needs.
    #[must_use]
    pub const fn needed(&self) -> PermSet {
        self.needs
    }
}

/// What authorization decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The rule passed.
    Allow,
    /// Refused: 401 for a guest that must sign in, 403 for a signed-in account
    /// without the permission.
    Deny(Refusal),
}

/// Authorization: checks the matched route's rule, once per request.
///
/// It decides on the identity and the rule alone (checks against a specific
/// object, such as "owner of this post", belong to the handler that loaded
/// the object), so the same authorizer serves passport services and services
/// that answer on the protocol's own types.
pub trait Authorizer: Send + Sync + 'static {
    /// Decides whether `identity` may use the route `rule` protects.
    fn authorize(&self, identity: &Identity, rule: &Rule) -> Decision;
}

/// The first authorizer: the rule's own terms and nothing else. Guests pass
/// public rules; signed-in accounts pass rules whose permissions they hold.
#[derive(Clone, Copy, Debug, Default)]
pub struct RuleTerms;

impl Authorizer for RuleTerms {
    #[inline]
    fn authorize(&self, identity: &Identity, rule: &Rule) -> Decision {
        if rule.allows_guests() {
            return Decision::Allow;
        }
        if identity.is_guest() {
            return Decision::Deny(Refusal::status(401));
        }
        if identity.perms().contains(rule.needed()) {
            Decision::Allow
        } else {
            Decision::Deny(Refusal::status(403))
        }
    }
}

/// The access gate's handle, given to each service at boot. The only way to a
/// cleared passport.
#[derive(Clone)]
pub struct Access {
    authorizer: Arc<dyn Authorizer>,
}

impl Access {
    /// Wraps an authorizer.
    #[must_use]
    pub fn new(authorizer: impl Authorizer) -> Access {
        Access {
            authorizer: Arc::new(authorizer),
        }
    }

    /// Wraps a shared authorizer.
    #[must_use]
    pub fn from_arc(authorizer: Arc<dyn Authorizer>) -> Access {
        Access { authorizer }
    }

    /// Authorizes the passport for `rule`, or refuses it. Use with `?`:
    /// a refusal goes straight to the response pipeline.
    #[inline]
    pub fn authorize(
        &self,
        p: Passport<Identified>,
        rule: &Rule,
    ) -> Result<Passport<Cleared>, Exit> {
        match self.authorizer.authorize(p.identity(), rule) {
            Decision::Allow => Ok(p.clear(AccessStamp { rule: rule.id() })),
            Decision::Deny(refusal) => Err(p.refuse_with(refusal)),
        }
    }

    /// The decision alone, for a service that answers on the protocol's own
    /// types (the web service): it holds no passport, so it gets a decision
    /// and enforces it itself.
    #[inline]
    #[must_use]
    pub fn check(&self, identity: &Identity, rule: &Rule) -> Decision {
        self.authorizer.authorize(identity, rule)
    }
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Access")
    }
}
