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

/// A `Set-Cookie` value authentication wants the response to carry, whatever
/// the outcome (an answer, a refusal, a cached page): for example clearing the
/// cookie of a session that no longer exists. Reused per passport and wiped
/// with it.
#[derive(Debug)]
pub struct AuthCookie {
    value: Vec<u8>,
}

impl AuthCookie {
    pub(crate) fn from_buf(mut value: Vec<u8>) -> AuthCookie {
        value.clear();
        AuthCookie { value }
    }

    pub(crate) fn into_buf(self) -> Vec<u8> {
        self.value
    }

    /// Sets the `Set-Cookie` value (the field value only, without the name).
    pub fn set(&mut self, value: &[u8]) {
        self.value.clear();
        self.value.extend_from_slice(value);
    }

    /// Whether a value was set.
    #[must_use]
    pub fn is_set(&self) -> bool {
        !self.value.is_empty()
    }
}

/// Authentication: the ID check, run by the core once per request.
pub trait Authenticator: Send + Sync + 'static {
    /// Reads the credential where `profile.locator` says it is and decides.
    /// A `Set-Cookie` the response must carry goes into `cookie`. Must not
    /// block on the network: a remote store answers from local state when it
    /// is unreachable.
    fn authenticate(
        &self,
        request: RequestView<'_>,
        profile: &Profile,
        cookie: &mut AuthCookie,
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
        _cookie: &mut AuthCookie,
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
pub trait Authorizer: Send + Sync + 'static {
    /// Decides whether `identity` may use the route `rule` protects.
    fn authorize(&self, request: RequestView<'_>, identity: &Identity, rule: &Rule) -> Decision;
}

/// The first authorizer: the rule's own terms and nothing else. Guests pass
/// public rules; signed-in accounts pass rules whose permissions they hold.
#[derive(Clone, Copy, Debug, Default)]
pub struct RuleTerms;

impl Authorizer for RuleTerms {
    #[inline]
    fn authorize(&self, _request: RequestView<'_>, identity: &Identity, rule: &Rule) -> Decision {
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
        match self.authorizer.authorize(p.view(), p.identity(), rule) {
            Decision::Allow => Ok(p.clear(AccessStamp { rule: rule.id() })),
            Decision::Deny(refusal) => Err(p.refuse_with(refusal)),
        }
    }
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Access")
    }
}
