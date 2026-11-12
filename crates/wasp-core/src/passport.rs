//! The passport: the handle that moves a request through the platform.
//!
//! A passport is a box holding one [`Slot`]: moving it moves eight bytes. Its
//! stage is part of its type, and each stage has only the methods that stage
//! may use:
//!
//! | Stage | Produced by | Can |
//! |---|---|---|
//! | [`Arrived`] | the pool, once the head is complete | be filled (trip, head, body), be inspected |
//! | [`Inspected`] | customs ([`Passport::inspect`]) | be read; go to the core |
//! | [`Identified`] | the core's authentication (crate-private) | be read; go to the service |
//! | [`Cleared`] | authorization ([`crate::Access::authorize`]) | write its reply |
//!
//! Every stage can be refused ([`Passport::refuse`]), which turns it into an
//! [`Exit`] carrying a fixed refusal. Only a cleared passport can write content,
//! and only this crate can produce `Identified` and `Cleared` passports, so a
//! path that skips a gate does not compile:
//!
//! ```compile_fail,E0599
//! // A service cannot write a reply before authorization.
//! fn skip(mut p: wasp_core::Passport<wasp_core::Identified>) {
//!     p.reply().text(200, "content without authorization");
//! }
//! ```
//!
//! ```compile_fail,E0624
//! // Nothing outside the core can identify a passport.
//! fn forge(p: wasp_core::Passport<wasp_core::Inspected>) -> wasp_core::Passport<wasp_core::Identified> {
//!     p.identify(wasp_core::Identity::guest())
//! }
//! ```
//!
//! ```compile_fail,E0624
//! // Nothing outside the core can clear a passport.
//! fn forge(p: wasp_core::Passport<wasp_core::Identified>) -> wasp_core::Passport<wasp_core::Cleared> {
//!     p.clear(wasp_core::AccessStamp { rule: 0 })
//! }
//! ```
//!
//! ```compile_fail,E0624
//! // A service cannot clear a passport through an authorizer of its own:
//! // only the core makes an `Access`.
//! struct Yes;
//! impl wasp_core::Authorizer for Yes {
//!     fn authorize(&self, _: &wasp_core::Identity, _: &wasp_core::Rule) -> wasp_core::Decision {
//!         wasp_core::Decision::Allow
//!     }
//! }
//! let _ = wasp_core::Access::from_arc(std::sync::Arc::new(Yes));
//! ```
//!
//! ```compile_fail,E0451
//! // Nor build the context that carries the core's.
//! fn build(access: wasp_core::Access) -> wasp_core::ServiceCtx {
//!     wasp_core::ServiceCtx { tag: wasp_core::ServiceTag(0), access, jobs: todo!() }
//! }
//! ```
//!
//! ```compile_fail,E0451
//! // A passport is never built by hand.
//! fn build() -> wasp_core::Passport<wasp_core::Cleared> {
//!     wasp_core::Passport { slot: todo!(), _stage: std::marker::PhantomData }
//! }
//! ```
//!
//! ```compile_fail,E0599
//! // The head is fixed once customs passed it.
//! fn rewrite(mut p: wasp_core::Passport<wasp_core::Inspected>) {
//!     p.head_mut().set_line("GET", "/admin", 1);
//! }
//! ```

use std::fmt;
use std::marker::PhantomData;

use crate::customs::Customs;
use crate::identity::Identity;
use crate::slot::{AccessStamp, Head, Refusal, Reply, Slot, Trip};
use crate::stage::{Arrived, Cleared, Identified, Inspected, Stage};

/// The handle that moves one request through the platform. See the module docs.
#[must_use = "a passport must reach the response pipeline, or its slot never returns to the pool"]
pub struct Passport<S: Stage> {
    slot: Box<Slot>,
    _stage: PhantomData<fn() -> S>,
}

// A passport must be able to move between threads (offload, lanes): seam 1.
const _: () = {
    const fn must_be_send<T: Send>() {}
    must_be_send::<Passport<Arrived>>();
    must_be_send::<Passport<Cleared>>();
    must_be_send::<Exit>();
};

/// A read-only view of a request, for the gates and customs.
#[derive(Clone, Copy)]
pub struct RequestView<'a> {
    slot: &'a Slot,
}

impl<'a> RequestView<'a> {
    /// The trip facts.
    #[must_use]
    pub fn trip(&self) -> &'a Trip {
        &self.slot.trip
    }

    /// The head.
    #[must_use]
    pub fn head(&self) -> &'a Head {
        &self.slot.head
    }

    /// The buffered body.
    #[must_use]
    pub fn body(&self) -> &'a [u8] {
        &self.slot.body
    }

    /// The identity, once authentication ran.
    #[must_use]
    pub fn identity(&self) -> Option<&'a Identity> {
        self.slot.identity.as_ref()
    }
}

impl fmt::Debug for RequestView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RequestView").field(&self.slot).finish()
    }
}

impl<S: Stage> Passport<S> {
    #[inline]
    fn into_stage<T: Stage>(self) -> Passport<T> {
        Passport {
            slot: self.slot,
            _stage: PhantomData,
        }
    }

    /// The trip facts.
    #[inline]
    #[must_use]
    pub fn trip(&self) -> &Trip {
        &self.slot.trip
    }

    /// The head.
    #[inline]
    #[must_use]
    pub fn head(&self) -> &Head {
        &self.slot.head
    }

    /// A read-only view for the gates.
    #[inline]
    #[must_use]
    pub fn view(&self) -> RequestView<'_> {
        RequestView { slot: &self.slot }
    }

    /// The stage's name.
    #[must_use]
    pub fn stage(&self) -> &'static str {
        S::NAME
    }

    /// Refuses the request: whatever the reply held is wiped and replaced by
    /// the fixed refusal for `status`. Nothing after this runs.
    #[inline]
    pub fn refuse(self, status: u16) -> Exit {
        self.refuse_with(Refusal::status(status))
    }

    /// [`refuse`](Self::refuse) with `Retry-After` or a close.
    pub fn refuse_with(mut self, refusal: Refusal) -> Exit {
        let status = if (400..=599).contains(&refusal.status) {
            refusal.status
        } else {
            500
        };
        self.slot.reply.refuse(Refusal { status, ..refusal });
        Exit { slot: self.slot }
    }

    pub(crate) fn from_slot(slot: Box<Slot>) -> Passport<S> {
        Passport {
            slot,
            _stage: PhantomData,
        }
    }
}

impl Passport<Arrived> {
    /// Writes the trip facts. The slot's home worker is kept.
    #[inline]
    pub fn set_trip(&mut self, trip: Trip) {
        self.slot.trip = trip;
    }

    /// The head, to copy the request head into.
    #[inline]
    pub fn head_mut(&mut self) -> &mut Head {
        &mut self.slot.head
    }

    /// Appends `bytes` to the body, wiping the old buffer when it grows.
    #[inline]
    pub fn push_body(&mut self, bytes: &[u8]) {
        crate::slot::extend_wiped(&mut self.slot.body, bytes);
    }

    /// The body buffer, to copy a buffered body into.
    #[inline]
    pub fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.slot.body
    }

    /// Customs: checks the head and stamps it, or refuses the request.
    #[inline]
    pub fn inspect(mut self, customs: &dyn Customs) -> Result<Passport<Inspected>, Exit> {
        match customs.head(self.view()) {
            Ok(stamp) => {
                self.slot.inspected = Some(stamp);
                Ok(self.into_stage())
            }
            Err(refusal) => Err(self.refuse_with(refusal)),
        }
    }
}

impl Passport<Inspected> {
    /// The reused `Set-Cookie` buffer, lent to authentication.
    pub(crate) fn take_auth_cookie(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.slot.auth_cookie)
    }

    /// What authentication handed back: the cookie buffer and the token.
    pub(crate) fn put_auth_out(&mut self, cookie: Vec<u8>, token: Option<crate::gates::GateToken>) {
        self.slot.auth_cookie = cookie;
        self.slot.gate_token = token;
    }

    /// The buffered body (customs checked its size).
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.slot.body
    }

    /// Writes the identity stamp. Only the core calls this, right after the
    /// authenticator decided.
    #[inline]
    pub(crate) fn identify(mut self, identity: Identity) -> Passport<Identified> {
        self.slot.identity = Some(identity);
        self.into_stage()
    }
}

impl Passport<Identified> {
    /// The gate's own identity token, if authentication kept one of type `T`.
    #[must_use]
    pub fn token<T: std::any::Any>(&self) -> Option<&T> {
        self.slot.gate_token.as_deref()?.downcast_ref::<T>()
    }

    /// A `Set-Cookie` value authentication asked the response to carry.
    #[must_use]
    pub fn auth_cookie(&self) -> Option<&[u8]> {
        (!self.slot.auth_cookie.is_empty()).then_some(&self.slot.auth_cookie[..])
    }

    /// The token as kept, whatever its type.
    #[must_use]
    pub fn token_any(&self) -> Option<&(dyn std::any::Any + Send + Sync)> {
        self.slot.gate_token.as_deref()
    }

    /// Who the request is from.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        // Set by `identify`, the only way to this stage.
        self.slot.identity.as_ref().unwrap_or(&GUEST)
    }

    /// The buffered body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.slot.body
    }

    /// The passport's exit when an external service answered on the
    /// protocol's own types: the passport carries no reply. Only the core's
    /// [`crate::Handoff`] calls this.
    pub(crate) fn handed_off(mut self) -> Exit {
        self.slot.reply.mark_handed_off();
        Exit { slot: self.slot }
    }

    /// Writes the access stamp. Only [`crate::Access::authorize`] calls this,
    /// after the authorizer allowed the rule.
    #[inline]
    pub(crate) fn clear(mut self, stamp: AccessStamp) -> Passport<Cleared> {
        self.slot.access = Some(stamp);
        self.into_stage()
    }
}

static GUEST: Identity = Identity::guest();

impl Passport<Cleared> {
    /// The gate's own identity token, if authentication kept one of type `T`.
    #[must_use]
    pub fn token<T: std::any::Any>(&self) -> Option<&T> {
        self.slot.gate_token.as_deref()?.downcast_ref::<T>()
    }

    /// Who the request is from.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        self.slot.identity.as_ref().unwrap_or(&GUEST)
    }

    /// The rule that cleared it.
    #[must_use]
    pub fn access(&self) -> Option<AccessStamp> {
        self.slot.access
    }

    /// The buffered body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.slot.body
    }

    /// The reply, to write content into.
    #[inline]
    pub fn reply(&mut self) -> &mut Reply {
        &mut self.slot.reply
    }

    /// Hands the reply to the response pipeline.
    #[inline]
    pub fn answer(self) -> Exit {
        Exit { slot: self.slot }
    }
}

impl<S: Stage> fmt::Debug for Passport<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passport")
            .field("stage", &S::NAME)
            .field("slot", &self.slot)
            .finish()
    }
}

/// A passport on its way out: its reply is final (an answer, a refusal, or a
/// cached page). The response pipeline encodes it, writes it, and returns it to
/// the pool.
#[must_use = "an exit must be written and returned to the pool"]
pub struct Exit {
    slot: Box<Slot>,
}

impl Exit {
    /// The trip facts.
    #[must_use]
    pub fn trip(&self) -> &Trip {
        &self.slot.trip
    }

    /// The reply to encode.
    #[must_use]
    pub fn reply(&self) -> &Reply {
        &self.slot.reply
    }

    /// A `Set-Cookie` value authentication asked the response to carry.
    #[must_use]
    pub fn auth_cookie(&self) -> Option<&[u8]> {
        (!self.slot.auth_cookie.is_empty()).then_some(&self.slot.auth_cookie[..])
    }

    /// The identity, when authentication ran before the exit.
    #[must_use]
    pub fn identity(&self) -> Option<&Identity> {
        self.slot.identity.as_ref()
    }

    /// Replaces the reply with a refusal (a revocation at the last checkpoint,
    /// or customs export refusing it).
    pub fn refuse_with(mut self, refusal: Refusal) -> Exit {
        // A refusal is an error: a success status here (a customs rule's
        // mistake) becomes a 500, never a 200 carrying an error text.
        let status = if (400..=599).contains(&refusal.status) {
            refusal.status
        } else {
            500
        };
        self.slot.reply.refuse(Refusal { status, ..refusal });
        self
    }

    pub(crate) fn into_slot(self) -> Box<Slot> {
        self.slot
    }

    pub(crate) fn home_worker(&self) -> u16 {
        self.slot.home.worker
    }
}

impl fmt::Debug for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Exit").field("slot", &self.slot).finish()
    }
}
