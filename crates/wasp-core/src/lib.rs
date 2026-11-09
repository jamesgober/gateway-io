//! The platform core: the passport and its stages, the pool, customs, the
//! gates seam, the service seam, and the core that sits in the request path.
//!
//! A request moves as a [`Passport`]:
//!
//! ```text
//!  gateway  pool.take ─▶ Passport<Arrived> ─▶ inspect (customs) ─▶ Passport<Inspected>
//!  core     authenticate ─▶ Passport<Identified> ─▶ guest cache? ─▶ the profile's service
//!  service  route ─▶ Access::authorize ─▶ Passport<Cleared> ─▶ reply ─▶ Exit
//!  gateway  export (customs) ─▶ encode ─▶ write ─▶ pool.give_back (wiped)
//! ```
//!
//! The stage types make skipping a gate a compile error: see [`passport`].
//!
//! The foundation (configuration, logging, errors, the kernel, the urgent
//! line) is system-suite, re-exported as [`suite`].

#![forbid(unsafe_code)]

pub mod cache;
pub mod core;
pub mod customs;
pub mod gates;
pub mod identity;
pub mod passport;
pub mod pool;
pub mod profile;
pub mod service;
pub mod slot;
pub mod stage;
pub mod stub;

/// The foundation package.
pub use system_suite as suite;

pub use crate::cache::{GuestCache, NoCache};
pub use crate::core::{Core, CoreBuilder, CoreSubsystem, LoadError};
pub use crate::customs::{Customs, HeadRules};
pub use crate::gates::{
    Access, AuthCookie, Authentication, Authenticator, Authorizer, Decision, EveryoneGuest, Rule,
    RuleTerms,
};
pub use crate::identity::{Identity, PermSet, SessionId, Standing, Subject, TenantId, UserId};
pub use crate::passport::{Exit, Passport, RequestView};
pub use crate::pool::{PassportPool, PoolStats};
pub use crate::profile::{CredentialLocator, Profile, SessionSettings};
pub use crate::service::{Service, ServiceCtx, Work};
pub use crate::slot::{
    AccessStamp, Head, Inspection, Lane, ProfileId, Refusal, Reply, ReplyKind, RequestId,
    ServiceTag, SlotSizes, Trip, refusal_text,
};
pub use crate::stage::{Arrived, Cleared, Identified, Inspected, Stage};
