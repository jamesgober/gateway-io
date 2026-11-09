//! The guest output cache seam: the core answers a guest's cacheable page
//! without waking the service.
//!
//! Implementations live in this crate: answering from the cache writes a reply
//! on an identified passport, which nothing outside the core may do.

use crate::passport::{Exit, Passport};
use crate::stage::Identified;

/// The core's guest output cache. Only guests, only `GET` and `HEAD`, only
/// requests without a body; the service decides what is stored.
pub trait GuestCache: Send + Sync + 'static {
    /// A hit answers the request (`Ok`); a miss hands the passport back (`Err`).
    #[allow(clippy::result_large_err)]
    fn guest_hit(&self, p: Passport<Identified>) -> Result<Exit, Passport<Identified>>;
}

/// No cache: every request goes to its service. Correct, only minimal.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCache;

impl GuestCache for NoCache {
    #[inline]
    fn guest_hit(&self, p: Passport<Identified>) -> Result<Exit, Passport<Identified>> {
        Err(p)
    }
}
