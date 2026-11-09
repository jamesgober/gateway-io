//! The service seam: what the core hands an identified passport to.

use crate::gates::Access;
use crate::passport::{Exit, Passport};
use crate::slot::ServiceTag;
use crate::stage::Identified;

/// How a service's work behaves, so a dispatcher can move slow work off the
/// worker later without touching the service.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Work {
    /// Returns in microseconds and never blocks: run in place, always.
    #[default]
    Quick,
    /// May wait on a file, a database, or another service.
    Io,
    /// Heavy computation (password hashing, image work).
    Cpu,
}

/// What a service gets at boot: its tag and its handles. Held for the
/// service's whole life, so nothing is looked up per request.
#[derive(Clone, Debug)]
pub struct ServiceCtx {
    /// The service's tag.
    pub tag: ServiceTag,
    /// The access gate: the only way to a cleared passport.
    pub access: Access,
}

/// A service: routes, authorizes, builds content, renders.
///
/// The core calls [`handle`](Service::handle) with a passport that is already
/// identified. The service matches its route, refuses with 404 or 405, calls
/// [`Access::authorize`] for the route's rule, and only then can it write
/// content. It returns the passport as an [`Exit`].
pub trait Service: Send + Sync + 'static {
    /// The service's name in configuration.
    fn name(&self) -> &str;

    /// How it behaves (default [`Work::Quick`]).
    fn work(&self) -> Work {
        Work::Quick
    }

    /// Answers one request.
    fn handle(&self, p: Passport<Identified>) -> Exit;

    /// Shutdown step 3: finish or persist background work by the deadline.
    fn stop(&self) {}
}
