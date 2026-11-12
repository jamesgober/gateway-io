//! The service seam: what the core hands an identified passport to.

use std::sync::Arc;

use crate::gates::Access;
use crate::jobs::Jobs;
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
///
/// Only the core builds one, so the access gate a service holds is always
/// the core's.
#[derive(Clone)]
pub struct ServiceCtx {
    pub(crate) tag: ServiceTag,
    pub(crate) access: Access,
    pub(crate) jobs: Arc<dyn Jobs>,
}

impl ServiceCtx {
    /// The service's tag.
    #[must_use]
    pub fn tag(&self) -> ServiceTag {
        self.tag
    }

    /// The access gate: the only way to a cleared passport.
    #[must_use]
    pub fn access(&self) -> &Access {
        &self.access
    }

    /// The job runner: slow side work off the request path.
    #[must_use]
    pub fn jobs(&self) -> &Arc<dyn Jobs> {
        &self.jobs
    }
}

impl std::fmt::Debug for ServiceCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceCtx")
            .field("tag", &self.tag)
            .field("access", &self.access)
            .field("jobs", &self.jobs.stats())
            .finish()
    }
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
