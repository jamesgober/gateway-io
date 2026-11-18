//! The core: in the request path between the gateway and the services.
//!
//! For every request the core authenticates the inspected passport, answers a
//! guest's cached page, or assigns the profile's service. It is built in boot
//! phases 1 to 3 ([`CoreBuilder`]) and stopped in shutdown steps 3 to 6
//! ([`CoreSubsystem`]).

use std::sync::Arc;

use crate::cache::{GuestCache, NoCache};
use crate::customs::{Customs, HeadRules};
use crate::gates::{
    Access, AuthOut, Authentication, Authenticator, Authorizer, EveryoneGuest, RuleTerms,
};
use crate::identity::Identity;
use crate::jobs::{Jobs, NoJobs};
use crate::passport::{Exit, Passport};
use crate::profile::Profile;
use crate::provider::Provider;
use crate::service::{Service, ServiceCtx};
use crate::slot::{ProfileId, ServiceTag};
use crate::slot::{Refusal, Trip};
use crate::stage::{Identified, Inspected};
use crate::suite::lifecycle::{Deadline, Failure, Link, Subsystem};
use crate::suite::log;

/// `Retry-After` when the credential store cannot answer.
const AUTH_RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(5);

/// Why the core refused to load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError(pub String);

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoadError {}

type ServiceFactory = Box<dyn FnOnce(ServiceCtx) -> Box<dyn Service> + Send>;

/// A registered service: one that answers on passports, or one served outside
/// the core on the protocol's own types (the web service on serve-net).
enum Entry {
    Passport(Box<dyn Service>),
    External(String),
}

impl Entry {
    fn name(&self) -> &str {
        match self {
            Entry::Passport(s) => s.name(),
            Entry::External(n) => n,
        }
    }
}

/// What the core decided for one request.
#[must_use = "a routed request carries a passport that must reach the pool"]
pub enum Routed {
    /// Answered, refused, or served from the cache: ready for the response
    /// pipeline.
    Exit(Exit),
    /// Identified and assigned to an external service; the caller runs it and
    /// then [`Handoff::finish`]es the passport.
    Handoff(Handoff),
}

/// An identified request assigned to an external service. Only the core makes
/// one, after authentication, so an external service can only ever be given an
/// identified request.
#[must_use = "a hand-off must be finished, or its passport never returns to the pool"]
pub struct Handoff {
    p: Passport<Identified>,
    service: ServiceTag,
}

impl Handoff {
    /// The service the profile names.
    #[must_use]
    pub fn service(&self) -> ServiceTag {
        self.service
    }

    /// Who the request is from.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        self.p.identity()
    }

    /// The gate's own identity token, as authentication kept it.
    #[must_use]
    pub fn token_any(&self) -> Option<&(dyn std::any::Any + Send + Sync)> {
        self.p.token_any()
    }

    /// The trip facts.
    #[must_use]
    pub fn trip(&self) -> &Trip {
        self.p.trip()
    }

    /// A `Set-Cookie` value authentication asked the response to carry (a
    /// dead session's cookie cleared). The caller writes it before the
    /// service's own fields, so a cookie of the same name the service sets
    /// (a new session) comes later and wins.
    #[must_use]
    pub fn auth_cookie(&self) -> Option<&[u8]> {
        self.p.auth_cookie()
    }

    /// The service answered on the protocol's own reply: the passport goes to
    /// the response pipeline with no reply of its own (its authentication
    /// cookie still rides on the response).
    pub fn finish(self) -> Exit {
        self.p.handed_off()
    }

    /// The service could not be run (none is attached for the tag): refuse.
    pub fn refuse(self, status: u16) -> Exit {
        self.p.refuse(status)
    }
}

impl std::fmt::Debug for Handoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handoff")
            .field("service", &self.service)
            .field("passport", &self.p)
            .finish()
    }
}

/// Boot phases 1 to 3: declare profiles and services, then compile them into a
/// [`Core`]. Every name is resolved here, once; at run time a profile and a
/// service are array indexes.
#[must_use = "a CoreBuilder does nothing until load()"]
pub struct CoreBuilder {
    profiles: Vec<Profile>,
    services: Vec<(String, Option<ServiceFactory>)>,
    authenticator: Box<dyn Authenticator>,
    authorizer: Arc<dyn Authorizer>,
    customs: Arc<dyn Customs>,
    cache: Box<dyn GuestCache>,
    providers: Vec<Arc<dyn Provider>>,
    jobs: Arc<dyn Jobs>,
}

impl Default for CoreBuilder {
    fn default() -> Self {
        CoreBuilder::new()
    }
}

impl CoreBuilder {
    /// Phase 1: an empty core with the first implementation of every seam:
    /// [`EveryoneGuest`], [`RuleTerms`], [`HeadRules`], [`NoCache`].
    pub fn new() -> CoreBuilder {
        CoreBuilder {
            profiles: Vec::new(),
            services: Vec::new(),
            authenticator: Box::new(EveryoneGuest),
            authorizer: Arc::new(RuleTerms),
            customs: Arc::new(HeadRules::default()),
            cache: Box::new(NoCache),
            providers: Vec::new(),
            jobs: Arc::new(NoJobs),
        }
    }

    /// Phase 3: a provider the core owns (a content store, a database). It
    /// is flushed at shutdown step 4, after the services stopped.
    pub fn provider(mut self, provider: Arc<dyn Provider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// The job runner every service gets (default [`NoJobs`]: every job
    /// refused). Stopped at shutdown step 3, with the services.
    pub fn jobs(mut self, jobs: Arc<dyn Jobs>) -> Self {
        self.jobs = jobs;
        self
    }

    /// The authenticator (the auth gate).
    pub fn authenticator(mut self, authenticator: impl Authenticator) -> Self {
        self.authenticator = Box::new(authenticator);
        self
    }

    /// The authorizer (the access gate) handed to every service.
    pub fn authorizer(mut self, authorizer: impl Authorizer) -> Self {
        self.authorizer = Arc::new(authorizer);
        self
    }

    /// Customs, used by the gateway.
    pub fn customs(mut self, customs: impl Customs) -> Self {
        self.customs = Arc::new(customs);
        self
    }

    /// The guest output cache.
    pub fn guest_cache(mut self, cache: impl GuestCache) -> Self {
        self.cache = Box::new(cache);
        self
    }

    /// Phase 2: a service registers under a name; it is built in phase 3 with
    /// its context. Its tag is its registration order.
    pub fn service<S, F>(mut self, name: &str, build: F) -> Self
    where
        S: Service,
        F: FnOnce(ServiceCtx) -> S + Send + 'static,
    {
        self.services.push((
            name.to_owned(),
            Some(Box::new(move |ctx| {
                Box::new(build(ctx)) as Box<dyn Service>
            })),
        ));
        self
    }

    /// Phase 2: a service served outside the core, on the protocol's own
    /// types (the web service). The core still authenticates its requests and
    /// assigns them; [`Core::route`] hands them over as a [`Handoff`].
    pub fn external(mut self, name: &str) -> Self {
        self.services.push((name.to_owned(), None));
        self
    }

    /// Phase 2: a profile, naming its service. Ids are dense from 0 in the
    /// order profiles are added.
    pub fn profile(
        mut self,
        name: &str,
        service: &str,
        configure: impl FnOnce(&mut Profile),
    ) -> Self {
        let id = ProfileId(u8::try_from(self.profiles.len()).unwrap_or(u8::MAX));
        let tag = self
            .services
            .iter()
            .position(|(n, _)| n == service)
            .map_or(ServiceTag(u8::MAX), |i| {
                ServiceTag(u8::try_from(i).unwrap_or(u8::MAX))
            });
        let mut profile = Profile::new(id, name, tag);
        configure(&mut profile);
        self.profiles.push(profile);
        self
    }

    /// Phases 2 and 3: validates every declaration, builds every service with
    /// its context, and returns the core. Invalid: refuse to start.
    pub fn load(self) -> Result<Core, LoadError> {
        if self.services.is_empty() {
            return Err(LoadError("no service is registered".into()));
        }
        if self.services.len() > 255 {
            return Err(LoadError("more than 255 services".into()));
        }
        if self.profiles.is_empty() {
            return Err(LoadError("no profile is declared".into()));
        }
        if self.profiles.len() > 255 {
            return Err(LoadError("more than 255 profiles".into()));
        }
        for (i, (name, _)) in self.services.iter().enumerate() {
            if self.services[..i].iter().any(|(n, _)| n == name) {
                return Err(LoadError(format!("service `{name}` is registered twice")));
            }
        }
        for (i, p) in self.profiles.iter().enumerate() {
            if usize::from(p.service.0) >= self.services.len() {
                return Err(LoadError(format!(
                    "profile `{}` names a service that is not registered",
                    p.name
                )));
            }
            if self.profiles[..i].iter().any(|q| q.name == p.name) {
                return Err(LoadError(format!("profile `{}` is declared twice", p.name)));
            }
        }
        let access = Access::from_arc(self.authorizer.clone());
        let services = self
            .services
            .into_iter()
            .enumerate()
            .map(|(i, (name, build))| match build {
                Some(build) => Entry::Passport(build(ServiceCtx {
                    tag: ServiceTag(u8::try_from(i).unwrap_or(u8::MAX)),
                    access: access.clone(),
                    jobs: self.jobs.clone(),
                })),
                None => Entry::External(name),
            })
            .collect();
        Ok(Core {
            profiles: self.profiles.into_boxed_slice(),
            services,
            access,
            authenticator: self.authenticator,
            customs: self.customs,
            cache: self.cache,
            providers: self.providers.into_boxed_slice(),
            jobs: self.jobs,
        })
    }
}

/// The running core. Shared by every worker (`Arc<Core>`); every field is read
/// only.
pub struct Core {
    profiles: Box<[Profile]>,
    services: Box<[Entry]>,
    access: Access,
    authenticator: Box<dyn Authenticator>,
    customs: Arc<dyn Customs>,
    cache: Box<dyn GuestCache>,
    providers: Box<[Arc<dyn Provider>]>,
    jobs: Arc<dyn Jobs>,
}

impl Core {
    /// Phase 1.
    pub fn builder() -> CoreBuilder {
        CoreBuilder::new()
    }

    /// One request for a passport service: [`route`](Self::route), with a
    /// hand-off to an external service refused (500), since no protocol layer
    /// is here to run it.
    #[inline]
    pub fn handle(&self, p: Passport<Inspected>) -> Exit {
        match self.route(p) {
            Routed::Exit(exit) => exit,
            Routed::Handoff(h) => h.refuse(500),
        }
    }

    /// One request: authenticate, answer from the guest cache, or assign the
    /// profile's service. A passport service runs here and the passport comes
    /// back as an exit; an external service's request comes back as a
    /// [`Handoff`]. Either way the service only ever sees an identified
    /// request.
    #[inline]
    pub fn route(&self, p: Passport<Inspected>) -> Routed {
        let Some(profile) = self.profiles.get(usize::from(p.trip().profile.0)) else {
            return Routed::Exit(p.refuse(500));
        };
        let mut p = p;
        let mut out = AuthOut::from_parts(p.take_auth_cookie());
        let decided = self.authenticator.authenticate(p.view(), profile, &mut out);
        let (cookie, token) = out.into_parts();
        p.put_auth_out(cookie, token);
        let p = match decided {
            Authentication::Identified(identity) => p.identify(identity),
            Authentication::Refused(refusal) => return Routed::Exit(p.refuse_with(refusal)),
            Authentication::Unavailable => {
                let refusal = Refusal::status(503).retry_after(AUTH_RETRY_AFTER);
                return Routed::Exit(p.refuse_with(refusal));
            }
        };
        let p = match self.cache.guest_hit(p) {
            Ok(hit) => return Routed::Exit(hit),
            Err(miss) => miss,
        };
        match self.services.get(usize::from(profile.service.0)) {
            Some(Entry::Passport(service)) => {
                let exit = service.handle(p);
                if exit.reply().guest_ttl().is_some() {
                    self.cache.offer(&exit);
                }
                Routed::Exit(exit)
            }
            Some(Entry::External(_)) => Routed::Handoff(Handoff {
                p,
                service: profile.service,
            }),
            None => Routed::Exit(p.refuse(500)),
        }
    }

    /// The job runner, for external services.
    #[must_use]
    pub fn jobs(&self) -> &Arc<dyn Jobs> {
        &self.jobs
    }

    /// The providers, in the order they were added.
    #[must_use]
    pub fn providers(&self) -> &[Arc<dyn Provider>] {
        &self.providers
    }

    /// The access gate's handle, for external services (they authorize on
    /// their own types with [`Access::check`]).
    #[must_use]
    pub fn access(&self) -> &Access {
        &self.access
    }

    /// A service's tag by its registered name. Boot only.
    #[must_use]
    pub fn service_tag(&self, name: &str) -> Option<ServiceTag> {
        self.services
            .iter()
            .position(|e| e.name() == name)
            .and_then(|i| u8::try_from(i).ok())
            .map(ServiceTag)
    }

    /// Whether the tag names an external service.
    #[must_use]
    pub fn is_external(&self, tag: ServiceTag) -> bool {
        matches!(
            self.services.get(usize::from(tag.0)),
            Some(Entry::External(_))
        )
    }

    /// The names of the external services, by tag.
    pub fn external_services(&self) -> impl Iterator<Item = (ServiceTag, &str)> + '_ {
        self.services
            .iter()
            .enumerate()
            .filter_map(|(i, e)| match e {
                Entry::External(n) => u8::try_from(i).ok().map(|t| (ServiceTag(t), n.as_str())),
                Entry::Passport(_) => None,
            })
    }

    /// The compiled profiles, by id.
    #[must_use]
    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    /// A profile by id.
    #[must_use]
    pub fn profile(&self, id: ProfileId) -> Option<&Profile> {
        self.profiles.get(usize::from(id.0))
    }

    /// Customs, for the gateway.
    #[must_use]
    pub fn customs(&self) -> &dyn Customs {
        &*self.customs
    }

    /// The registered services' names, by tag.
    pub fn service_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.services.iter().map(Entry::name)
    }

    fn stop_services(&self) {
        for entry in self.services.iter() {
            if let Entry::Passport(service) = entry {
                service.stop();
            }
        }
    }
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core")
            .field("profiles", &self.profiles)
            .field("services", &self.service_names().collect::<Vec<_>>())
            .finish()
    }
}

/// The core as a kernel subsystem: started before the gateway, so it is
/// stopped after the gateway's door closed and its requests drained.
pub struct CoreSubsystem {
    core: Arc<Core>,
    link: Option<Link>,
}

impl CoreSubsystem {
    /// Wraps the loaded core.
    #[must_use]
    pub fn new(core: Arc<Core>) -> CoreSubsystem {
        CoreSubsystem { core, link: None }
    }
}

impl Subsystem for CoreSubsystem {
    fn name(&self) -> &str {
        "core"
    }

    fn start(&mut self, link: &Link) -> Result<(), Failure> {
        let services: Vec<&str> = self.core.service_names().collect();
        log::info!(
            link.foundation().log(),
            "core loaded",
            profiles = self.core.profiles.len(),
            services = services.join(",").as_str()
        );
        self.link = Some(link.clone());
        Ok(())
    }

    fn stop(&mut self, deadline: Deadline) -> Result<(), Failure> {
        // 3: services stop, and the jobs they queued finish (or are counted
        // as left). 4: providers flush. 5: gates persist (in-memory guest
        // gate: nothing to persist). 6: the core stops.
        self.core.stop_services();
        let jobs = self.core.jobs.stop(deadline.instant());
        let mut failed = Vec::new();
        for p in self.core.providers.iter() {
            if let Err(e) = p.flush() {
                failed.push(format!("{}: {e}", p.name()));
            }
        }
        if let Some(link) = &self.link {
            log::info!(
                link.foundation().log(),
                "core stopped",
                jobs_done = jobs.done,
                jobs_failed = jobs.failed,
                jobs_abandoned = jobs.abandoned,
                providers = self.core.providers.len(),
                provider_failures = failed.join("; ").as_str(),
                remaining_ms = u64::try_from(deadline.remaining().as_millis()).unwrap_or(u64::MAX)
            );
        }
        if failed.is_empty() {
            Ok(())
        } else {
            Err(Failure::new(format!(
                "providers failed to flush: {}",
                failed.join("; ")
            )))
        }
    }
}
