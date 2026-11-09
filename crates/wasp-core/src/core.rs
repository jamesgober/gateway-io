//! The core: in the request path between the gateway and the services.
//!
//! For every request the core authenticates the inspected passport, answers a
//! guest's cached page, or assigns the profile's service. It is built in boot
//! phases 1 to 3 ([`CoreBuilder`]) and stopped in shutdown steps 3 to 6
//! ([`CoreSubsystem`]).

use std::sync::Arc;

use crate::cache::{GuestCache, NoCache};
use crate::customs::{Customs, HeadRules};
use crate::gates::{Access, Authentication, Authenticator, Authorizer, EveryoneGuest, RuleTerms};
use crate::passport::{Exit, Passport};
use crate::profile::Profile;
use crate::service::{Service, ServiceCtx};
use crate::slot::{ProfileId, ServiceTag};
use crate::stage::Inspected;
use crate::suite::lifecycle::{Deadline, Failure, Link, Subsystem};
use crate::suite::log;

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

/// Boot phases 1 to 3: declare profiles and services, then compile them into a
/// [`Core`]. Every name is resolved here, once; at run time a profile and a
/// service are array indexes.
#[must_use = "a CoreBuilder does nothing until load()"]
pub struct CoreBuilder {
    profiles: Vec<Profile>,
    services: Vec<(String, ServiceFactory)>,
    authenticator: Box<dyn Authenticator>,
    authorizer: Arc<dyn Authorizer>,
    customs: Arc<dyn Customs>,
    cache: Box<dyn GuestCache>,
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
        }
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
            Box::new(move |ctx| Box::new(build(ctx)) as Box<dyn Service>),
        ));
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
        let services = self
            .services
            .into_iter()
            .enumerate()
            .map(|(i, (_, build))| {
                build(ServiceCtx {
                    tag: ServiceTag(u8::try_from(i).unwrap_or(u8::MAX)),
                    access: Access::from_arc(self.authorizer.clone()),
                })
            })
            .collect();
        Ok(Core {
            profiles: self.profiles.into_boxed_slice(),
            services,
            authenticator: self.authenticator,
            customs: self.customs,
            cache: self.cache,
        })
    }
}

/// The running core. Shared by every worker (`Arc<Core>`); every field is read
/// only.
pub struct Core {
    profiles: Box<[Profile]>,
    services: Box<[Box<dyn Service>]>,
    authenticator: Box<dyn Authenticator>,
    customs: Arc<dyn Customs>,
    cache: Box<dyn GuestCache>,
}

impl Core {
    /// Phase 1.
    pub fn builder() -> CoreBuilder {
        CoreBuilder::new()
    }

    /// One request: authenticate, answer from the guest cache, or assign the
    /// profile's service. The service only ever sees an identified passport.
    #[inline]
    pub fn handle(&self, p: Passport<Inspected>) -> Exit {
        let Some(profile) = self.profiles.get(usize::from(p.trip().profile.0)) else {
            return p.refuse(500);
        };
        let p = match self.authenticator.authenticate(p.view(), profile) {
            Authentication::Identified(identity) => p.identify(identity),
            Authentication::Refused(refusal) => return p.refuse_with(refusal),
        };
        let p = match self.cache.guest_hit(p) {
            Ok(hit) => return hit,
            Err(miss) => miss,
        };
        match self.services.get(usize::from(profile.service.0)) {
            Some(service) => service.handle(p),
            None => p.refuse(500),
        }
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
        self.services.iter().map(|s| s.name())
    }

    fn stop_services(&self) {
        for service in self.services.iter() {
            service.stop();
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
        // 3: services stop. 4: providers flush (none yet). 5: gates persist
        // (in-memory guest gate: nothing to persist). 6: the core stops.
        self.core.stop_services();
        if let Some(link) = &self.link {
            log::info!(
                link.foundation().log(),
                "core stopped",
                remaining_ms = u64::try_from(deadline.remaining().as_millis()).unwrap_or(u64::MAX)
            );
        }
        Ok(())
    }
}
