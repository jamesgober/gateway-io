//! Profiles: what a listener's connections are, and what the core needs to
//! know about them (which service answers, where the credential is).

use crate::slot::{Lane, ProfileId, ServiceTag};

/// Where a profile's credential is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialLocator {
    /// The profile has no credential: everyone is a guest.
    None,
    /// A cookie, by name (for example `__Host-sid`).
    Cookie(String),
    /// A field, by name (for example `authorization`).
    Header(String),
}

/// Session settings the authenticator reads from the profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionSettings {
    /// Idle lifetime of a session, in seconds.
    pub idle_secs: u32,
    /// Absolute lifetime of a session, in seconds.
    pub max_secs: u32,
}

impl Default for SessionSettings {
    fn default() -> SessionSettings {
        SessionSettings {
            idle_secs: 30 * 60,
            max_secs: 12 * 60 * 60,
        }
    }
}

/// A cheap rule, read once the head is complete, that puts a request in a
/// lane by its method and path.
///
/// The path is matched as it was received (percent-encoding kept, no query):
/// a lane decides priority, never permission, so a request that dodges a
/// rule only loses its priority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneRule {
    method: Option<Box<str>>,
    path: Box<str>,
    under: bool,
    lane: Lane,
}

impl LaneRule {
    /// Requests for exactly `path`.
    #[must_use]
    pub fn exact(path: &str, lane: Lane) -> LaneRule {
        LaneRule {
            method: None,
            path: path.into(),
            under: false,
            lane,
        }
    }

    /// Requests for `path` and everything below it: `/admin` matches
    /// `/admin` and `/admin/edit/x`, not `/administer`.
    #[must_use]
    pub fn under(path: &str, lane: Lane) -> LaneRule {
        LaneRule {
            under: true,
            ..LaneRule::exact(path.trim_end_matches('/'), lane)
        }
    }

    /// The same rule, for one method only (`POST`).
    #[must_use]
    pub fn method(mut self, method: &str) -> LaneRule {
        self.method = Some(method.into());
        self
    }

    /// The lane it gives.
    #[must_use]
    pub fn lane(&self) -> Lane {
        self.lane
    }

    /// Whether a request with this method and path matches.
    #[must_use]
    pub fn matches(&self, method: &str, path: &str) -> bool {
        if self.method.as_deref().is_some_and(|m| m != method) {
            return false;
        }
        match path.strip_prefix(&*self.path) {
            Some("") => true,
            Some(rest) => self.under && (rest.starts_with('/') || self.path.is_empty()),
            None => false,
        }
    }
}

/// One profile, compiled at boot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Dense id from 0.
    pub id: ProfileId,
    /// Its name in configuration.
    pub name: String,
    /// The service that answers its requests.
    pub service: ServiceTag,
    /// Its default lane.
    pub lane: Lane,
    /// Whether it is served under lockdown.
    pub critical: bool,
    /// Where its credential is.
    pub locator: CredentialLocator,
    /// Its session settings.
    pub session: SessionSettings,
    /// Rules that move a request to another lane by its method and path;
    /// the first that matches wins, none keeps `lane`.
    pub lanes: Vec<LaneRule>,
}

impl Profile {
    /// A profile with defaults: lane 4, not critical, no credential.
    #[must_use]
    pub fn new(id: ProfileId, name: impl Into<String>, service: ServiceTag) -> Profile {
        Profile {
            id,
            name: name.into(),
            service,
            lane: Lane::default(),
            critical: false,
            locator: CredentialLocator::None,
            session: SessionSettings::default(),
            lanes: Vec::new(),
        }
    }

    /// The lane of a request with this method and path.
    #[must_use]
    pub fn lane_for(&self, method: &str, path: &str) -> Lane {
        self.lanes
            .iter()
            .find(|r| r.matches(method, path))
            .map_or(self.lane, LaneRule::lane)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_rules_match_by_method_and_path() {
        let mut p = Profile::new(ProfileId(0), "site", ServiceTag(0));
        p.lanes = vec![
            LaneRule::exact("/health", Lane::CRITICAL),
            LaneRule::under("/admin/", Lane::ADMIN),
            LaneRule::exact("/sign-in", Lane::AUTH).method("POST"),
        ];
        assert_eq!(p.lane_for("GET", "/health"), Lane::CRITICAL);
        assert_eq!(p.lane_for("GET", "/health/x"), Lane::NORMAL);
        assert_eq!(p.lane_for("GET", "/admin"), Lane::ADMIN);
        assert_eq!(p.lane_for("POST", "/admin/save"), Lane::ADMIN);
        assert_eq!(p.lane_for("GET", "/administer"), Lane::NORMAL);
        assert_eq!(p.lane_for("POST", "/sign-in"), Lane::AUTH);
        assert_eq!(p.lane_for("GET", "/sign-in"), Lane::NORMAL);
        assert_eq!(p.lane_for("GET", "/"), Lane::NORMAL);
        assert!(Lane::AUTH.is_reserved() && !Lane::WRITE.is_reserved());
    }
}
