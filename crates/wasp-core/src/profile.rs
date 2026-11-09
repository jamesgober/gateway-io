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
        }
    }
}
