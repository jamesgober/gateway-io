//! Who a request is from, as authentication decided it.

/// A signed-in account's id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(pub u128);

/// A tenant (for multi-tenant services).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(pub u64);

/// A server-side session, by the store's own id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u128);

/// Who the request is from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    /// No credential, or one that did not check out. A guest carries nothing.
    Guest,
    /// A signed-in account.
    User(UserId),
}

/// The account's standing. A ban never becomes an identity: authentication
/// refuses the request instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Normal.
    Good,
    /// Suspended until the given Unix time in seconds (`None`: until lifted).
    /// The route rules decide what a suspended account may still do.
    Suspended {
        /// Seconds since the Unix epoch, or `None`.
        until: Option<u64>,
    },
}

/// A set of permissions as bits: the access gate compiles names to bits at boot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PermSet(pub u64);

impl PermSet {
    /// No permission.
    pub const NONE: PermSet = PermSet(0);

    /// Whether every bit of `needed` is in this set.
    #[inline]
    #[must_use]
    pub const fn contains(self, needed: PermSet) -> bool {
        self.0 & needed.0 == needed.0
    }
}

/// The identity stamp: written once, by the core's authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    subject: Subject,
    standing: Standing,
    perms: PermSet,
    tenant: Option<TenantId>,
    session: Option<SessionId>,
}

impl Identity {
    /// A guest: no account, no session, no permission.
    #[must_use]
    pub const fn guest() -> Identity {
        Identity {
            subject: Subject::Guest,
            standing: Standing::Good,
            perms: PermSet::NONE,
            tenant: None,
            session: None,
        }
    }

    /// A signed-in account with its session.
    #[must_use]
    pub const fn user(user: UserId, session: SessionId, perms: PermSet) -> Identity {
        Identity {
            subject: Subject::User(user),
            standing: Standing::Good,
            perms,
            tenant: None,
            session: Some(session),
        }
    }

    /// The same identity with a standing.
    #[must_use]
    pub const fn with_standing(mut self, standing: Standing) -> Identity {
        self.standing = standing;
        self
    }

    /// The same identity in a tenant.
    #[must_use]
    pub const fn in_tenant(mut self, tenant: TenantId) -> Identity {
        self.tenant = Some(tenant);
        self
    }

    /// Who.
    #[must_use]
    pub const fn subject(&self) -> Subject {
        self.subject
    }

    /// Whether this is a guest.
    #[must_use]
    pub const fn is_guest(&self) -> bool {
        matches!(self.subject, Subject::Guest)
    }

    /// The standing.
    #[must_use]
    pub const fn standing(&self) -> Standing {
        self.standing
    }

    /// The permissions.
    #[must_use]
    pub const fn perms(&self) -> PermSet {
        self.perms
    }

    /// The tenant, if any.
    #[must_use]
    pub const fn tenant(&self) -> Option<TenantId> {
        self.tenant
    }

    /// The session, if any.
    #[must_use]
    pub const fn session(&self) -> Option<SessionId> {
        self.session
    }
}
