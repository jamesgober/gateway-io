//! Providers: the stores and connections the core opens for its services
//! (databases, key-value stores, caches). The core owns them: it opens them
//! at boot (phase 3), hands services direct handles (nothing is looked up per
//! request), and flushes and closes them at shutdown step 4, after the
//! services stopped and before the gates.

use std::fmt;

/// Why a provider failed to flush or reported itself unhealthy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderError(pub String);

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProviderError {}

/// A store or connection the core owns.
pub trait Provider: Send + Sync + 'static {
    /// The provider's name, for logs and health.
    fn name(&self) -> &str;

    /// Shutdown step 4: make everything written durable (write-behind
    /// caches, file sync). Called once, after the services stopped.
    fn flush(&self) -> Result<(), ProviderError>;

    /// Whether the provider can serve right now (cheap, never blocks).
    fn healthy(&self) -> bool {
        true
    }
}
