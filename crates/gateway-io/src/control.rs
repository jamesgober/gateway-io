//! The urgent line as the transport's control line.
//!
//! One line for the whole process: the kernel's urgent line. net-io reads it
//! once per worker loop and before each accept batch; serve-net reads it at its
//! request checkpoints. A stop request moves the line to `Draining`, which
//! closes the door before anything else stops.

use std::time::Instant;

use net_io::{ControlLine, ControlState, Lane};
use wasp_core::suite::kernel::{Level, UrgentLine};

/// The lane `Shed` starts refusing at: lanes 0 to 3 (health, admin, login) keep
/// being served; the default lane 4 and below are shed.
pub const SHED_FROM: Lane = Lane(4);

/// The kernel's urgent line, read by the transport.
#[derive(Clone)]
pub struct UrgentControl {
    line: UrgentLine,
}

impl UrgentControl {
    /// Wraps the kernel's line (or `UrgentLine::detached()` in tests).
    #[must_use]
    pub fn new(line: UrgentLine) -> UrgentControl {
        UrgentControl { line }
    }

    /// The line itself.
    #[must_use]
    pub fn line(&self) -> &UrgentLine {
        &self.line
    }
}

impl ControlLine for UrgentControl {
    #[inline]
    fn epoch(&self) -> u64 {
        self.line.epoch()
    }

    fn state(&self) -> ControlState {
        match self.line.level() {
            Level::Normal => ControlState::Normal,
            Level::Shed => ControlState::Shed {
                from_lane: SHED_FROM,
            },
            Level::Lockdown => ControlState::Lockdown,
            Level::Draining => ControlState::Draining,
            Level::Stopping => ControlState::Stopping,
            // A level added later: the strictest reading that still serves.
            _ => ControlState::Lockdown,
        }
    }

    fn deadline(&self) -> Option<Instant> {
        // The drain deadline comes from the kernel's stop of the gateway
        // subsystem, which calls drain with what is left of the shutdown.
        None
    }
}

impl std::fmt::Debug for UrgentControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UrgentControl")
            .field("level", &self.line.level())
            .field("epoch", &self.line.epoch())
            .finish()
    }
}
