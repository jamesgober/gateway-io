//! gateway-io: the platform's front door and its wire.
//!
//! Bytes in, passport out; reply in, bytes out. In order:
//!
//! 1. net-io accepts; the bouncer's door decides from the address alone,
//!    before a byte is read (a banned address is closed with nothing written).
//! 2. http-net parses the head (inside serve-net's engine).
//! 3. Admission reserves a passport once the head is complete; a full worker
//!    answers 503 without taking anything.
//! 4. The passport is filled (trip facts, a copy of the head, the body),
//!    inspected by customs, checkpointed, and handed to the core.
//! 5. The exit comes back: customs export, the last checkpoint, encode, and
//!    the passport is wiped and returned to its shelf.
//! 6. net-io writes; the bouncer's egress check runs before every write.
//!
//! [`Gateway`] is the kernel subsystem that opens all of this last at boot and
//! closes it first at shutdown.

#![forbid(unsafe_code)]

pub mod access;
pub mod bouncer;
pub mod control;
pub mod events;
#[cfg(feature = "gatekeeper")]
pub mod gatekeeper;
pub mod gateway;
pub mod load;
pub mod note;
pub mod observe;
pub mod pipeline;
pub mod rules;
pub mod settings;
pub mod stages;
pub mod tickets;
pub mod web;

pub use crate::access::{AccessEntry, AccessLog};
pub use crate::control::UrgentControl;
pub use crate::events::LogSink;
pub use crate::gateway::{Door, Extras, Gateway, OpenError};
pub use crate::load::{LoadSignal, ShedMarks};
pub use crate::observe::{ServerTime, ServerTimeSummary, TimeObserver};
pub use crate::pipeline::{PassportAdmit, Pipeline};
pub use crate::rules::LogRules;
pub use crate::settings::{Driver, IngressMode, LaneRate, Settings, SettingsError};
pub use crate::stages::StageTimes;
pub use crate::tickets::RequestTickets;
pub use crate::web::{Answered, Caller, WaspGate, WebGate, WebService, WebServices, Who};
