//! The four stages a passport moves through.
//!
//! A stage is a type with no values: it exists only for the compiler, so a
//! `Passport<Inspected>` and a `Passport<Cleared>` are the same eight bytes at
//! run time. What a stage allows is decided by which methods exist on
//! `Passport<Stage>`, and which code can produce the next stage.

mod sealed {
    pub trait Sealed {}
}

/// A passport stage. Sealed: only the four stages below exist.
pub trait Stage: sealed::Sealed + 'static {
    /// The stage's name, for logs and debug output.
    const NAME: &'static str;
}

/// Taken from the pool once the request head was complete; nothing checked yet.
#[derive(Debug)]
pub enum Arrived {}

/// Customs passed the head: sizes, field rules, the protocol's field map.
#[derive(Debug)]
pub enum Inspected {}

/// The core authenticated it: it carries an identity (possibly a guest).
#[derive(Debug)]
pub enum Identified {}

/// The service's router authorized it for the matched route. Only a cleared
/// passport can write content into its reply.
#[derive(Debug)]
pub enum Cleared {}

impl sealed::Sealed for Arrived {}
impl sealed::Sealed for Inspected {}
impl sealed::Sealed for Identified {}
impl sealed::Sealed for Cleared {}

impl Stage for Arrived {
    const NAME: &'static str = "arrived";
}
impl Stage for Inspected {
    const NAME: &'static str = "inspected";
}
impl Stage for Identified {
    const NAME: &'static str = "identified";
}
impl Stage for Cleared {
    const NAME: &'static str = "cleared";
}
