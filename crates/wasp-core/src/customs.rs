//! Customs: the checks a request head passes before anything trusts it, and
//! the checks a reply passes before it leaves.
//!
//! [`HeadRules`] is the first implementation: real limits and field rules, on
//! top of what the protocol parser already refused. The byte grammar (control
//! bytes, bare CR, obs-text in names, framing conflicts) is the parser's job
//! and is not checked twice; customs holds the policy. A fuller customs library
//! plugs in through the same trait.

use crate::passport::RequestView;
use crate::slot::{Inspection, Refusal, Reply};

/// What customs checks. Both methods must be fast and must not block: they run
/// on the worker for every request.
pub trait Customs: Send + Sync + 'static {
    /// The head: sizes, field rules, the protocol's field map. `Err` refuses
    /// the request with that status before any gate or service runs.
    fn head(&self, request: RequestView<'_>) -> Result<Inspection, Refusal>;

    /// The reply, before it is encoded. `Err` replaces it with the refusal.
    fn export(&self, reply: &Reply) -> Result<(), Refusal> {
        let _ = reply;
        Ok(())
    }
}

/// Fields that belong to the encoder or the transport. A head that repeats
/// one is a request-smuggling shape; a reply that sets one is a service bug.
const SINGLE: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "authorization",
];
const FRAMING: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
];

/// Customs head and export rules: limits and field rules, all on by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadRules {
    /// The longest request target (414 above it). Default 4 KiB.
    pub max_target: usize,
    /// The most fields (431 above it). Default 64.
    pub max_fields: usize,
    /// The longest single field value (431 above it). Default 4 KiB.
    pub max_field: usize,
    /// The whole head as copied into the passport (431 above it). Default 12 KiB.
    pub max_head: usize,
    /// The largest buffered body (413 above it). Default 1 MiB.
    pub max_body: usize,
    /// HTTP/1.1 requests must name their host (400 without). Default on.
    pub require_host: bool,
}

impl Default for HeadRules {
    fn default() -> HeadRules {
        HeadRules {
            max_target: 4 * 1024,
            max_fields: 64,
            max_field: 4 * 1024,
            max_head: 12 * 1024,
            max_body: 1024 * 1024,
            require_host: true,
        }
    }
}

/// The rule set id `HeadRules` stamps.
pub const HEAD_RULES: u16 = 1;

impl Customs for HeadRules {
    fn head(&self, request: RequestView<'_>) -> Result<Inspection, Refusal> {
        let head = request.head();
        let target = head.target();
        if target.is_empty() {
            return Err(Refusal::status(400).closing());
        }
        if target.len() > self.max_target {
            return Err(Refusal::status(414).closing());
        }
        if head.field_count() > self.max_fields || head.len_bytes() > self.max_head {
            return Err(Refusal::status(431).closing());
        }
        if request.body().len() > self.max_body {
            return Err(Refusal::status(413).closing());
        }
        let mut seen = [0u8; SINGLE.len()];
        let mut host = false;
        for (name, value) in head.fields() {
            if value.len() > self.max_field {
                return Err(Refusal::status(431).closing());
            }
            for (i, single) in SINGLE.iter().enumerate() {
                if name.eq_ignore_ascii_case(single.as_bytes()) {
                    seen[i] = seen[i].saturating_add(1);
                    if seen[i] > 1 {
                        return Err(Refusal::status(400).closing());
                    }
                    if i == 0 {
                        host = !value.is_empty();
                    }
                }
            }
        }
        if self.require_host && head.version_minor() >= 1 && !host {
            return Err(Refusal::status(400).closing());
        }
        Ok(Inspection { rules: HEAD_RULES })
    }

    fn export(&self, reply: &Reply) -> Result<(), Refusal> {
        if !(100..=599).contains(&reply.status_code()) {
            return Err(Refusal::status(500));
        }
        for (name, _) in reply.fields() {
            if FRAMING
                .iter()
                .any(|f| name.eq_ignore_ascii_case(f.as_bytes()))
            {
                return Err(Refusal::status(500));
            }
        }
        Ok(())
    }
}
