//! Where a request's server time goes, stage by stage.
//!
//! Off by default (`gateway.stage_timing`): when off, every mark is one
//! branch and nothing is recorded. When on, the pipeline takes a timestamp at
//! each stage boundary, keeps them with the request's ticket, and when serve-net
//! reports the request done they are joined with serve-net's own times into
//! one histogram per stage. serve-net stamps a request's arrival with net-io's
//! loop clock (read once per pass of the worker's loop) and the reply with the
//! real clock; the gateway's marks are real-clock reads.
//!
//! | Stage | From | To | What runs |
//! |---|---|---|---|
//! | `wake` | the worker's loop clock when the bytes were seen | the `head` hook runs | the loop pass up to this request: read, parse, other connections' work |
//! | `hook` | the `head` hook runs | `call` starts | bouncer request ticket, admission, checkpoints, body, dispatch |
//! | `passport` | `call` starts | inspected | take, trip, head copy, customs head |
//! | `core` | inspected | routed | checkpoint, authenticate, guest cache, assign (and a passport service itself) |
//! | `service` | routed | served | the web service (web-net: site, url, route, authorize, handler, render, finish) |
//! | `render` | (inside `service`) | | the template engine alone |
//! | `respond` | served | `call` returns | cookie, passport back to the pool (encode for passport services) |
//! | `to_reply` | `call` returns | reply handed to net-io | serve-net's encode, the last checkpoint |
//! | `total` | head complete | reply handed to net-io | the server time |

use std::time::{Duration, Instant};

use serve_net::Finished;

use crate::observe::{ServerTime, ServerTimeSummary};

/// The marks one request collected inside `call`.
#[derive(Clone, Copy, Debug)]
pub struct Stamps {
    pub(crate) hook: Option<Instant>,
    pub(crate) call: Instant,
    pub(crate) passport: Option<Instant>,
    pub(crate) core: Option<Instant>,
    pub(crate) service: Option<Instant>,
    pub(crate) respond: Option<Instant>,
}

impl Stamps {
    pub(crate) fn start() -> Stamps {
        Stamps {
            hook: None,
            call: Instant::now(),
            passport: None,
            core: None,
            service: None,
            respond: None,
        }
    }
}

/// One histogram per stage.
#[derive(Debug, Default)]
pub struct StageTimes {
    enabled: bool,
    wake: ServerTime,
    hook: ServerTime,
    passport: ServerTime,
    core: ServerTime,
    service: ServerTime,
    render: ServerTime,
    respond: ServerTime,
    to_reply: ServerTime,
    total: ServerTime,
}

fn between(from: Instant, to: Instant) -> Duration {
    to.saturating_duration_since(from)
}

impl StageTimes {
    /// Stage timing, on or off.
    #[must_use]
    pub fn new(enabled: bool) -> StageTimes {
        StageTimes {
            enabled,
            ..StageTimes::default()
        }
    }

    /// Whether anything is recorded.
    #[inline]
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Records the template engine's time for one render.
    #[inline]
    pub fn render(&self, took: Duration) {
        if self.enabled {
            self.render.record(took);
        }
    }

    /// Joins one request's marks with serve-net's times.
    pub(crate) fn record(&self, arrived: Instant, finished: &Finished, s: &Stamps) {
        let Some(replied) = finished.replied_at else {
            return;
        };
        let head = finished.head_at;
        let _ = arrived;
        let hook = s.hook.unwrap_or(head);
        self.wake.record(between(head, hook));
        self.hook.record(between(hook, s.call));
        let passport = s.passport.unwrap_or(s.call);
        self.passport.record(between(s.call, passport));
        let core = s.core.unwrap_or(passport);
        self.core.record(between(passport, core));
        let service = s.service.unwrap_or(core);
        if s.service.is_some() {
            self.service.record(between(core, service));
        }
        let respond = s.respond.unwrap_or(service);
        self.respond.record(between(service, respond));
        self.to_reply.record(between(respond, replied));
        self.total.record(between(head, replied));
    }

    /// Every stage's summary, in order.
    #[must_use]
    pub fn summaries(&self) -> Vec<(&'static str, ServerTimeSummary)> {
        vec![
            ("wake", self.wake.summary()),
            ("hook", self.hook.summary()),
            ("passport", self.passport.summary()),
            ("core", self.core.summary()),
            ("service", self.service.summary()),
            ("render", self.render.summary()),
            ("respond", self.respond.summary()),
            ("to_reply", self.to_reply.summary()),
            ("total", self.total.summary()),
        ]
    }

    /// Clears every histogram.
    pub fn reset(&self) {
        for h in [
            &self.wake,
            &self.hook,
            &self.passport,
            &self.core,
            &self.service,
            &self.render,
            &self.respond,
            &self.to_reply,
            &self.total,
        ] {
            h.reset();
        }
    }

    /// The summaries as a Markdown table (mean and p50 in ns).
    #[must_use]
    pub fn table(&self) -> String {
        let mut out = String::from(
            "| stage | count | mean ns | p50 below ns | p99 below ns |\n|---|---|---|---|---|\n",
        );
        for (name, s) in self.summaries() {
            out.push_str(&format!(
                "| {name} | {} | {} | {} | {} |\n",
                s.count,
                s.mean.as_nanos(),
                s.p50.as_nanos(),
                s.p99.as_nanos()
            ));
        }
        out
    }
}
