//! The request and response pipelines, as serve-net's service and admission.
//!
//! ```text
//!  net-io accept ─▶ bouncer door (gate, before any byte) ─▶ http-net parse (serve-net)
//!  head complete ─▶ admission: reserve a passport, or 503 with nothing taken
//!  body read ─▶ call: take the passport, fill it, customs head ─▶ core ─▶ service
//!  response: customs export ─▶ last checkpoint ─▶ encode ─▶ passport wiped and returned
//!  net-io write ─▶ bouncer egress (gate, before every write)
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use bouncer_io::{Bouncer, TicketTag};
use serve_net::{
    Admit, Admitted, Envelope, Finished, HeadAction, HttpHead, HttpReply, HttpRequest, HttpService,
    Outcome, ProfileTable, Shed, WorkerId,
};
use wasp_core::{
    Core, Exit, Lane, PassportPool, ProfileId, Refusal, RequestId, Routed, ServiceTag, Trip,
};

use crate::access::{AccessLog, Line};
use crate::stages::{StageTimes, Stamps};
use crate::tickets::RequestTickets;
use crate::web::{Caller, WebServices};

/// Admission: a request is admitted only if its worker has a free passport
/// for its lane (browsing cannot take the passports held back for the
/// reserved lanes). Runs once the head is complete and before any body byte
/// is read, so a slow or half-sent request never holds a passport. A refusal
/// asks the client to come back in one to three seconds, spread by
/// connection, so refused clients do not all return in the same second.
#[derive(Clone)]
pub struct PassportAdmit {
    pool: Arc<PassportPool>,
    prepared: Arc<AtomicU16>,
}

impl PassportAdmit {
    /// Admission over this pool.
    #[must_use]
    pub fn new(pool: Arc<PassportPool>) -> PassportAdmit {
        PassportAdmit {
            pool,
            prepared: Arc::new(AtomicU16::new(0)),
        }
    }

    /// The number of workers serve-net prepared admission for (0 before the
    /// server is built). The gateway refuses to open when it is more than
    /// the pool has shelves for.
    #[must_use]
    pub fn prepared_workers(&self) -> u16 {
        self.prepared.load(Ordering::Acquire)
    }
}

impl Admit for PassportAdmit {
    fn prepare(&mut self, workers: u16, _profiles: &ProfileTable) {
        // A worker the pool has no shelf for is refused at every admission
        // (fail closed); the gateway reads this back and refuses to open.
        self.prepared.store(workers, Ordering::Release);
    }

    #[inline]
    fn admit(&self, worker: WorkerId, env: &Envelope) -> Result<Admitted, Shed> {
        if self.pool.admit_lane(worker.get(), Lane(env.lane().0)) {
            Ok(Admitted { token: 0 })
        } else {
            Err(Shed {
                retry_after: Some(Duration::from_secs(1 + env.connection().get() % 3)),
                close: false,
            })
        }
    }

    #[inline]
    fn release(&self, worker: WorkerId, _env: &Envelope, _admitted: Admitted) {
        self.pool.release(worker.get());
    }
}

/// The gateway's service: the passport pipeline around the core, and the
/// hand-off to web services.
pub struct Pipeline {
    core: Arc<Core>,
    pool: Arc<PassportPool>,
    bouncer: Bouncer,
    tickets: Arc<RequestTickets>,
    web: Arc<WebServices>,
    stages: Arc<StageTimes>,
    access: Option<Arc<AccessLog>>,
    /// The lanes with a budget per caller, by core lane.
    budgeted: [bool; 6],
}

/// A passport out of its shelf for one call. If the call unwinds (a panic in
/// a service, web-net, or the theme) before the passport is given back, the
/// passport's slot wipes itself as it is dropped, and this puts a new slot on
/// the shelf so the worker keeps its capacity (counted as `lost`).
struct Loan<'a> {
    pool: &'a PassportPool,
    worker: u16,
    out: bool,
}

impl Drop for Loan<'_> {
    fn drop(&mut self) {
        if self.out {
            self.pool.replace_lost(self.worker);
        }
    }
}

/// How a request left the request pipeline.
enum Flow {
    /// A passport exit: encode its reply.
    Exit(Exit),
    /// A web service already wrote serve-net's reply; the passport goes back.
    Web(Exit, Outcome),
    /// A web service started a reply in parts: its hand-off is parked with
    /// the request until the last part.
    Parked(Outcome),
    /// Admission reserved a passport the shelf did not have (a bug; fail closed).
    NoPassport,
}

impl Pipeline {
    /// The pipeline over a loaded core, its pool, the process's bouncer, the
    /// request tickets, and the web services by tag.
    #[must_use]
    pub fn new(
        core: Arc<Core>,
        pool: Arc<PassportPool>,
        bouncer: Bouncer,
        tickets: Arc<RequestTickets>,
        web: Arc<WebServices>,
    ) -> Pipeline {
        Pipeline::with_stages(
            core,
            pool,
            bouncer,
            tickets,
            web,
            Arc::new(StageTimes::new(false)),
        )
    }

    /// [`new`](Self::new), recording stage times into `stages` when it is
    /// enabled.
    #[must_use]
    pub fn with_stages(
        core: Arc<Core>,
        pool: Arc<PassportPool>,
        bouncer: Bouncer,
        tickets: Arc<RequestTickets>,
        web: Arc<WebServices>,
        stages: Arc<StageTimes>,
    ) -> Pipeline {
        Pipeline {
            core,
            pool,
            bouncer,
            tickets,
            web,
            stages,
            access: None,
            budgeted: [false; 6],
        }
    }

    /// Charges the lanes in `rates` to each request's caller, once the core
    /// has authenticated it (the bouncer holds the budgets).
    #[must_use]
    pub fn with_lane_rates(mut self, rates: &[crate::settings::LaneRate]) -> Pipeline {
        for r in rates {
            self.budgeted[usize::from(r.lane.0.min(5))] = true;
        }
        self
    }

    /// The request's caller, bound to its ticket, charged to its lane's
    /// budget: `Some(status)` when it is over. Only for a lane with a
    /// budget, so other requests pay nothing. A signed-in caller is its
    /// session (or API key) by the id authentication gave it; a guest is its
    /// address.
    fn charge(&self, worker: u16, tag: TicketTag, h: &wasp_core::Handoff) -> Option<u16> {
        let lane = h.trip().lane;
        if !self.budgeted[usize::from(lane.0.min(5))] {
            return None;
        }
        let session = h.identity().session();
        let verdict = self.tickets.with_ticket(worker, tag, |ticket| {
            if let Some(id) = session {
                let bound =
                    ticket.bind_session(bouncer_io::SessionKey::from_digest(id.0.to_le_bytes()));
                if bound.is_deny() {
                    return bound;
                }
            }
            ticket.bind_lane(crate::bouncer::lane_class(lane))
        });
        match verdict {
            Some(bouncer_io::Verdict::Deny(d)) => Some(d.code.http_status()),
            _ => None,
        }
    }

    /// Writes a line per request to `access`.
    #[must_use]
    pub fn with_access(mut self, access: Option<Arc<AccessLog>>) -> Pipeline {
        self.access = access;
        self
    }

    /// A checkpoint on this request's ticket: `Some(status)` when the bouncer
    /// denies it. Two atomic loads while nothing is revoked. A request over
    /// its lane's budget is not denied here: the gateway answered it with
    /// its own 429 (and `Retry-After`) when it charged the budget.
    #[inline]
    fn denied(&self, tag: TicketTag) -> Option<u16> {
        match self.bouncer.egress(tag) {
            bouncer_io::Verdict::Deny(d) if d.code != bouncer_io::DenialCode::TooManyRequests => {
                Some(d.code.http_status())
            }
            _ => None,
        }
    }

    /// The request pipeline for one admitted request.
    #[inline]
    fn request(
        &self,
        req: &HttpRequest<'_>,
        env: &Envelope,
        tag: TicketTag,
        reply: &mut HttpReply,
        marks: &mut Option<Stamps>,
        loan: &mut Loan<'_>,
    ) -> Flow {
        let worker = env.worker().get();
        let Some(mut p) = self.pool.take(worker) else {
            return Flow::NoPassport;
        };
        loan.out = true;
        let service = ServiceTag(env.tag());
        p.set_trip(Trip {
            id: RequestId::new(),
            conn: env.connection().get(),
            seq: env.seq().get(),
            worker,
            profile: ProfileId(env.profile().0),
            service,
            lane: Lane(env.lane().0),
            client: env.client().addr(),
            arrived: env.arrived(),
            deadline: env.deadline(),
            ticket: tag.get(),
        });
        // Copy the head (and spans) into the passport; the body too, unless
        // a web service reads it from serve-net's request itself.
        let head = req.head();
        let minor = match head.version() {
            serve_net::Version::Http10 => 0,
            _ => 1,
        };
        let slot = p.head_mut();
        slot.set_line(head.method_str(), head.target(), minor);
        for (name, value) in head.headers() {
            slot.push_field(name, value);
        }
        if !self.core.is_external(service) {
            p.push_body(req.body_bytes());
        }

        // REQUEST: customs head.
        let p = match p.inspect(self.core.customs()) {
            Ok(p) => p,
            Err(refused) => return Flow::Exit(refused),
        };
        if let Some(m) = marks {
            m.passport = Some(Instant::now());
        }
        // Checkpoint between gateway and core.
        if let Some(status) = self.denied(tag) {
            return Flow::Exit(p.refuse_with(Refusal::status(status).closing()));
        }
        // CORE: authenticate, cache, assign the service.
        let routed = self.core.route(p);
        if let Some(m) = marks {
            m.core = Some(Instant::now());
        }
        match routed {
            Routed::Exit(exit) => Flow::Exit(exit),
            Routed::Handoff(h) => {
                if let Some(status) = self.charge(worker, tag, &h) {
                    let refusal = Refusal::status(status);
                    return Flow::Exit(h.refuse_with(if status == 429 {
                        refusal.retry_after(Duration::from_secs(1))
                    } else {
                        refusal
                    }));
                }
                match self.web.get(h.service()) {
                    Some(web) => {
                        // The gate's cookie first: a cookie of the same name the
                        // service sets (a new session) comes later and wins.
                        if let Some(cookie) = h.auth_cookie() {
                            reply.header("set-cookie", cookie);
                            // web-net decides caching without seeing this cookie:
                            // forbid every cache. Field lines combine, so a
                            // `public` web-net adds stays overruled by `no-store`.
                            reply.header("cache-control", "private, no-store");
                        }
                        if let wasp_core::Subject::User(u) = h.identity().subject() {
                            crate::note::set_user(u.0);
                        }
                        let caller = Caller::new(h.identity(), h.token_any());
                        let answered = web.respond(req, env, &caller, reply);
                        let outcome = answered.outcome;
                        if let Some(m) = marks {
                            m.service = Some(Instant::now());
                        }
                        if let (Some(ttl), Outcome::Done | Outcome::Close) =
                            (answered.guests, outcome)
                        {
                            // A whole page every guest may share: the core's
                            // guest cache gets a copy to consider.
                            let exit = self
                                .core
                                .finish_for_guests(h, ttl, |copy| copy_reply(reply, copy));
                            return Flow::Web(exit, outcome);
                        }
                        if outcome == Outcome::More {
                            // A reply in parts: the request keeps its passport,
                            // and later parts skip the pipeline (authorized once).
                            match self.tickets.park(worker, tag, h) {
                                Ok(()) => {
                                    loan.out = false;
                                    Flow::Parked(outcome)
                                }
                                Err(h) => Flow::Web(h.finish(), outcome),
                            }
                        } else {
                            Flow::Web(h.finish(), outcome)
                        }
                    }
                    None => Flow::Exit(h.refuse(500)),
                }
            }
        }
    }

    /// The next part of a web reply in parts, on the hand-off parked with the
    /// request.
    fn continue_web(
        &self,
        h: wasp_core::Handoff,
        req: &HttpRequest<'_>,
        env: &Envelope,
        tag: TicketTag,
        reply: &mut HttpReply,
    ) -> Outcome {
        let worker = env.worker().get();
        let mut loan = Loan {
            pool: &self.pool,
            worker: h.trip().worker,
            out: true,
        };
        let outcome = match self.web.get(h.service()) {
            Some(web) => {
                let caller = Caller::new(h.identity(), h.token_any());
                web.respond(req, env, &caller, reply).outcome
            }
            // Attached at open and never removed: unreachable. Ending the
            // stream with `Close` would look complete, so let serve-net's
            // service-error path cut it.
            None => Outcome::Deferred,
        };
        if outcome == Outcome::More {
            match self.tickets.park(worker, tag, h) {
                Ok(()) => {
                    loan.out = false;
                    return outcome;
                }
                Err(h) => self.pool.give_back(h.finish()),
            }
        } else {
            self.pool.give_back(h.finish());
        }
        loan.out = false;
        outcome
    }

    /// The response pipeline for a passport exit: export check, the last
    /// checkpoint, encode.
    #[inline]
    fn respond(&self, exit: Exit, tag: TicketTag, reply: &mut HttpReply) -> Outcome {
        let exit = match self.core.customs().export(exit.reply()) {
            Ok(()) => exit,
            Err(refusal) => exit.refuse_with(refusal),
        };
        let exit = match self.denied(tag) {
            Some(status) => exit.refuse_with(Refusal::status(status).closing()),
            None => exit,
        };
        let close = encode(&exit, reply);
        self.pool.give_back(exit);
        if close { Outcome::Close } else { Outcome::Done }
    }

    /// The response pipeline for a web service's reply: the passport back to
    /// the pool (the authentication cookie went on the reply before the
    /// service ran). A revocation from here on is serve-net's `BeforeReply`
    /// checkpoint, which replaces the reply whole.
    #[inline]
    fn respond_web(&self, exit: Exit, outcome: Outcome) -> Outcome {
        self.pool.give_back(exit);
        outcome
    }
}

/// Copies a web service's reply, as it set it, into the passport's reply for
/// the guest cache. A reply in parts is not copied (the cache keeps nothing
/// without a status).
fn copy_reply(from: &HttpReply, to: &mut wasp_core::Reply) {
    let parts = from.parts();
    if parts.is_streamed() {
        return;
    }
    to.status(parts.status());
    for (name, value) in parts.headers() {
        to.header(name, value);
    }
    to.body(parts.body());
}

/// Writes the exit's reply into serve-net's reply. serve-net encodes it through
/// http-net, adds `Date`, and refuses invalid fields with a 500.
#[inline]
fn encode(exit: &Exit, out: &mut HttpReply) -> bool {
    let reply = exit.reply();
    out.status(reply.status_code());
    for (name, value) in reply.fields() {
        // Names were written as `&str`, so this never fails; a broken name
        // becomes an invalid field, which serve-net turns into a 500.
        out.header(std::str::from_utf8(name).unwrap_or("\u{0}"), value);
    }
    if let Some(cookie) = exit.auth_cookie() {
        out.header("set-cookie", cookie);
        // As on the web path: a reply that sets the gate's cookie (a cached
        // page answering a stale session, for one) is never kept by a cache.
        out.header("cache-control", "private, no-store");
    }
    if reply.status_code() >= 400 {
        out.header("x-content-type-options", "nosniff");
        out.header("cache-control", "no-store");
    }
    out.body(reply.body_bytes());
    if let Some(after) = reply.retry_after() {
        out.retry_after(after);
    }
    if reply.closes() {
        out.close();
    }
    reply.closes()
}

impl Pipeline {
    /// [`HttpService::call`], between the note's start and end.
    fn call_noted(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        let tag = TicketTag::from_raw(env.user_word());
        let worker = env.worker().get();
        // A later part of a reply in parts: the request was authorized when
        // its first part ran. No passport, customs, or authentication again,
        // and nothing here can refuse into a body already on the wire (a
        // revocation is serve-net's checkpoint, which aborts the connection).
        if let Some(h) = self.tickets.unpark(worker, tag) {
            return self.continue_web(h, req, env, tag, reply);
        }
        let mut marks = self.stages.enabled().then(Stamps::start);
        let mut loan = Loan {
            pool: &self.pool,
            worker: env.worker().get(),
            out: false,
        };
        let outcome = match self.request(req, env, tag, reply, &mut marks, &mut loan) {
            Flow::Exit(exit) => {
                let o = self.respond(exit, tag, reply);
                loan.out = false;
                o
            }
            Flow::Web(exit, outcome) => {
                let o = self.respond_web(exit, outcome);
                loan.out = false;
                o
            }
            Flow::Parked(outcome) => outcome,
            Flow::NoPassport => {
                reply
                    .text(503, wasp_core::refusal_text(503))
                    .retry_after(Duration::from_secs(1));
                Outcome::Done
            }
        };
        if let Some(mut m) = marks {
            m.respond = Some(Instant::now());
            self.tickets.set_stamps(env.worker().get(), tag, m);
        }
        outcome
    }
}

impl HttpService for Pipeline {
    /// The head is complete: the request's bouncer ticket, under the
    /// connection's, is taken and held until `done`. A connection the door
    /// never admitted, or one already revoked, is refused here.
    fn head(&self, head: &HttpHead<'_>, env: &mut Envelope) -> HeadAction {
        let hook = self.stages.enabled().then(Instant::now);
        // The profile's lane rules (health, admin, sign-in), before the
        // urgent line and admission read the lane.
        if let Some(profile) = self.core.profile(ProfileId(env.profile().0))
            && !profile.lanes.is_empty()
        {
            let lane = profile.lane_for(head.method_str(), head.path());
            env.set_lane(serve_net::Lane(lane.0));
        }
        let id = bouncer_io::RequestId(
            u128::from(env.connection().get()) << 32 | u128::from(env.seq().get()),
        );
        let mut ticket = match self.bouncer.request(TicketTag::from(env.gate_tag()), id) {
            Ok(ticket) => ticket,
            Err(bouncer_io::BouncerError::Revoked) => return HeadAction::refuse(403),
            Err(_) => return HeadAction::refuse(503),
        };
        // Behind a trusted proxy, serve-net names the real client from the
        // forwarded header: the bouncer judges and charges that client (bans,
        // budgets), not the proxy every visitor shares.
        if env.client().ingress() == serve_net::IngressKind::Forwarded
            && let Some(addr) = env.client().addr()
            && let bouncer_io::Verdict::Deny(d) =
                ticket.bind_client(addr, bouncer_io::Provenance::ForwardedHeader)
        {
            return HeadAction::refuse(d.code.http_status());
        }
        let line = self
            .access
            .as_ref()
            .and_then(|a| a.capture())
            .map(|wants| Line::of(head, wants));
        match self.tickets.hold_at(env.worker().get(), ticket, hook, line) {
            Some(tag) => {
                env.set_user_word(tag.get());
                HeadAction::Proceed
            }
            None => HeadAction::refuse(503),
        }
    }

    fn call(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        // The path, for a web service on this thread that asks where it is
        // (`note::path_under`); what it notes is taken when the call ends.
        crate::note::begin(req.path());
        let outcome = self.call_noted(req, env, reply);
        if let Some(note) = crate::note::end()
            && self.access.is_some()
            && env.user_word() != 0
        {
            self.tickets.set_note(
                env.worker().get(),
                TicketTag::from_raw(env.user_word()),
                note,
            );
        }
        outcome
    }

    fn done(&self, env: &Envelope, finished: &Finished) {
        // A web service forgets what it kept for the request (web-net's
        // record of a reply in parts).
        if let Some(web) = self.web.get(ServiceTag(env.tag())) {
            web.done(env, finished);
        }
        if env.user_word() == 0 {
            if let Some(access) = &self.access {
                access.finished(None, env, finished);
            }
            return;
        }
        let (stamps, parked, line) = self
            .tickets
            .release_all(env.worker().get(), TicketTag::from_raw(env.user_word()));
        if let Some(access) = &self.access {
            access.finished(line, env, finished);
        }
        if let Some(h) = parked {
            // The client left before the last part.
            self.pool.give_back(h.finish());
        }
        if let Some(stamps) = stamps {
            self.stages.record(env.arrived(), finished, &stamps);
        }
    }
}
