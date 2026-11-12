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
use std::time::{Duration, Instant};

use bouncer_io::{Bouncer, TicketTag};
use serve_net::{
    Admit, Admitted, Envelope, Finished, HeadAction, HttpHead, HttpReply, HttpRequest, HttpService,
    Outcome, ProfileTable, Shed, WorkerId,
};
use wasp_core::{
    Core, Exit, Lane, PassportPool, ProfileId, Refusal, RequestId, Routed, ServiceTag, Trip,
};

use crate::stages::{StageTimes, Stamps};
use crate::tickets::RequestTickets;
use crate::web::{Caller, WebServices};

/// Admission: a request is admitted only if its worker has a free passport.
/// Runs once the head is complete and before any body byte is read, so a slow
/// or half-sent request never holds a passport.
#[derive(Clone)]
pub struct PassportAdmit {
    pool: Arc<PassportPool>,
    retry_after: Duration,
}

impl PassportAdmit {
    /// Admission over this pool.
    #[must_use]
    pub fn new(pool: Arc<PassportPool>) -> PassportAdmit {
        PassportAdmit {
            pool,
            retry_after: Duration::from_secs(1),
        }
    }
}

impl Admit for PassportAdmit {
    fn prepare(&mut self, workers: u16, _profiles: &ProfileTable) {
        // The pool is sized at boot for the configured workers. A worker the
        // pool has no shelf for is refused at every admission (fail closed);
        // the gateway checks the two agree before it opens.
        debug_assert!(workers <= self.pool.workers());
    }

    #[inline]
    fn admit(&self, worker: WorkerId, _env: &Envelope) -> Result<Admitted, Shed> {
        if self.pool.admit(worker.get()) {
            Ok(Admitted { token: 0 })
        } else {
            Err(Shed {
                retry_after: Some(self.retry_after),
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
}

/// How a request left the request pipeline.
enum Flow {
    /// A passport exit: encode its reply.
    Exit(Exit),
    /// A web service already wrote serve-net's reply; the passport goes back.
    Web(Exit, Outcome),
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
        }
    }

    /// A checkpoint on this request's ticket: `Some(status)` when the bouncer
    /// denies it. Two atomic loads while nothing is revoked.
    #[inline]
    fn denied(&self, tag: TicketTag) -> Option<u16> {
        match self.bouncer.egress(tag) {
            bouncer_io::Verdict::Deny(d) => Some(d.code.http_status()),
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
    ) -> Flow {
        let worker = env.worker().get();
        let Some(mut p) = self.pool.take(worker) else {
            return Flow::NoPassport;
        };
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
            p.body_mut().extend_from_slice(req.body_bytes());
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
            Routed::Handoff(h) => match self.web.get(h.service()) {
                Some(web) => {
                    // The gate's cookie first: a cookie of the same name the
                    // service sets (a new session) comes later and wins.
                    if let Some(cookie) = h.auth_cookie() {
                        reply.header("set-cookie", cookie);
                    }
                    let caller = Caller::new(h.identity(), h.token_any());
                    let outcome = web.respond(req, env, &caller, reply);
                    if let Some(m) = marks {
                        m.service = Some(Instant::now());
                    }
                    Flow::Web(h.finish(), outcome)
                }
                None => Flow::Exit(h.refuse(500)),
            },
        }
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

impl HttpService for Pipeline {
    /// The head is complete: the request's bouncer ticket, under the
    /// connection's, is taken and held until `done`. A connection the door
    /// never admitted, or one already revoked, is refused here.
    fn head(&self, _head: &HttpHead<'_>, env: &mut Envelope) -> HeadAction {
        let hook = self.stages.enabled().then(Instant::now);
        let id = bouncer_io::RequestId(
            u128::from(env.connection().get()) << 32 | u128::from(env.seq().get()),
        );
        let ticket = match self.bouncer.request(TicketTag::from(env.gate_tag()), id) {
            Ok(ticket) => ticket,
            Err(bouncer_io::BouncerError::Revoked) => return HeadAction::refuse(403),
            Err(_) => return HeadAction::refuse(503),
        };
        match self.tickets.hold_at(env.worker().get(), ticket, hook) {
            Some(tag) => {
                env.set_user_word(tag.get());
                HeadAction::Proceed
            }
            None => HeadAction::refuse(503),
        }
    }

    fn call(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        let tag = TicketTag::from_raw(env.user_word());
        let mut marks = self.stages.enabled().then(Stamps::start);
        let outcome = match self.request(req, env, tag, reply, &mut marks) {
            Flow::Exit(exit) => self.respond(exit, tag, reply),
            Flow::Web(exit, outcome) => self.respond_web(exit, outcome),
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

    fn done(&self, env: &Envelope, finished: &Finished) {
        if env.user_word() != 0
            && let Some(stamps) = self
                .tickets
                .release(env.worker().get(), TicketTag::from_raw(env.user_word()))
        {
            self.stages.record(env.arrived(), finished, &stamps);
        }
    }
}
