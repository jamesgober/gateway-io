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
use std::time::Duration;

use bouncer_io::{Bouncer, TicketTag};
use serve_net::{
    Admit, Admitted, Envelope, HttpReply, HttpRequest, HttpService, Outcome, ProfileTable, Shed,
    WorkerId,
};
use wasp_core::{Core, Exit, Lane, PassportPool, ProfileId, Refusal, RequestId, ServiceTag, Trip};

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

/// The gateway's service: the passport pipeline around the core.
pub struct Pipeline {
    core: Arc<Core>,
    pool: Arc<PassportPool>,
    bouncer: Bouncer,
}

impl Pipeline {
    /// The pipeline over a loaded core, its pool, and the process's bouncer.
    #[must_use]
    pub fn new(core: Arc<Core>, pool: Arc<PassportPool>, bouncer: Bouncer) -> Pipeline {
        Pipeline {
            core,
            pool,
            bouncer,
        }
    }

    /// The request pipeline for one admitted request, ending in an exit.
    #[inline]
    fn request(
        &self,
        req: &HttpRequest<'_>,
        env: &Envelope,
        ticket: &mut bouncer_io::Ticket,
    ) -> Result<Exit, Shortfall> {
        let worker = env.worker().get();
        let mut p = self.pool.take(worker).ok_or(Shortfall::NoPassport)?;
        let id = RequestId::new();
        p.set_trip(Trip {
            id,
            conn: env.connection().get(),
            seq: env.seq().get(),
            worker,
            profile: ProfileId(env.profile().0),
            service: ServiceTag(env.tag()),
            lane: Lane(env.lane().0),
            client: env.client().addr(),
            arrived: env.arrived(),
            deadline: env.deadline(),
            ticket: ticket.tag().get(),
        });
        // Copy the head (and spans) and the buffered body into the passport.
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
        p.body_mut().extend_from_slice(req.body_bytes());

        // REQUEST: customs head.
        let p = match p.inspect(self.core.customs()) {
            Ok(p) => p,
            Err(refused) => return Ok(refused),
        };
        // Checkpoint between gateway and core.
        if let bouncer_io::Verdict::Deny(d) = ticket.checkpoint() {
            return Ok(p.refuse_with(Refusal::status(d.code.http_status()).closing()));
        }
        // CORE: authenticate, cache, assign the service.
        Ok(self.core.handle(p))
    }

    /// The response pipeline: export check, the last checkpoint, encode.
    #[inline]
    fn respond(
        &self,
        exit: Exit,
        ticket: &mut bouncer_io::Ticket,
        reply: &mut HttpReply,
    ) -> Outcome {
        let exit = match self.core.customs().export(exit.reply()) {
            Ok(()) => exit,
            Err(refusal) => exit.refuse_with(refusal),
        };
        let exit = match ticket.checkpoint() {
            bouncer_io::Verdict::Deny(d) => {
                exit.refuse_with(Refusal::status(d.code.http_status()).closing())
            }
            _ => exit,
        };
        let close = encode(&exit, reply);
        self.pool.give_back(exit);
        if close { Outcome::Close } else { Outcome::Done }
    }
}

/// Why a request could not get as far as an exit.
enum Shortfall {
    /// Admission reserved a passport the shelf did not have (a bug; fail closed).
    NoPassport,
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
    fn call(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        // The request's bouncer ticket, under the connection's. A connection the
        // door never admitted (or one already released) fails closed.
        let id = bouncer_io::RequestId(
            u128::from(env.connection().get()) << 32 | u128::from(env.seq().get()),
        );
        let Ok(mut ticket) = self.bouncer.request(TicketTag::from(env.gate_tag()), id) else {
            reply.text(503, wasp_core::refusal_text(503)).close();
            return Outcome::Close;
        };
        match self.request(req, env, &mut ticket) {
            Ok(exit) => self.respond(exit, &mut ticket, reply),
            Err(Shortfall::NoPassport) => {
                reply
                    .text(503, wasp_core::refusal_text(503))
                    .retry_after(Duration::from_secs(1));
                Outcome::Done
            }
        }
    }
}
