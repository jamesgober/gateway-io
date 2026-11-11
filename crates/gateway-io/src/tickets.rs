//! The bouncer's request tickets, held from the head to the end of the request.
//!
//! A request ticket is taken when the head is complete and kept until serve-net
//! reports the request done (after the last byte of its reply was handed to
//! net-io). Its tag rides in the envelope's user word, so every checkpoint
//! (between gateway and core, before encode, and serve-net's own before the
//! reply, which replaces a reply whole) judges exactly this request with one
//! lock-free `egress` call. The ticket itself lives here, per worker, because
//! dropping it releases it.

use std::sync::Mutex;

use bouncer_io::{Ticket, TicketTag};

use crate::stages::Stamps;

/// One worker's live request tickets. Touched by the owning worker only on the
/// inline path, so the lock is uncontended.
#[repr(align(64))]
struct Shelf {
    live: Mutex<Vec<(Ticket, Option<Stamps>)>>,
}

/// Request tickets, per worker.
pub struct RequestTickets {
    shelves: Box<[Shelf]>,
}

impl RequestTickets {
    /// Shelves for `workers` workers.
    #[must_use]
    pub fn new(workers: u16) -> RequestTickets {
        RequestTickets {
            shelves: (0..workers.max(1))
                .map(|_| Shelf {
                    live: Mutex::new(Vec::with_capacity(16)),
                })
                .collect(),
        }
    }

    /// Keeps `ticket` alive for its request and returns its tag for the
    /// envelope. `None` when the worker is unknown (the ticket is dropped,
    /// which releases it; the caller refuses the request).
    #[inline]
    #[must_use]
    pub fn hold(&self, worker: u16, ticket: Ticket) -> Option<TicketTag> {
        self.hold_at(worker, ticket, None)
    }

    /// [`hold`](Self::hold), with the moment the head hook ran (stage timing).
    pub(crate) fn hold_at(
        &self,
        worker: u16,
        ticket: Ticket,
        hook: Option<std::time::Instant>,
    ) -> Option<TicketTag> {
        let shelf = self.shelves.get(usize::from(worker))?;
        let tag = ticket.tag();
        let stamps = hook.map(|h| Stamps {
            hook: Some(h),
            ..Stamps::start()
        });
        shelf.live.lock().ok()?.push((ticket, stamps));
        Some(tag)
    }

    /// Keeps the stage marks of the request with `tag` (stage timing only).
    pub(crate) fn set_stamps(&self, worker: u16, tag: TicketTag, stamps: Stamps) {
        if let Some(shelf) = self.shelves.get(usize::from(worker))
            && let Ok(mut live) = shelf.live.lock()
            && let Some(entry) = live.iter_mut().find(|(t, _)| t.tag() == tag)
        {
            let hook = entry.1.and_then(|s| s.hook);
            entry.1 = Some(Stamps { hook, ..stamps });
        }
    }

    /// Releases the ticket with `tag`, when its request is done, and hands
    /// back the request's stage marks if it had any.
    #[inline]
    pub fn release(&self, worker: u16, tag: TicketTag) -> Option<Stamps> {
        let shelf = self.shelves.get(usize::from(worker))?;
        // Taken out under the lock, dropped after it.
        let gone = shelf.live.lock().ok().and_then(|mut live| {
            live.iter()
                .position(|(t, _)| t.tag() == tag)
                .map(|i| live.swap_remove(i))
        });
        let stamps = gone.as_ref().and_then(|(_, s)| *s);
        drop(gone);
        stamps
    }

    /// Tickets held right now, for health and tests.
    #[must_use]
    pub fn held(&self) -> usize {
        self.shelves
            .iter()
            .map(|s| s.live.lock().map_or(0, |l| l.len()))
            .sum()
    }
}

impl std::fmt::Debug for RequestTickets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestTickets")
            .field("workers", &self.shelves.len())
            .field("held", &self.held())
            .finish()
    }
}
