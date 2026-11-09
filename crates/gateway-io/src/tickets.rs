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

/// One worker's live request tickets. Touched by the owning worker only on the
/// inline path, so the lock is uncontended.
#[repr(align(64))]
struct Shelf {
    live: Mutex<Vec<Ticket>>,
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
        let shelf = self.shelves.get(usize::from(worker))?;
        let tag = ticket.tag();
        shelf.live.lock().ok()?.push(ticket);
        Some(tag)
    }

    /// Releases the ticket with `tag`, when its request is done.
    #[inline]
    pub fn release(&self, worker: u16, tag: TicketTag) {
        let Some(shelf) = self.shelves.get(usize::from(worker)) else {
            return;
        };
        // Taken out under the lock, dropped after it.
        let gone = shelf.live.lock().ok().and_then(|mut live| {
            live.iter()
                .position(|t| t.tag() == tag)
                .map(|i| live.swap_remove(i))
        });
        drop(gone);
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
