//! The passport's costs, step by step, against the estimates of the design
//! (take, trip, head copy, hand-offs, stamps, wipe).
//!
//! ```text
//! cargo bench -p wasp-core --bench passport
//! ```
//!
//! std only, one thread. Each step is timed in rounds of 200,000 iterations;
//! the whole suite runs in three passes and each step reports its fastest
//! round across them. On a shared machine the scheduler moves the thread
//! between cores of different speed over seconds, so the fastest round is the
//! closest figure to the code's own cost. Steps are timed as a growing chain
//! and reported as increments, because a passport cannot leave the pool
//! without being returned.

use std::hint::black_box;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use wasp_core::stub::Hello;
use wasp_core::{
    Arrived, Core, HeadRules, Lane, Passport, PassportPool, ProfileId, RequestId, ServiceTag,
    SlotSizes, Trip,
};

const ITERS: u32 = 200_000;
const ROUNDS: usize = 9;
const PASSES: usize = 3;

/// A typical browser GET: 10 fields, about 560 bytes.
const FIELDS: &[(&str, &[u8])] = &[
    ("host", b"example.com"),
    (
        "user-agent",
        b"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    ),
    (
        "accept",
        b"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ),
    ("accept-language", b"en-US,en;q=0.9"),
    ("accept-encoding", b"gzip, deflate, br, zstd"),
    (
        "cookie",
        b"__Host-sid=Zk3J9qVb2xL0p7sQwE4rT6yU8iO1aS3d; theme=dark",
    ),
    ("sec-fetch-site", b"same-origin"),
    ("sec-fetch-mode", b"navigate"),
    ("sec-fetch-dest", b"document"),
    ("upgrade-insecure-requests", b"1"),
];

/// The fastest round's ns per call.
fn measure(mut f: impl FnMut()) -> f64 {
    for _ in 0..ITERS / 10 {
        f();
    }
    (0..ROUNDS)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..ITERS {
                f();
            }
            t.elapsed().as_nanos() as f64 / f64::from(ITERS)
        })
        .fold(f64::INFINITY, f64::min)
}

struct Fixture {
    pool: PassportPool,
    core: Core,
    customs: HeadRules,
    now: Instant,
    client: IpAddr,
    body_2k: Vec<u8>,
    body_64k: Vec<u8>,
}

impl Fixture {
    fn trip(&self) -> Trip {
        Trip {
            id: RequestId::new(),
            conn: 4411,
            seq: 1,
            worker: 0,
            profile: ProfileId(0),
            service: ServiceTag(0),
            lane: Lane(4),
            client: Some(self.client),
            arrived: self.now,
            deadline: self.now + Duration::from_secs(30),
            ticket: 88_213,
        }
    }

    fn fill(&self, p: &mut Passport<Arrived>) {
        p.set_trip(self.trip());
        let h = p.head_mut();
        h.set_line("GET", "/account/settings?tab=profile", 1);
        for (n, v) in FIELDS {
            h.push_field(n, v);
        }
    }
}

const STEPS: usize = 10;

/// One pass over every step:
/// [ulid, a, b, c, d, e, wipe_2k, wipe_64k, copy_64k, handoff].
fn pass(x: &Fixture) -> [f64; STEPS] {
    let pool = &x.pool;
    let ulid = measure(|| {
        black_box(RequestId::new());
    });
    // A: admission + take + refuse + give back (wipe of an empty slot) + release.
    let a = measure(|| {
        let p = pool.admit_and_take(0).expect("passport");
        pool.give_back_and_release(black_box(p).refuse(500));
    });
    // B: A + the trip facts (includes the request id).
    let b = measure(|| {
        let mut p = pool.admit_and_take(0).expect("passport");
        p.set_trip(x.trip());
        pool.give_back_and_release(black_box(p).refuse(500));
    });
    // C: B + the head copy (request line, 10 fields as spans), wiped on return.
    let c = measure(|| {
        let mut p = pool.admit_and_take(0).expect("passport");
        x.fill(&mut p);
        pool.give_back_and_release(black_box(p).refuse(500));
    });
    // D: C + customs head (Arrived to Inspected).
    let d = measure(|| {
        let mut p = pool.admit_and_take(0).expect("passport");
        x.fill(&mut p);
        let exit = match p.inspect(&x.customs) {
            Ok(p) => p.refuse(500),
            Err(e) => e,
        };
        pool.give_back_and_release(black_box(exit));
    });
    // E: D + the core (authenticate, cache miss, assign) + the hello service
    // (route, authorize, render the page into the reply).
    let e = measure(|| {
        let mut p = pool.admit_and_take(0).expect("passport");
        x.fill(&mut p);
        let exit = match p.inspect(&x.customs) {
            Ok(p) => x.core.handle(p),
            Err(e) => e,
        };
        pool.give_back_and_release(black_box(exit));
    });
    // Wipe on return: a 2 KiB request (head + body) and a 64 KiB body.
    let wipe_2k = measure(|| {
        let mut p = pool.admit_and_take(0).expect("passport");
        let h = p.head_mut();
        h.set_line("GET", "/", 1);
        for (n, v) in FIELDS {
            h.push_field(n, v);
        }
        p.body_mut().extend_from_slice(&x.body_2k);
        pool.give_back_and_release(black_box(p).refuse(500));
    });
    let wipe_64k = measure(|| {
        let mut p = pool.admit_and_take(0).expect("passport");
        p.body_mut().extend_from_slice(&x.body_64k);
        pool.give_back_and_release(black_box(p).refuse(500));
    });
    // The copy alone, to separate it from the wipe above.
    let mut scratch: Vec<u8> = Vec::with_capacity(64 * 1024);
    let copy_64k = measure(|| {
        scratch.clear();
        scratch.extend_from_slice(black_box(&x.body_64k));
        black_box(&scratch);
    });
    // A hand-off: the passport through a function boundary that is not inlined.
    #[inline(never)]
    fn hand_off<T>(t: T) -> T {
        black_box(t)
    }
    let mut slot = Some(pool.admit_and_take(0).expect("passport"));
    let handoff = measure(|| {
        let p = slot.take().expect("passport");
        slot = Some(hand_off(p));
    });
    if let Some(p) = slot {
        pool.give_back_and_release(p.refuse(500));
    }
    [ulid, a, b, c, d, e, wipe_2k, wipe_64k, copy_64k, handoff]
}

fn main() {
    let x = Fixture {
        pool: PassportPool::new(1, 64, SlotSizes::default()),
        core: Core::builder()
            .service("hello", Hello::new)
            .profile("site", "hello", |_| {})
            .load()
            .expect("core"),
        customs: HeadRules::default(),
        now: Instant::now(),
        client: "203.0.113.7".parse().expect("address"),
        body_2k: vec![b'x'; 2048 - 560],
        body_64k: vec![b'x'; 64 * 1024],
    };
    let mut best = [f64::INFINITY; STEPS];
    for _ in 0..PASSES {
        for (b, v) in best.iter_mut().zip(pass(&x)) {
            *b = b.min(v);
        }
    }
    let [ulid, a, b, c, d, e, wipe_2k, wipe_64k, copy_64k, handoff] = best;

    println!(
        "passport costs, ns per request (fastest round of {PASSES} passes x {ROUNDS} x {ITERS}), one thread"
    );
    println!();
    println!("| step | measured | design estimate (6.4) |");
    println!("|---|---|---|");
    println!("| request id (ULID) | {ulid:.1} | (in the trip) |");
    println!(
        "| take + return an empty slot (admit, take, refuse, give back, release) | {a:.1} | 2-5 (take only) |"
    );
    println!(
        "| fill the trip fields (incl. the id) | {:.1} | 10-30 |",
        b - a
    );
    println!(
        "| copy the head and spans (10 fields, 560 B; wiped on return) | {:.1} | 20-50 |",
        c - b
    );
    println!(
        "| customs head (Arrived to Inspected) | {:.1} | a few (stamp) |",
        d - c
    );
    println!(
        "| core + hello service (identify, assign, authorize, render) | {:.1} | (not in 6.4) |",
        e - d
    );
    println!("| hand-off (8-byte move, not inlined) | {handoff:.1} | ~1 |");
    println!(
        "| copy in and wipe a 2 KiB request (over the empty cycle) | {:.1} | 50-100 (wipe) |",
        wipe_2k - a
    );
    println!(
        "| wipe a 64 KiB body (over the empty cycle, less the copy in) | {:.1} | 1000-2000 |",
        wipe_64k - a - copy_64k
    );
    println!(
        "| **passport total** (take, trip, head, customs, return) | **{d:.1}** | **90-200** |"
    );
    println!("| passport + core + hello | {e:.1} | |");
}
