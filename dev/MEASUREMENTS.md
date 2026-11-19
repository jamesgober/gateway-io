# Measurements

Laptop numbers on a shared machine (AMD Ryzen 9 9950X3D, 16 cores / 32 threads, Windows 11 and WSL2 Ubuntu on the same box). During every run other work held the CPU near 100%, so figures are for comparing builds and for checking the design's estimates, not for publishing. Each figure says how it was taken.

Reproduce: `cargo bench -p wasp-core --bench passport` and `cargo bench -p gateway-io --bench request_path`.

## The passport

std-only benchmark, one thread, steps timed as a growing chain (a passport cannot leave the pool without returning) and reported as increments; fastest round of 3 passes x 9 rounds x 200,000 iterations. A browser-like head: request line plus 10 fields, 560 bytes.

| Step | Estimate | Windows | WSL2 Linux (noisier: load 70) | Notes |
|---|---|---|---|---|
| take a slot from the pool | 2-5 ns | 45.7 (full cycle) | 59.5 | The cycle is admission (atomic), take (uncontended lock), a refusal write, give back (lock, wipe of an empty slot), release (atomic). Take alone is not separable; a lock-free shelf is the next step if it matters (G-7). |
| fill the trip fields | 10-30 ns | 41.1 | 109.1 | Includes the request id (ULID, 28 ns); about 13 ns without it. |
| copy the request head and spans | 20-50 ns | 66.9 | 30.9 | Includes wiping those 560 bytes on return. |
| each hand-off | ~1 ns | 1.1 | 1.2 | An 8-byte move through a call that is not inlined. |
| stamps | a few ns | customs head 21.5 | 61.5 | The customs stamp with its checks (sizes, single-use fields, Host). Identity and access stamps are inside the core figure below. |
| wipe on return, 2 KiB | 50-100 ns | 82.0 | 96.2 | Copy in plus wipe, over the empty cycle. |
| wipe on return, 64 KiB body | 1-2 us | 0.35 us | 0.54 us | Vectorized fill (G-9). With crypt-io's zeroize-backed wipe it measured 10.5 us. |
| **passport total** | **90-200 ns** | **175** | **261** | Take, trip, head copy, customs, return. Windows inside the estimate; the Linux run was on a machine at load 70 and its steps moved between runs. |
| passport + core + hello service | (not estimated) | 260 | 331 | Adds authenticate (guest), cache miss, assign, route, authorize, render a 110-byte page. |

## The request path over loopback (WASP-NEXUS 2.1)

Keep-alive connections, one request in flight each, 4 reactor workers, client threads on the same machine. "serve-net alone" answers the same page with a bare handler on the same workers, so the difference is what the platform adds (bouncer door and egress, admission, passport, customs, core, service, encode).

Windows (CPU near 100% from other work):

| server | connections | requests/s | p50 us | p99 us | p99.9 us | failed |
|---|---|---|---|---|---|---|
| serve-net alone | 1 | 20914 | 49.3 | 137.6 | 806.8 | 0 |
| gateway (WASP path) | 1 | 18526 | 53.1 | 105.2 | 987.0 | 0 |
| difference at p50 | 1 | | +3.8 | | | |
| serve-net alone | 8 | 146377 | 41.9 | 148.4 | 1051.0 | 0 |
| gateway (WASP path) | 8 | 164162 | 34.2 | 132.0 | 971.8 | 0 |
| difference at p50 | 8 | | -7.7 | | | |
| serve-net alone | 32 | 148292 | 112.2 | 1668.5 | 6573.1 | 0 |
| gateway (WASP path) | 32 | 115530 | 111.3 | 2395.1 | 8424.0 | 0 |
| difference at p50 | 32 | | -0.9 | | | |

WSL2 Linux (load average 70 on 32 CPUs):

| server | connections | requests/s | p50 us | p99 us | p99.9 us | failed |
|---|---|---|---|---|---|---|
| serve-net alone | 1 | 62497 | 9.5 | 49.6 | 520.9 | 0 |
| gateway (WASP path) | 1 | 32436 | 10.0 | 61.2 | 6729.0 | 0 |
| difference at p50 | 1 | | +0.6 | | | |
| serve-net alone | 8 | 119330 | 16.2 | 130.9 | 11836.3 | 0 |
| gateway (WASP path) | 8 | 137556 | 17.3 | 114.9 | 7712.9 | 0 |
| difference at p50 | 8 | | +1.1 | | | |
| serve-net alone | 32 | 119330 | 67.3 | 3193.4 | 17315.5 | 0 |
| gateway (WASP path) | 32 | 107894 | 69.2 | 10839.5 | 26209.6 | 0 |
| difference at p50 | 32 | | +1.9 | | | |

Server time inside each server (head complete to reply handed to net-io, from serve-net's `Finished`), as a log-linear histogram:

Windows:

| connections | serve-net alone mean ns | gateway mean ns | added by the WASP path, mean ns | gateway p50 below | gateway p99 below |
|---|---|---|---|---|---|
| 1 | 9147 | 12677 | +3530 | 10.24µs | 65.536µs |
| 8 | 12211 | 16696 | +4485 | 7.168µs | 163.84µs |
| 32 | 290071 | 357271 | +67200 | 196.608µs | 4.194304ms |

WSL2 Linux:

| connections | serve-net alone mean ns | gateway mean ns | added by the WASP path, mean ns | gateway p50 below | gateway p99 below |
|---|---|---|---|---|---|
| 1 | 2726 | 3555 | +829 | 1.792µs | 10.24µs |
| 8 | 10863 | 10234 | -629 | 2.56µs | 40.96µs |
| 32 | 67943 | 92778 | +24835 | 28.672µs | 229.376µs |

The cleanest figure is the single connection on Linux: the WASP path adds about 0.8 us of server time per request (3.6 us against 2.7 us mean; gateway p50 under 1.8 us). With more connections than workers, queueing on the loaded machine dominates both servers.

What the WASP path adds inside the server, timed around the gateway's `call` on Windows: 1.8 us mean over 18,000 requests, against 79 ns for the bare handler; the microbenchmarks above account for about 0.4 us of it (passport, core, hello, bouncer request ticket 60-100 ns), the rest is the copy into serve-net's reply and noise from the loaded machine.

| WASP-NEXUS 2.1 step | Estimate | Measured |
|---|---|---|
| 1-2 read, door, parse, passport | 1-2 us | passport 0.18 us; door and parse are serve-net's and equal in both servers |
| 3 identify (guest) | 0.1 us | inside the 0.26 us core + hello figure |
| 4 assign | ~1 ns | an array index |
| 6-7 route and authorize | 0.1 us | inside the 0.26 us figure (stub router) |
| 9 render | 2-20 us | 0.1 us for the hello page (no template engine yet) |
| 10 encode and write | 1-5 us | serve-net's, equal in both servers |
| total server time | 5-30 us | Linux, one connection: 3.6 us mean, p50 under 1.8 us (bare serve-net 2.7 us); Windows p50 under 10 us. End to end the WASP path is within 0.6 to 1.9 us of bare serve-net at p50 on Linux |

## Findings

- The estimates hold for the passport (175 ns on Windows against 90-200 ns; 261 ns on the heavily loaded Linux run) once the wipe is a vectorized fill; with zeroize's per-byte volatile writes the passport total was about 500 ns and a 64 KiB wipe 10.5 us.
- Re-scanning field values in customs cost about 150 ns per request; the parser already refuses those bytes, so customs keeps only policy (G-10).
- End to end, the WASP path is indistinguishable from bare serve-net within the noise of this machine (runs of the same server differ by more than the gap). The published comparison needs the reference box.
- On a single connection, runs with a net-io gate installed were sometimes 10-25 us slower at p50 than without one, but not reproducibly; worth a quiet-machine run before concluding anything about the gate's write path.

## Step 4: the web path (web-net 0.6 behind the core)

Same benchmark (`cargo bench -p gateway-io --bench request_path`), now with two comparisons: the hello passport service against serve-net alone, and the web site path (core authenticates, hands off, web-net routes, authorizes through the core's access gate, renders) against web-net alone on serve-net with the same route. Since this step every request also takes its bouncer ticket at the head and releases it when done (G-16).

WSL2 Linux (load average 82 to 90 on 32 CPUs), passport path:

| server | connections | requests/s | p50 us | p99 us | p99.9 us | failed |
|---|---|---|---|---|---|---|
| serve-net alone | 1 | 30071 | 8.7 | 90.4 | 11096.0 | 0 |
| gateway + hello | 1 | 20402 | 9.3 | 50.6 | 12194.9 | 0 |
| difference at p50 | 1 | | +0.6 | | | |
| serve-net alone | 8 | 78748 | 13.2 | 78.3 | 13039.9 | 0 |
| gateway + hello | 8 | 72550 | 17.9 | 210.1 | 14906.8 | 0 |
| difference at p50 | 8 | | +4.7 | | | |
| serve-net alone | 32 | 60960 | 63.0 | 4037.2 | 43070.5 | 0 |
| gateway + hello | 32 | 64683 | 65.9 | 10805.6 | 37427.8 | 0 |
| difference at p50 | 32 | | +2.9 | | | |

| connections | serve-net alone mean ns | gateway + hello mean ns | added, mean ns | gateway + hello p50 below | gateway + hello p99 below |
|---|---|---|---|---|---|
| 1 | 3332 | 3763 | +431 | 1.792µs | 10.24µs |
| 8 | 8333 | 9888 | +1555 | 2.56µs | 40.96µs |
| 32 | 70793 | 86251 | +15458 | 24.576µs | 262.144µs |

WSL2 Linux, web path:

| server | connections | requests/s | p50 us | p99 us | p99.9 us | failed |
|---|---|---|---|---|---|---|
| web-net alone | 1 | 39319 | 9.9 | 69.1 | 4340.2 | 0 |
| gateway + web-net | 1 | 38493 | 10.5 | 55.6 | 4896.0 | 0 |
| difference at p50 | 1 | | +0.6 | | | |
| web-net alone | 8 | 67790 | 16.1 | 176.4 | 14064.1 | 0 |
| gateway + web-net | 8 | 93152 | 17.1 | 142.3 | 13022.4 | 0 |
| difference at p50 | 8 | | +1.0 | | | |

| connections | web-net alone mean ns | gateway + web-net mean ns | added, mean ns | gateway + web-net p50 below | gateway + web-net p99 below |
|---|---|---|---|---|---|
| 1 | 6422 | 5449 | -973 | 2.56µs | 12.288µs |
| 8 | 13134 | 15473 | +2339 | 3.072µs | 40.96µs |

Windows (CPU near 100%), web path:

| server | connections | requests/s | p50 us | p99 us | p99.9 us | failed |
|---|---|---|---|---|---|---|
| web-net alone | 1 | 20315 | 47.8 | 128.7 | 1247.0 | 0 |
| gateway + web-net | 1 | 31454 | 21.4 | 89.1 | 766.5 | 0 |
| difference at p50 | 1 | | -26.4 | | | |
| web-net alone | 8 | 117161 | 45.0 | 230.8 | 1996.5 | 0 |
| gateway + web-net | 8 | 120368 | 39.8 | 201.3 | 1684.3 | 0 |
| difference at p50 | 8 | | -5.2 | | | |

| connections | web-net alone mean ns | gateway + web-net mean ns | added, mean ns | gateway + web-net p50 below | gateway + web-net p99 below |
|---|---|---|---|---|---|
| 1 | 16696 | 14411 | -2285 | 5.12µs | 131.072µs |
| 8 | 17399 | 17015 | -384 | 4.096µs | 163.84µs |

Reading: on one connection on Linux, the platform adds 0.6 us at p50 on both paths, over serve-net alone and over web-net alone. Server-time means move by 1 to 2 us between runs, more than the difference; on Windows the gateway even measured faster than the bare servers in some rows. Every run ended with 0 passports in use and 0 request tickets held.

## Step 5: one themed page through the wasp binary

The release binary serving the site (web-net 0.9, Luminess 0.9.2, the default theme), measured from outside with `cargo run --release -p wasp --example hit -- 127.0.0.1:8090 /posts/the-passport 20000`: one keep-alive connection, one request at a time, request written to whole page read, after 1,000 warm-up requests. The page is the post page, 611 bytes; the home page (956 bytes, three posts) is the same within noise. Config: `keep_alive_requests = 1000000`, `door.exempt = ["127.0.0.1"]`; workers at their default (one per logical CPU).

| | min | p50 | p90 | p99 | mean | pages/s |
|---|---|---|---|---|---|---|
| Windows (host at 58% CPU), three runs | 9.9 to 10.3 us | 40.5 to 45.3 us | 70.2 to 71.1 us | 86.9 to 89.7 us | 44.0 to 46.9 us | 21,200 to 22,600 |
| WSL2 Linux (load average 12 to 20), best runs | 12.7 to 13.0 us | 15.3 to 16.2 us | 127.6 to 145.9 us | 362 to 790 us | 72.5 to 106.5 us | 9,400 to 13,800 |
| WSL2 Linux, typical runs | 52 to 67 us | 104 to 134 us | 136 to 264 us | 280 to 3,640 us | 125 to 260 us | 3,800 to 8,000 |

WSL runs fall into two regimes (about 15 us or about 125 us at p50) with the worker count at 4 or 32 alike: the guest's scheduling on a loaded host, not the code. The Windows host figures are the steadier ones.

Inside the binary, the gateway's server-time histogram (head complete to page handed to net-io, so web-net's site, url, route, authorization, the render, and the gateway's passport path):

| | requests | mean | p50 below |
|---|---|---|---|
| Windows | 84,001 | 13.1 us | 10.2 us |
| WSL2 Linux | 84,000 | 14.7 to 23.5 us | 16.4 to 20.5 us |

The render itself, measured alone (`cargo bench -p wasp --bench page`, Windows, fastest round): building the page view 44 ns (pointer clones and one title), rendering the post page 278 ns, the home page 644 ns. The template engine is under 1 us of the page; the rest of the server time is the web pipeline and the transport on a loaded machine. Server time inside the binary is several times what the in-process benchmark of step 4 measured for the same pipeline (p50 under 2.6 us on Linux); finding where the difference goes needs a quiet machine and a profiler, and is noted as a follow-up.

Against the design (WASP-NEXUS 2.1): render 2-20 us estimated, 0.3 to 0.6 us measured; total server time 5-30 us estimated, 13 to 23 us mean measured.

## Where the server time goes (2026-11-11)

Stage timing (`gateway.stage_timing = true`; off by default, one branch per mark when off) splits each request's server time. serve-net stamps a request's arrival with net-io's loop clock, which the reactor reads right after the OS wait returns; every gateway mark is a real-clock read. Stages: `wake` (loop clock to the gateway's `head` hook: the completion, the receive, serve-net's engine, http-net's parse), `hook` (bouncer request ticket, admission, checkpoints, dispatch), `passport` (take, trip, head copy, customs), `core` (checkpoint, authentication, assignment), `service` (web-net: site, url, route, authorization, handler, finish), `render` (inside `service`: the template engine), `respond` (cookie, passport back), `to_reply` (serve-net's encode, the last checkpoint). Driven like `examples/hit.rs`: one keep-alive connection, the post page, 20,000 requests.

**The binary and the process are the same.** Windows, reactor, 4 workers, means in ns (p50 below, p99 below):

| stage | in process (`cargo bench -p wasp --bench stages`) | the release binary (`hit`) |
|---|---|---|
| wake | 6,783 (1,536 / 65,536) | 13,897 (1,536 / 196,608) |
| hook | 487 (320 / 1,536) | 611 (448 / 1,536) |
| passport | 452 (320 / 1,280) | 538 (320 / 1,280) |
| core | 89 (112 / 320) | 119 (112 / 320) |
| service | 2,338 (1,536 / 6,144) | 2,728 (1,536 / 6,144) |
| render | 672 (512 / 2,048) | 834 (512 / 2,048) |
| respond | 228 (224 / 448) | 263 (224 / 512) |
| to_reply | 832 (640 / 2,560) | 1,128 (640 / 2,560) |
| total | 11,212 (5,120 / 81,920) | 19,287 (5,120 / 196,608) |

Every stage after `wake` has the same p50 in both. The step-5 "gap" came from comparing a Windows mean (13 us) with a Linux p50 (under 2.6 us): on Windows the step-4 benchmark also measured a 14 us mean for this path.

**The mean is the reactor turn on Windows.** `wake` is a few microseconds at p50 but carries a tail to 65-200 us (no blocking happens in that window, so the tail is the thread being preempted mid-turn on a loaded host, plus net-io's Windows receive path, which polls before each receive). On Linux the same stage is about 1 us:

| | wake mean | wake p50 below | total mean | total p50 below | client p50 |
|---|---|---|---|---|---|
| Windows, reactor | 6.8-17.6 us | 1.5-6.1 us | 11.2-23.8 us | 5.1-16.4 us | 22-58 us |
| WSL2 Linux, reactor (load average 54-63) | 1.0-2.7 us | 0.9-1.0 us | 3.7-9.9 us | 3.1-3.6 us | 11.2-12.0 us |

The gateway's own stages (hook, passport, core, respond) are 0.5 to 1.5 us of the mean on both systems; web-net is about 1.5 us plus 0.5-0.7 us of render.

**A/B, reactor against the blocking driver (`gateway.driver = "blocking"`), three alternating runs each, in process, 4 workers:**

| | server time mean | server time p99 below | wake mean | client p50 |
|---|---|---|---|---|
| Windows, reactor | 20.2, 20.1, 18.3 us | 98 us | 11.4-11.6 us | 61.4, 56.3, 36.6 us |
| Windows, blocking | 9.5, 9.1, 8.0 us | 20-41 us | 1.1-1.3 us | 58.3, 56.9, 40.7 us |
| Linux, reactor | 6.2, 9.9, 3.7 us | 14-20 us | 1.0-2.6 us | 12.0, 11.6, 11.7 us |
| Linux, blocking | 4.5, 5.5 us (a third run failed; see below) | 14 us | 0.6-1.0 us | 12.1, 11.2 us |

On Windows the blocking driver halves the server time and cuts its p99 by 60-80%; what a client on the same machine sees does not move, because there the loopback and the client side dominate. On Linux the two drivers are the same within noise. The default stays the reactor (it holds thousands of connections per worker, and production is Linux); `gateway.driver = "blocking"` is the option for a Windows development machine (`workers` then is the number of connections). The root of the Windows tail is in net-io's Windows reactor path and goes to net-io with these numbers.

One blocking run on each system ended with a non-200 reply mid-run before the benchmark reconnected on closed connections (now it does); with reconnects every run completed with 0 reconnects on Windows.

## Soak: ten minutes of steady traffic (2026-11-18)

The release `wasp` binary in WSL2 (Linux, rustc 1.99, load average 2.4 to 3.5 from other work), built `--no-default-features --features store-nex`: accounts, sessions and content in nex-db, the access log on, the theme folder watched (polled every second). `cargo run --release -p wasp --example soak -- 127.0.0.1:8092 8 250 600`: 8 keep-alive connections, 250 requests a second each, for 600 s. The traffic mixes cached guest pages (`/`, posts, `/about`), pages with a query (never cached), missing pages (404), the sign-in form (303 to set the pre-session cookie, since the client keeps no cookies) and `/health`. The theme's home template was touched every 60 s, so the theme reloaded and the guest cache was purged under load.

| | result |
|---|---|
| requests answered | 1,199,978 in 600 s (2,000 a second), none unanswered |
| statuses | 70% 2xx, 10% 3xx, 20% 4xx, as expected; 0 5xx, 0 unexpected |
| client latency per 30 s window | p50 112-127 us, p99 195-315 us, max 0.46-2.4 ms |
| server time (head to reply) | mean 16.7 us, p50 below 16.4 us, p99 below 41 us |
| resident memory | 130.3 MB at start, 134.9 MB after 30 s, 135.1 MB at the end |
| threads, open files | 46 and 146-154 throughout |
| theme reloads under load | 9 |
| load watch | never shed (no urgent line change before the stop) |
| access log | 1,199,981 lines, none dropped |
| stop | SIGINT, drained, exit 0 |

Memory settles in the first 30 seconds (the guest cache and the connections' buffers) and then holds: 256 KB over the remaining nine and a half minutes.
