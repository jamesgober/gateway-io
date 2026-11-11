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
