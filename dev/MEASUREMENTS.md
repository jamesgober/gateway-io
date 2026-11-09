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
