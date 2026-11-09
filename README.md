# gateway-io

Proprietary. All rights reserved.

The platform's front door and the minimum of the core it hands requests to, as a walking skeleton that answers real requests.

| Crate | What it holds |
|---|---|
| `crates/wasp-core` | the passport and its stage types, the passport pool, customs, the gates seam (authentication, authorization), the service seam, the core, the hello stub |
| `crates/gateway-io` | serve-net wiring: the bouncer door and egress, admission on the passport pool, the request and response pipelines, the urgent line as the transport's control line, server-time metrics |
| `crates/wasp` | the process: boot phases 0 to 4, shutdown in reverse |

## The path of a request

```text
 net-io accept ─▶ bouncer door (address only, before any byte) ─▶ http-net parse (serve-net)
 head complete ─▶ admission: reserve a passport, or 503 with nothing taken
 Passport<Arrived> ─▶ customs head ─▶ Passport<Inspected> ─▶ checkpoint
 core: authenticate ─▶ Passport<Identified> ─▶ guest cache ─▶ the profile's service
 service: route ─▶ authorize ─▶ Passport<Cleared> ─▶ reply ─▶ Exit
 customs export ─▶ last checkpoint ─▶ encode ─▶ passport wiped and returned ─▶ net-io write (bouncer egress)
```

Skipping a gate does not compile: only the core can produce `Identified`, only `Access::authorize` can produce `Cleared`, and only `Cleared` can write a reply (see the `compile_fail` tests in `crates/wasp-core/src/passport.rs`).

## Run

```bash
cargo run -p wasp
```

It reads `wasp.conf` from the working directory (or the file named by `WASP_CONFIG`) and listens on `127.0.0.1:8080` by default. Ctrl+C (or SIGTERM) closes the door first, drains, then stops the core and the kernel.

```bash
curl -i http://127.0.0.1:8080/
```

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `gateway.listen` | `127.0.0.1:8080` | the listening address |
| `gateway.workers` | logical CPUs, at most 64 | reactor workers |
| `gateway.passports` | 256 | passports per worker (requests in flight) |
| `gateway.drain` | `10s` | the longest a drain may take |
| `gateway.head_timeout` | `10s` | the head deadline |
| `gateway.max_body` | 1 MiB | the largest buffered body |
| `gateway.keep_alive_requests` | 1000 | requests per connection |
| `door.ban` | none | addresses refused at the door from boot |
| `door.exempt` | none | addresses exempt from the door's budgets (local load tests) |
| `hello.slow_route` | false | `GET /slow?ms=N` waits, for drain tests |

## Check

```bash
cargo fmt --all --check
cargo +1.99 clippy --workspace --all-targets -- -D warnings
cargo +1.89 clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench -p wasp-core --bench passport
cargo bench -p gateway-io --bench request_path
```

Decisions are in `dev/DECISIONS.md`; measurements in `dev/MEASUREMENTS.md`.
