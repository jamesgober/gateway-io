# gateway-io

Proprietary. All rights reserved.

The platform's front door and the minimum of the core it hands requests to, as a walking skeleton that answers real requests.

| Crate | What it holds |
|---|---|
| `crates/wasp-core` | the passport and its stage types, the passport pool, customs, the gates seam (authentication, authorization), the service seam, the core, the hello stub |
| `crates/gateway-io` | serve-net wiring: the bouncer door and egress, admission on the passport pool, the request and response pipelines, the urgent line as the transport's control line, server-time metrics |
| `crates/wasp` | the process: boot phases 0 to 4, shutdown in reverse; the first web site (web-net, content in memory) |

## The path of a request

```text
 net-io accept ─▶ bouncer door (address only, before any byte) ─▶ http-net parse (serve-net)
 head complete ─▶ admission: reserve a passport, or 503 with nothing taken
 Passport<Arrived> ─▶ customs head ─▶ Passport<Inspected> ─▶ checkpoint
 core: authenticate ─▶ Passport<Identified> ─▶ guest cache ─▶ the profile's service
 passport service: route ─▶ authorize ─▶ Passport<Cleared> ─▶ reply ─▶ Exit
 web service (web-net): Handoff ─▶ site, url, route, 405 ─▶ authorize (core's access gate) ─▶ handler ─▶ serve-net's reply
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
curl -i http://127.0.0.1:8080/posts/hello-world
curl -i http://127.0.0.1:8080/account
```

The site: `/`, `/posts/:slug` and `/about` (from the in-memory content manifest), `/account` (signed in only: guests get a 303 to `/sign-in`), `/sign-in`, `/health`, `/theme/site.css`. Pages and error pages (404, 405, 500) are rendered by Luminess from `themes/default`; edit a template while the server runs and the next request has it (a template that does not compile is refused and the running theme stays).

```text
themes/default/pages/    base, home, post, page   (view: page)
themes/default/errors/   error, error/404         (view: error)
themes/default/static/   site.css                 (served under /theme/)
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
| `door.ban` | none | addresses refused at the door; changes apply on reload |
| `door.exempt` | none | addresses exempt from the door's budgets (local load tests); changes apply on reload |
| `site.service` | `web` | which service the site profile uses: `web` (web-net) or `hello` (the passport stub) |
| `site.base` | none | the folder the site lives under (`/blog`) |
| `site.hosts` | none | the site's hosts, canonical first; none answers localhost (development) |
| `site.assets` | none | a folder served under `/static` |
| `site.name` | `WASP` | the site's name, in every page title |
| `site.theme` | `themes/default` | the theme folder (`pages/`, `errors/`, `static/`) |
| `site.theme_poll` | `1s` | how often the theme folder is checked for changes (`0s` turns live reload off) |
| `hello.slow_route` | false | `GET /slow?ms=N` waits, for drain tests (with `site.service = "hello"`) |

A reload (SIGHUP on Linux, or `System::reload`) applies `door.ban`, `door.exempt` and `gateway.drain` at once; the listener and pool settings take effect at the next start. The door's decisions (bans added and lifted, banned sources refused, egress blocked) are written to the log.

## Check

```bash
cargo fmt --all --check
cargo +1.99 clippy --workspace --all-targets -- -D warnings
cargo +1.89 clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench -p wasp-core --bench passport
cargo bench -p gateway-io --bench request_path
cargo bench -p wasp --bench page
cargo run --release -p wasp --example hit -- 127.0.0.1:8080 /posts/the-passport 20000
```

Decisions are in `dev/DECISIONS.md`; measurements in `dev/MEASUREMENTS.md`.
