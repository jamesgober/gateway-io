# gateway-io

The front door of WASP, my platform for web applications and services, with the part of its core that requests are handed to and the binary that boots both. It is a working skeleton: it answers real requests, signs people in and out, renders themed pages, and keeps content across restarts.

**Source-available, not open source.** The code is public so it can be read. It is not licensed for use, copying, or distribution; see [LICENSE](LICENSE).

| Crate | What it holds |
|---|---|
| `crates/wasp-core` | the passport and its stage types, the passport pool, customs, the gates seam (authentication, authorization), the service seam, the core, the hello stub |
| `crates/gateway-io` | serve-net wiring: the bouncer door and egress, admission on the passport pool, the request and response pipelines, the urgent line as the transport's control line, server-time metrics; the gatekeeper adapter (feature `gatekeeper`) |
| `crates/wasp` | the process: boot phases 0 to 4, shutdown in reverse; the first web site (web-net, Luminess themes, a content store), behind the gatekeeper |

## The path of a request

```text
 net-io accept ─▶ bouncer door (address only, before any byte) ─▶ http-net parse (serve-net)
 head complete ─▶ admission: reserve a passport, or 503 with nothing taken
 Passport<Arrived> ─▶ customs head ─▶ Passport<Inspected> ─▶ checkpoint
 core: authenticate (gatekeeper) ─▶ Passport<Identified> ─▶ guest cache ─▶ the profile's service
 passport service: route ─▶ authorize ─▶ Passport<Cleared> ─▶ reply ─▶ Exit
 web service (web-net): Handoff ─▶ site, url, route, 405 ─▶ authorize (gatekeeper) ─▶ handler ─▶ serve-net's reply
 customs export ─▶ last checkpoint ─▶ encode ─▶ passport wiped and returned ─▶ net-io write (bouncer egress)
```

For passport services, skipping a gate does not compile: only the core can produce `Identified`, only the core's `Access` (a service cannot make its own) can produce `Cleared`, and only `Cleared` can write a reply (see the `compile_fail` tests in `crates/wasp-core/src/passport.rs`). Web services answer on serve-net's own types after the core identified the request: there the per-route guarantee is web-net's (a handler's context exists only after its gate authorized the route), not the passport's.

## Build

Rust 1.89 or newer. On Windows, set `AWS_LC_SYS_PREBUILT_NASM=1` so the crypto dependency builds without a NASM install.

```bash
cargo build --release -p wasp
```

## Run

```bash
cargo run -p wasp
```

It reads `wasp.conf` from the working directory (or the file named by `WASP_CONFIG`) and listens on `127.0.0.1:8080` by default. Ctrl+C (or SIGTERM) closes the door first, drains, then stops the core and the kernel.

To sign in, name a boot account and give its password in the environment (never in the configuration):

```toml
[auth]
admin = "admin@example.com"
```

```bash
WASP_ADMIN_PASSWORD='a long password' cargo run -p wasp
```

Accounts and sessions are in memory: a restart signs everyone out. The gates' master secret is `<data folder>/gate.key`, made on the first run.

The stores are cargo features of `wasp`: `gatekeeper` (on by default) and `store-nex` (off). A site on nex-db alone, with durable accounts and no C dependency:

```bash
cargo run -p wasp --no-default-features --features store-nex
```

A build asked for a store it was built without refuses to boot and names the feature.

```bash
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/posts/hello-world
curl -i http://127.0.0.1:8080/account
```

The site: `/`, `/posts/:slug`, `/about` and every other page at `/:slug` (from the content store: in memory by default, or a bison-db file that survives restarts), `/account` (signed in only: guests get a 303 to `/sign-in?next=/account`), `/sign-in` (the form, and `POST` to sign in), `/sign-out` (`POST`), `/admin` (the content editor, below), `/health`, `/ready` (503 while a store cannot serve), `/theme/site.css`. Pages and error pages (404, 405, 500) are rendered by Luminess from `themes/default`; edit a template while the server runs and the next request has it (a template that does not compile is refused and the running theme stays).

## Edit content

On a site signed in through nex-db (`auth.store = "nex"`), an account with the `editor` role writes the content in the browser: `/admin` lists every post and page, with links to edit each one and to write a new post or page. A save is checked and escaped like an import, and a refused save shows the form again with what was typed and the reason. Renaming an entry (changing its slug) moves it; a slug another entry has is refused. The boot account (`auth.admin`) is given the `member` and `editor` roles. The editor's pages are never cached, and every form carries a CSRF token.

Guests' copies of the content pages (`/`, posts and pages) are kept in memory and answered before the site runs, for up to 60 seconds, and every save, rename or removal, and every theme reload, drops them at once. Signed-in visitors, queries and pages with a form are always served fresh.

Saves go through the content store, so use a durable one (`content.store = "nex"` or `"bison"`) or the edits end with the process.

## Import content

With a durable store (`content.store = "bison"`), posts and pages come in from files. Stop the server first: the store allows one process at a time.

```text
<folder>/posts/<slug>.md     title, date (YYYY-MM-DD), summary; a blank line; the body
<folder>/pages/<slug>.md     title, summary; a blank line; the body
```

```bash
cargo run -p wasp -- import ./content
```

Each file is validated and escaped like any save (the body is plain text, blank lines between paragraphs); a file that does not pass is reported and skipped, and a slug already in the store is replaced.

```text
themes/default/pages/    base, home, post, page, sign-in, account, admin, edit   (view: page)
themes/default/errors/   error, error/404         (view: error)
themes/default/static/   site.css                 (served under /theme/)
```

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `gateway.listen` | `127.0.0.1:8080` | the listening address |
| `gateway.workers` | logical CPUs, at most 64 | reactor workers (1 to 256); with `blocking`, the connections served at once |
| `gateway.passports` | 256 | passports per worker (requests in flight) |
| `gateway.reserve` | an eighth of `gateway.passports` | passports per worker held back for health checks, the content editor, and sign-in: browsing cannot take them, so a flood of page views never locks those out |
| `gateway.shed_passports` | 90 | the gateway sheds browsing on its own when this share of the passports (percent) is in use; 0 turns it off |
| `gateway.shed_slow` | `1s` | the gateway sheds browsing on its own when browsing replies take this long on average; `0s` turns it off |
| `gateway.shed_check` | `250ms` | how often the load is read (10 ms to 60 s) |
| `gateway.drain` | `10s` | the longest a drain may take |
| `gateway.head_timeout` | `10s` | the head deadline |
| `gateway.max_body` | 1 MiB | the largest buffered body (at most 64 MiB) |
| `gateway.keep_alive_requests` | 1000 | requests per connection |
| `gateway.driver` | `reactor` | net-io's driver; `blocking` (one thread per connection: `workers` connections, plus a few threads that answer the ones over the cap) halves server time on a Windows development machine |
| `gateway.stage_timing` | false | record where each request's server time goes; logged per stage when the gateway stops |
| `gateway.ingress` | `direct` | `direct`, or `proxy` behind a reverse proxy: the client is the address in `X-Forwarded-For`, believed only from `gateway.trusted_proxies`, and the door bans and charges that client; a trusted proxy that sends no header is refused |
| `gateway.trusted_proxies` | none | the proxies' addresses or blocks (`127.0.0.1`, `10.0.0.0/8`); required with `ingress = "proxy"` |
| `gateway.forwarded_proto` | true | with `ingress = "proxy"`, take the scheme from `X-Forwarded-Proto` (an https proxy in front makes the site https) |
| `door.ban` | none | addresses refused at the door; changes apply on reload |
| `door.exempt` | none | addresses exempt from the door's budgets (local load tests); changes apply on reload |
| `site.service` | `web` | which service the site profile uses: `web` (web-net) or `hello` (the passport stub) |
| `site.base` | none | the folder the site lives under (`/blog`: a leading `/`, no trailing `/`) |
| `site.hosts` | none | the site's hosts, canonical first; none answers only the development hosts (`localhost`, `127.0.0.1`, `[::1]`) |
| `site.assets` | none | a folder served under `/static` |
| `site.name` | `WASP` | the site's name, in every page title |
| `site.theme` | `themes/default` | the theme folder (`pages/`, `errors/`, `static/`) |
| `site.theme_poll` | `1s` | how often the theme folder is checked for changes (`0s` turns live reload off) |
| `content.store` | `memory` | where content is kept: `memory` (lost at exit), `bison` (a bison-db file), or `nex` (a nex-db database, feature `store-nex`: one entity per entry, published at its route); the durable stores allow one process at a time (a second instance refuses to boot); an empty store is given the sample content |
| `content.recovery` | `strict` | a bison-db file damaged before its end refuses to boot and is left as it was; after backing it up, start once with `salvage` to keep every record that still verifies (bison-db keeps a copy as `<path>.damaged`) |
| `content.path` | `<data folder>/content.bison` | the bison-db file |
| `auth.store` | `gatekeeper` (`nex` in a build without it) | the site's accounts and sessions: `gatekeeper` (feature `gatekeeper`, on by default; in memory: a restart signs everyone out) or `nex` (feature `store-nex`; nex-db: durable) |
| `nex.path` | `<data folder>/nex` | the nex-db database, shared by `auth.store = "nex"` and `content.store = "nex"`; one process at a time |
| `auth.admin` | none | an account made at boot (given the `member` and `editor` roles with nex-db); its password from `WASP_ADMIN_PASSWORD` |
| `auth.secret` | `<data folder>/gate.key` | the gates' 32-byte master secret, made on the first run (owner-only on Unix) |
| `auth.origin` | `https://<first site.hosts entry>` | the site's origin, for the CSRF origin check (none on a development site: the token decides) |
| `jobs.threads` | 2 | threads of the in-process job runner |
| `jobs.queue` | 1024 | jobs that may wait; a full queue refuses new jobs |
| `hello.slow_route` | false | `GET /slow?ms=N` waits, for drain tests (with `site.service = "hello"`; refused unless `gateway.listen` is a loopback address) |

Under heavy load the gateway sheds on its own: when replies to page views get slow or the passports run short, page views are answered with 503 and a short `Retry-After`, while health checks, the content editor and sign-in are still served. It stops by itself once the load has passed (about two seconds of calm), and it never lowers a shed someone else set.

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
cargo bench -p wasp --bench stages -- 4 20000 reactor
cargo run --release -p wasp --example hit -- 127.0.0.1:8080 /posts/the-passport 20000
```

Decisions are in `dev/DECISIONS.md`; measurements in `dev/MEASUREMENTS.md`.

## License

Copyright (c) 2026 James Gober. All rights reserved. See [LICENSE](LICENSE).
