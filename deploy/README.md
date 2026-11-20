# Deploying behind Apache with Phusion Passenger (cPanel)

The site runs as one process on a loopback port. Apache terminates TLS and passes requests through Passenger; the process trusts only that local front end for client addresses.

For the steps alone, in order, see [CPANEL.md](CPANEL.md).

## Build

A static Linux binary, so the host's C library does not matter:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked --target x86_64-unknown-linux-musl -p wasp --no-default-features --features store-nex
```

`--no-default-features --features store-nex` builds the site on nex-db alone (accounts with `auth.store = "nex"`, content with `content.store = "nex"`) and with no C dependency, so it needs no C toolchain. The default build has the in-memory gatekeeper instead, whose crypto library needs a C compiler for musl (`musl-tools`).

Then pack it with the theme, the start shim, these notes and the example configuration:

```bash
deploy/bundle.sh target/x86_64-unknown-linux-musl/release/wasp "$(git rev-parse --short=7 HEAD)" dist
```

That writes `dist/wasp-<commit>-x86_64-linux-musl.tar.gz` and its `.sha256`. CI does the same on every push to `main` (the `musl` job) and keeps both as the artifact `wasp-bundle-x86_64-linux-musl`.

## Upload

The bundle extracts to one folder, which becomes the application's folder (outside `public_html`):

```text
wasp                 the binary
themes/default       the theme (pages/, errors/, static/)
app.js               the start shim
wasp.conf.example    the configuration to copy to wasp.conf
DEPLOY.md            these notes
CPANEL.md            the steps, in order
service/             a systemd unit and a launchd job, for a server you run yourself
```

`wasp.conf.example` is the configuration for a first site: nex-db for accounts and content in `data/nex`, two workers, and warnings only in the log. Copy it to `wasp.conf` and set `site.hosts` and `auth.admin`. A key wasp does not know stops it at boot, and with `PORT` set an empty `site.hosts` does too.

Set `WASP_ADMIN_PASSWORD` in the application's environment, never in the file.

## Start

cPanel runs the site as a Node app ("Setup Node.js App", or "Application Manager" on some hosts), with `app.js` as the startup file and **Production** mode. The shim:

- starts `./wasp` on a free loopback port with `PORT` set, so wasp listens on `127.0.0.1:$PORT` and trusts only loopback for `X-Forwarded-For` and `X-Forwarded-Proto`;
- starts listening itself only once wasp accepts connections, so the request that wakes the app is answered by the site;
- passes every request through, adding the client to `X-Forwarded-For`;
- stops wasp cleanly when Passenger stops the app (after its idle time, on **Restart**, on `touch tmp/restart.txt`), and waits for it to exit.

wasp also stops by itself when its standard input closes (when it is a pipe) or its parent process goes away, so it is never left running on its own. A start that overlaps the previous process's stop waits up to 15 s for the database to be free.

On a server you manage yourself, Passenger can run wasp without the shim (a generic app whose start command is `./wasp`); Passenger closes its standard input to stop it. Without Passenger, let the service manager run it: `service/wasp.service` for systemd, `service/com.example.wasp.plist` for launchd (see "Start at boot" in the main README).

Turn on **Force HTTPS Redirect** for the domain: signing in needs https, because the browser does not keep a `Secure` cookie on a plain http page.

Requests must come through Apache, which sends `X-Forwarded-For`. A request straight to the local port names no client and is refused (`bouncer.door.proxy_hop` in the log), so point health checks at the public address.

## Content

Sign in with the boot account (`auth.admin`) and open `/admin` to write and edit posts and pages in the browser; with `content.store = "nex"` they are kept in the same database as the accounts.

The content store allows one process at a time. To import many posts and pages from files instead, stop the app, then:

```bash
WASP_CONFIG=wasp.conf ./wasp import ./content
```

and start it again. See the main README for the file format.

## Check

```bash
curl -sI https://example.com/health
```

The log (standard error, kept by Passenger in a file it does not rotate) shows warnings and errors with the example configuration: `refused to load` with the reason when wasp does not start, a `boot notice` for anything to fix, a line when a store stops or starts serving again, and the door's refusals. With `gateway.access_log = true` it also has one `access` line per request (method, path without the query, status, bytes, server time in microseconds, client address); leave that on only while troubleshooting.

When the disk or the account's quota fills, nex-db stops taking writes and stays read-only until the process restarts: free some space, then restart the app.
