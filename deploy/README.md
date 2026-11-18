# Deploying behind Apache with Phusion Passenger (cPanel)

The site runs as one process on a loopback port. Apache terminates TLS and passes requests through Passenger; the process trusts only that local front end for client addresses.

## Build

A static Linux binary, so the host's C library does not matter:

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install musl-tools          # a C compiler for musl (the crypto library needs one)
CC_x86_64_unknown_linux_musl=musl-gcc   cargo build --release --locked --target x86_64-unknown-linux-musl -p wasp
```

CI builds the same binary (the `musl` job) and keeps it as an artifact.

The binary is `target/x86_64-unknown-linux-musl/release/wasp`.

## Upload

Into the application's folder:

```text
wasp            the binary (chmod 755)
wasp.conf       the configuration below
themes/default  the theme (pages/, errors/, static/)
app.js          deploy/passenger/app.js, only when the host offers Node apps only
```

```toml
[site]
hosts = ["example.com", "www.example.com"]
theme = "themes/default"

[content]
store = "bison"
path = "data/content.bison"

[auth]
admin = "you@example.com"
secret = "data/gate.key"
```

Set `WASP_ADMIN_PASSWORD` in the application's environment, never in the file.

## Start

- **Passenger runs any command** (a generic app, `passenger_app_start_command`): start `./wasp` directly. Passenger sets `PORT`; wasp then listens on `127.0.0.1:$PORT` and trusts only loopback for `X-Forwarded-For` and `X-Forwarded-Proto`.
- **Node apps only** (cPanel's "Setup Node.js App"): set the startup file to `app.js`. The shim starts `./wasp` on a free loopback port, passes requests through, and stops it when Passenger stops the app.

Restart from the application setup page (or `touch tmp/restart.txt` where Passenger watches it).

Requests must come through Apache, which sends `X-Forwarded-For`. A request straight to the local port names no client and is refused (`bouncer.door.proxy_hop` in the log), so point health checks at the public address.

## Content

The content store allows one process at a time. To import posts and pages, stop the app, then:

```bash
WASP_CONFIG=wasp.conf ./wasp import ./content
```

and start it again. See the main README for the file format.

## Check

```bash
curl -sI https://example.com/health
```

The log (standard error, captured by Passenger) shows `ready` at boot, a `boot notice` for anything to fix (an empty `site.hosts` behind `PORT`, bytes discarded from the store), and the door's decisions.
