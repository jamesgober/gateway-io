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

Two-step sign-in (TOTP) for nex-db accounts is the `mfa` feature. It builds the same C crypto backend as the default gatekeeper, so the static musl build (`--no-default-features --features store-nex`) leaves it out:

```bash
cargo build --release -p wasp --features store-nex,mfa
```

## Run

```bash
cargo run -p wasp
```

It reads `wasp.conf` from the working directory (or the file named by `WASP_CONFIG`) and listens on `127.0.0.1:8080` by default. Run as root or administrator, it reads only the file `WASP_CONFIG` names: a working directory is easy for someone else to plant a file in. With no file found it starts on the defaults and says so in a warning. Ctrl+C (or SIGTERM) closes the door first, drains, then stops the core and the kernel.

To sign in, name a boot account and give its password in the environment (never in the configuration):

```toml
[auth]
admin = "admin@example.com"
```

```bash
WASP_ADMIN_PASSWORD='a long password' cargo run -p wasp
```

Accounts and sessions are in memory: a restart signs everyone out, and the boot account is made again on every start, so `WASP_ADMIN_PASSWORD` is needed each time. The gates' master secret is `<data folder>/gate.key`, made on the first run.

With nex-db (below) accounts are kept: `WASP_ADMIN_PASSWORD` is needed only for the start that makes the boot account. Once it exists, a start without the variable boots as usual; a start that names an account not made yet refuses with that reason.

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

### Upgrading an install

A start can now refuse a folder that other users of the machine can read, such as a log folder an older build made at mode 0755. The message names the folder and the fix, for example `run: chmod 700 /home/you/.local/share/wasp/logs`. Run it (or delete the folder so it is made again, private) and start again.

The configuration file is checked the same way: one that other accounts can change is refused. On Windows a file on a drive that keeps no permissions (FAT or exFAT, often a second drive or a USB disk) still loads, with a warning to move it to an NTFS drive.

A custom admin theme (`admin.custom_theme`) now needs five more pages: `security`, `two-factor`, `codes`, `code` and `accounts`. Copy them from `crates/wasp/admin/pages/`.

A stop signal that was already ignored when wasp started stays ignored: SIGHUP under `nohup`, and SIGINT for a job a shell script started in the background with `&`. A script that stops wasp with `kill -INT` should send SIGTERM instead.

### Start at boot

On a server you run yourself, the service manager starts wasp at boot, restarts it after a crash, and stops it cleanly. `deploy/` has a file for each. On a cPanel host, Passenger starts it instead (see [deploy/CPANEL.md](deploy/CPANEL.md)).

**Linux (systemd).** [deploy/systemd/wasp.service](deploy/systemd/wasp.service) runs wasp as its own user, with the binary and theme in `/opt/wasp`, the configuration in `/etc/wasp/wasp.conf` and the data in `/var/lib/wasp`. Its standard error goes to the journal.

```bash
sudo useradd --system --home-dir /var/lib/wasp --shell /usr/sbin/nologin wasp
sudo mkdir -p /opt/wasp /etc/wasp
sudo cp wasp /opt/wasp/ && sudo cp -R themes /opt/wasp/
sudo cp wasp.conf.example /etc/wasp/wasp.conf      # then edit it: see below
sudo chown root:wasp /etc/wasp/wasp.conf && sudo chmod 640 /etc/wasp/wasp.conf
sudo cp deploy/systemd/wasp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wasp
```

In `/etc/wasp/wasp.conf`, name the folders in full: `theme = "/opt/wasp/themes/default"`, `nex.path = "/var/lib/wasp/nex"`, and `log.file = false` (the journal keeps the log). For the first start only, put `WASP_ADMIN_PASSWORD=...` in `/etc/wasp/wasp.env` (owned by root, mode 600), and delete the file once the boot account exists.

wasp tells systemd when it is ready (`Type=notify`), so `systemctl start` returns once the site serves. Then:
- `systemctl reload wasp` sends SIGHUP, which reloads the configuration;
- `systemctl stop wasp` sends SIGTERM, which drains, then stops;
- `journalctl -u wasp` shows the log.

A crash restarts it after two seconds. A configuration it refuses (exit 78) or a folder others can read (exit 77) doesn't restart, since a restart can't fix either: `journalctl -u wasp` says why. systemd makes every folder wasp uses, private to the service. The unit also keeps wasp away from the rest of the system (read-only system folders, no home folders, no devices, no new privileges). To listen on port 80 or 443 without root, uncomment the two capability lines in the unit.

**macOS (launchd).** [deploy/launchd/com.example.wasp.plist](deploy/launchd/com.example.wasp.plist) runs `/usr/local/wasp/wasp` with `WASP_CONFIG=/usr/local/wasp/wasp.conf`. Change the label to your own reverse domain name, and the paths to where wasp is.
- **As a launch agent** (starts when you log in, runs as you), copy it to `~/Library/LaunchAgents/` and run `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.wasp.plist`.
- **As a launch daemon** (starts at boot, no login), add a `UserName` key with the account to run as, copy it to `/Library/LaunchDaemons/` (owned by root, mode 644), and run `sudo launchctl bootstrap system /Library/LaunchDaemons/com.example.wasp.plist`.

First make its log folder, private to the account: `mkdir -m 700 -p /usr/local/var/log/wasp`. launchd starts it again after a crash or a failed start (every 30 seconds while it keeps failing), and not after a clean stop.

## Edit content

On a site signed in through nex-db (`auth.store = "nex"`), an account with the `editor` role writes the content in the browser: `/admin` lists every post and page, with links to edit each one and to write a new post or page. A save is checked and escaped like an import, and a refused save shows the form again with what was typed and the reason. Renaming an entry (changing its slug) moves it; a slug another entry has is refused. The boot account (`auth.admin`) is given the `member`, `editor` and `admin` roles at every start. The editor's pages are never cached, and every form carries a CSRF token.

Each entry also has optional search and sharing fields, under "Search and sharing" in the editor:

| Field | Left empty |
|---|---|
| Search title (`seo_title`) | the title |
| Meta description (`description`) | the summary |
| Canonical address (`canonical`): a site path or an `https://` address | the entry's own address |
| Robots (`robots`): `noindex`, `nofollow`, both, or their `index`/`follow` opposites | none (search engines index and follow) |
| Sharing title (`og_title`) and description (`og_description`) | the search title and the meta description |
| Sharing image (`og_image`): a site path or an `https://` address | none |
| Card (`twitter_card`): `summary` or `summary_large_image` | the large card with an image, else `summary` |

A site path is under the site's base, and becomes absolute (`https://` and the first of `site.hosts`) in the page. The search title, the two descriptions and the sharing title are the text a reader sees, so they will be translated with the title and summary when translations arrive; the others stay the same in every language.

### Custom fields

A site can give posts and pages fields of its own, declared in the configuration:

```toml
[content.fields.post.author]
type = "text"
label = "Author"
required = true
help = "As it should appear under the title"
order = 1

[content.fields.post.size]
type = "select"
options = ["small", "large"]
```

| Key | Default | Meaning |
|---|---|---|
| `type` | required | `text` (one line), `textarea`, `url`, `number`, `bool`, `date` (`YYYY-MM-DD`), `select`, or `media` (a site path or an `https://` address, for now) |
| `label` | the name | what the editor shows |
| `required` | false | a save without a value is refused (a `bool` must be checked) |
| `help` | none | a line under the field in the editor |
| `options` | none | a `select`'s choices (needed there, refused elsewhere) |
| `order` | 0 | where the editor shows it, then by name |

A name is lower case letters, digits and `_`, starting with a letter. Each kind (`post`, `page`) takes up to 32 fields. Every save and every load checks each value against its type, as for the built-in fields. A required field is checked only at save, so adding one to a site with content doesn't stop the boot. Declarations are read at start.

The editor shows the fields of the entry's kind. A theme reads them in `page.entry.fields`, each with `name`, `label`, `kind` and `value`, in the declared order. The default theme lists the filled ones under the body. Stores keep them as `f_<name>`, and an older record reads them as empty.

## Accounts

With nex-db, every signed-in account has `/account/security`:

- **Password.** Change it with the current one. Every other session ends.
- **Sign out everywhere.** Ends every session of the account, this one too, and forgets its remembered devices.
- **Two-step sign-in.** Turn it on with an authenticator app and your password. You get the key to type in and its setup link, then a code to confirm, then recovery codes shown once. With it on, signing in asks for a code, or a recovery code, on a second page. "Don't ask on this device" skips the code for `auth.mfa.remember_device`. A password change, turning two-step off, signing out everywhere and "Forget remembered devices" undo that.

An account with the `admin` role has `/admin/accounts`. It lists every account with its roles and standing, and disables or removes one, or enables one that is disabled or locked out (a ban stays). Disabling ends its sessions. Neither your own account nor the boot account can be changed there.

Every one of these writes an `audit` line to the log: who, what, and which account.

These pages come from the admin theme, so a site theme can't change them, and they are never cached.

### Sign-in settings

Every key here is read again on a reload. A value under its floor stops the boot, or refuses the reload (the running settings stay).

| Key | Default | Meaning |
|---|---|---|
| `auth.password.min_length` | 12 | the shortest password (at least 8) |
| `auth.password.max_length` | 128 | the longest password (the minimum to 1024) |
| `auth.password.require_upper`, `require_lower`, `require_digit`, `require_symbol` | false | a password must hold that kind of character |
| `auth.mfa.enabled` | false | two-step sign-in is offered (needs the `mfa` feature) |
| `auth.mfa.mode` | `optional` | `off` (not offered), `optional`, or `required` (set up at the next sign-in; needs `enabled`) |
| `auth.mfa.methods` | `["totp"]` | the second steps; `totp` is the only one |
| `auth.mfa.remember_device` | `30d` | how long "don't ask on this device" lasts; `0` never offers it (at most `400d`) |
| `auth.mfa.every_login` | false | a code at every sign-in, even on a remembered device |
| `auth.mfa.recovery_codes` | 10 | recovery codes shown when two-step sign-in is turned on (0 to 10) |
| `auth.session.idle` | `7d` | a session ends after this long unused; `0` for no idle limit (else at least `1m`) |
| `auth.session.absolute` | `30d` | a session ends this long after sign-in (`1m` to `400d`) |
| `auth.session.max_concurrent` | 0 | the most sessions an account holds; a new sign-in past it ends the oldest (0: no cap) |
| `auth.session.recheck` | `1m` | how often a session's roles and standing are read again (`1s` to `1h`) |
| `auth.lockout.attempts` | 10 | wrong passwords or codes for one account within `window` that lock it (1 to 20; never off) |
| `auth.lockout.window` | `15m` | the window `attempts` are counted in (at least `1m`) |
| `auth.lockout.duration` | `15m` | how long a lockout lasts (at least `1m`) |
| `auth.lockout.address_attempts` | 10 | sign-in attempts one address may make within `address_window` |
| `auth.lockout.address_window` | `10m` | the window `address_attempts` are counted in |

A role can have its own password, two-step and session keys (all but `recheck`) in `[auth.role.<role>]`, for `member`, `editor` and `admin`. An account with several roles gets the strictest value of each:

```toml
[auth.mfa]
enabled = true

[auth.role.admin.mfa]
mode = "required"
remember_device = "0"

[auth.role.admin.session]
idle = "1h"
```

Times take `s`, `m`, `h` or `d`. With `auth.store = "gatekeeper"` these tables stop the boot: they are for nex-db accounts.

Guests' copies of the content pages (`/`, posts and pages) are kept in memory and answered before the site runs, for up to 60 seconds, and every save, rename or removal, and every theme reload, drops them at once. Signed-in visitors, queries and pages with a form are always served fresh.

Saves go through the content store, so use a durable one (`content.store = "nex"` or `"bison"`) or the edits end with the process.

## Import content

With a durable store (`content.store = "bison"`), posts and pages come in from files. Stop the server first: the store allows one process at a time.

```text
<folder>/posts/<slug>.md     title, date (YYYY-MM-DD), summary; a blank line; the body
<folder>/pages/<slug>.md     title, summary; a blank line; the body
```

The search and sharing fields are header lines too, by the names above (`description: One line for search results.`), and so are the custom fields, with `f_` in front of the name (`f_author: Ann`).

```bash
cargo run -p wasp -- import ./content
```

Each file is validated and escaped like any save (the body is plain text, blank lines between paragraphs); a file that does not pass is reported and skipped, and a slug already in the store is replaced.

```text
themes/default/pages/    base, home, post, page, sign-in, account   (view: page)
themes/default/errors/   error, error/404         (view: error)
themes/default/static/   site.css, favicon.svg    (served under /theme/)
```

Every page view has `page.head`, with the search and sharing fields already filled in from their fallbacks: `title`, `description`, `canonical`, `robots`, `og_type` (`article` for a post), `og_title`, `og_description`, `og_image` and `twitter_card`. A theme writes each one into its `<head>` as it is, and leaves out the empty ones. The default theme's `base.html` shows how.

The admin pages (`/admin` and below) have their own theme, built into the binary, so they work whatever the site theme is, and a site theme can neither restyle them nor put anything into them. They are sent with a stricter content security policy than the site's (nothing inline, nothing from another origin, never framed). An install that wants its own admin theme sets `[admin] custom_theme = true` and names a folder in `[admin] theme`, shaped like the built-in one (`crates/wasp/admin/`: `pages/` with `base`, `list`, `edit`, and `static/`, served under `/admin/static/`). The sign-in form and the account page stay with the site theme: every visitor sees them. The security pages (password, two-step sign-in, the second sign-in step) use the admin theme.

## Error pages

A theme's error pages are `errors/error.html` and `errors/error/<status>.html` (`errors/error/404.html`). An error page reads `error`:
- `status`, `title`, `message` and `reference` (what a visitor quotes when they report it);
- `base`;
- `code`, the application's error code (`admin.unknown`, `content.unavailable`).

`[errors]` sets, per status, the message a visitor reads and the template that shows it:

```toml
[errors.404]
message = "Nothing lives at this address."
template = "error/gone"          # themes/<theme>/errors/error/gone.html

[errors.5xx]
message = "Something broke on our side. Please try again in a minute."
```

A key is a status from 400 to 599, or `4xx` or `5xx`, and a status's own entry wins over its class. A key for any other code, an unknown setting, or a template the theme doesn't have stops the boot, or refuses the reload. The table is read again on every reload.

A request under `/admin` always gets the admin theme's error page (built in, or `errors/` in a custom admin theme), never the site theme's.

A handler sends any status from 400 to 599 with its own message in one call. The message replaces the configured one for that request, and the code and message go to the log:

```rust
return Err(site::fail(cx, 410, "content.gone", "This post was taken down."));
```

A status outside 400 to 599 there is a 500 with the code `site.bad_status`.

## Configuration

A key wasp does not know, in any section, refuses the boot with its name, so a typo never leaves a setting at its default.

| Key | Default | Meaning |
|---|---|---|
| `gateway.listen` | `127.0.0.1:8080` | the listening address |
| `gateway.workers` | logical CPUs, at most 64 (at most 4 when `PORT` is set) | reactor workers (1 to 256); with `blocking`, the connections served at once |
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
| `gateway.access_log` | false | one `access` line per request in the log: method, path (never the query), status, how it ended, bytes, server time, client; written off the worker, and dropped (and counted) rather than waited for when the log falls behind |
| `gateway.stage_timing` | false | record where each request's server time goes; logged per stage when the gateway stops |
| `gateway.ingress` | `direct` | `direct`, or `proxy` behind a reverse proxy: the client is the address in `X-Forwarded-For`, believed only from `gateway.trusted_proxies`, and the door bans and charges that client; a trusted proxy that sends no header is refused |
| `gateway.trusted_proxies` | none | the proxies' addresses or blocks (`127.0.0.1`, `10.0.0.0/8`); required with `ingress = "proxy"` |
| `gateway.forwarded_proto` | true | with `ingress = "proxy"`, take the scheme from `X-Forwarded-Proto` (an https proxy in front makes the site https) |
| `door.ban` | none | addresses refused at the door; changes apply on reload |
| `door.exempt` | none | addresses exempt from the door's budgets (local load tests); changes apply on reload |
| `site.service` | `web` | which service the site profile uses: `web` (web-net) or `hello` (the passport stub) |
| `site.base` | none | the folder the site lives under (`/blog`: a leading `/`, no trailing `/`) |
| `site.hosts` | none | the site's hosts, canonical first; none answers only the development hosts (`localhost`, `127.0.0.1`, `[::1]`), and is refused at boot when `PORT` is set |
| `site.development` | `false` | allows an empty `site.hosts` when `PORT` is set (a local run behind a front end) |
| `site.assets` | none | a folder served under `/static` |
| `site.name` | `WASP` | the site's name, in every page title |
| `site.theme` | `themes/default` | the theme folder (`pages/`, `errors/`, `static/`) |
| `site.theme_poll` | `1s` | how often the theme folder is checked for changes (`0s` turns live reload off) |
| `admin.theme` | `builtin` | the admin pages' theme: `builtin`, or a folder (`pages/`, `static/`) when `admin.custom_theme` allows it |
| `admin.custom_theme` | false | whether `admin.theme` may name a folder; without it a folder refuses the boot |
| `content.store` | `memory` | where content is kept: `memory` (lost at exit), `bison` (a bison-db file), or `nex` (a nex-db database, feature `store-nex`: one entity per entry, published at its route); the durable stores allow one process at a time (a second instance refuses to boot); an empty store is given the sample content |
| `content.recovery` | `strict` | a bison-db file damaged before its end refuses to boot and is left as it was; after backing it up, start once with `salvage` to keep every record that still verifies (bison-db keeps a copy as `<path>.damaged`) |
| `content.path` | `<data folder>/content.bison` | the bison-db file |
| `auth.store` | `gatekeeper` (`nex` in a build without it) | the site's accounts and sessions: `gatekeeper` (feature `gatekeeper`, on by default; in memory: a restart signs everyone out) or `nex` (feature `store-nex`; nex-db: durable) |
| `nex.path` | `<data folder>/nex` | the nex-db database, shared by `auth.store = "nex"` and `content.store = "nex"`; one process at a time |
| `nex.lock_wait` | `15s` | how long a boot waits for another process (a restart overlapping the old one's stop) to let go of the database; it warns when it starts waiting and names the process when it can. `0s` refuses at once |
| `auth.admin` | none | an account made at boot (given the `member`, `editor` and `admin` roles with nex-db, at every start); its password from `WASP_ADMIN_PASSWORD`, needed with nex-db only until the account exists |
| `auth.secret` | `gate.key` beside `nex.path` with nex-db, else `<data folder>/gate.key` | the site's 32-byte master secret, made on the first run (owner-only on Unix), kept with the site's database so it follows the site and its backups: the gatekeeper's keys and, with nex-db, the forms' CSRF key come from it, so a form opened before a restart still posts after it. Move the file away (while stopped) to change it; open forms are then refused once |
| `auth.origin` | `https://<first site.hosts entry>` | the site's origin, for the CSRF origin check (none on a development site: the token decides) |
| `jobs.threads` | 2 | threads of the in-process job runner |
| `jobs.queue` | 1024 | jobs that may wait; a full queue refuses new jobs |
| `hello.slow_route` | false | `GET /slow?ms=N` waits, for drain tests (with `site.service = "hello"`; refused unless `gateway.listen` is a loopback address) |

Under heavy load the gateway sheds on its own: when replies to page views get slow or the passports run short, page views are answered with 503 and a short `Retry-After`, while health checks, the content editor and sign-in are still served. It stops by itself once the load has passed (about two seconds of calm), and it never lowers a shed someone else set.

A reload (SIGHUP on Linux, or `System::reload`) applies `door.ban`, `door.exempt`, `gateway.drain` and the sign-in settings at once; the listener and pool settings take effect at the next start. The door's decisions (bans added and lifted, banned sources refused, egress blocked) are written to the log.

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
