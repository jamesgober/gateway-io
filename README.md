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

Two-step sign-in (TOTP) for nex-db accounts is the `mfa` feature. It is pure Rust, so the static musl build has it too:

```bash
cargo build --release -p wasp --no-default-features --features store-nex,mfa
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

## Host profiles

One wasp can serve several sites, each chosen by the request's `Host`:

```toml
[host]
default = "main"                 # a host no profile names (else 421)

[host.main]
hosts = ["example.com", "www.example.com"]
content = "default"              # the content the site had before profiles

[host.blog]
hosts = ["blog.example.com", "*.blog.example.com"]
name = "The Blog"
theme = "themes/blog"
content = "blog"

[host.blog.errors.404]
message = "No such post."

[host.blog.log_rule.misses]
codes = ["404"]
fields = ["path", "referrer"]
```

| Key | Default | Meaning |
|---|---|---|
| `hosts` | required | exact names, and `*.example.com` for one more label (`a.example.com`, never `example.com` or `a.b.example.com`) |
| `name` | `site.name` | the site's name |
| `theme` | `site.theme` | its theme |
| `content` | the profile's name | its content: a site of its own in nex-db, its own file with bison-db; `default` is the content from before profiles |
| `realm` | `shared` | the accounts and sessions: `shared` (the site's realm, with `auth.admin`), or a name for a realm of its own; profiles naming the same realm share it |
| `api` | `[api]` | the profile's own API, `[host.<name>.api]` with `enabled` and `prefix`; the budget is the process's |
| `chat` | `[chat]` | the profile's own messenger switch, `[host.<name>.chat]` with `enabled` and `path`; the limits are the process's |
| `admin` | none | the boot account of a realm of its own. Its password comes from the realm's own variable, `WASP_ADMIN_PASSWORD_<REALM>` (`WASP_ADMIN_PASSWORD_BLOG` for `blog`), needed until it exists. It never takes `WASP_ADMIN_PASSWORD`, so one leaked password never opens another realm |

An exact name wins over a wildcard, and the longest wildcard wins. A host belongs to one profile only. A host no profile names gets `[host] default`, or 421 when there is none, and never another profile's pages. A profile's `[host.<name>.errors.*]` and `[host.<name>.log_rule.*]` replace the top-level tables for its hosts; without them it uses `[errors]` and `[log_rule]`. The guest cache keeps every host's pages apart. A realm of its own has its own accounts, sessions, keys and account directory: a session of one realm is no one on a profile of another, and an account of one cannot sign in on the other. Without any `[host.*]` the site is the one `[site]` describes, as before.

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

- **Password.** Change it with the current one. Every other session ends, and the account's API keys are revoked.
- **Sessions.** Every session of the account, with the device and address it signed in from, when it signed in and when it was last used. Sign out any one of them, or all but this one.
- **Sign out everywhere.** Ends every session of the account, this one too, forgets its remembered devices, and revokes its API keys.
- **API keys.** With the API on, make a key for a program, with a label, its scopes and an expiry, and revoke it. See [API](#api).
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

## Log rules

`[log_rule.<name>]` writes a line for the requests that end with chosen statuses, with chosen fields, to the log or a file of its own:

```toml
[log_rule.server_errors]
codes = ["5xx"]
fields = ["client", "method", "path", "status", "code", "message", "user", "request"]

[log_rule.broken_links]
codes = ["404"]
fields = ["path", "referrer"]
destination = "file:/var/log/wasp/404.log"
rate = 20
```

| Key | Default | Meaning |
|---|---|---|
| `codes` | required | statuses (`"404"`) or classes (`"5xx"`), from 100 to 599 |
| `fields` | `client`, `method`, `path`, `status`, `code`, `request` | any of `client`, `method`, `path`, `query`, `status`, `code`, `message`, `user`, `user_agent`, `referrer`, `request` |
| `include_query` | false | the query is written only when this is true, whatever `fields` says |
| `destination` | `log` | `log` (info for 1xx to 4xx, warn for 5xx) or `file:<path>` (one JSON line per request, owner-only) |
| `max_size` | 10485760 | a file's size before it is rotated (to `<path>.1`, `<path>.2`, ...), in bytes: 64 KiB to 1 GiB |
| `keep` | 5 | rotated files kept, 0 to 100 |
| `rate` | 100 | lines a second at most, `0` for no cap |

`client` is the address the door judges: the peer, or the forwarded address only when the peer is one of `gateway.trusted_proxies`. A forwarded header from anyone else is never written. `code` and `message` are what the site said (`site::fail`, or web-net's error code), `request` is the reference the visitor's error page shows, and `user` is the account id, never an email. The user agent and referrer are cut to 256 bytes and the query to 512.

Lines are written by the access log's thread, never by the worker serving the request. A line that can't be written in time is dropped and counted, and the rule's next line says how many were dropped (`dropped`). That covers a full queue, a rule over its rate, and a file that can't be written or rotated. The rules are read again on every reload, and a bad rule stops the boot or refuses the reload.

## API

With nex-db accounts, a site can have a JSON API under `/api/v1`. It is off until `[api] enabled = true`, so a site that doesn't use it doesn't expose it:

| Request | Who | Answer |
|---|---|---|
| `GET /api/v1/me` | signed in; a key needs `account:read` | the account: `id`, `email`, `roles`, `signed_in_with` (`session` or `key`), and a key's `scopes` |
| `GET /api/v1/posts` | anyone | the posts, newest first: `posts`, `total`, `limit` (1 to 100, default 20) and `offset` |
| `GET /api/v1/posts/<slug>` | anyone | a post: title, summary, date, address, the body as HTML and as written, the search and sharing fields, the custom fields |
| `GET /api/v1/pages/<slug>` | anyone | a page, the same way |

A browser is signed in by its session cookie. A program sends a key:

```bash
curl -H "Authorization: Bearer <key>" https://example.com/api/v1/me
```

Keys are made and revoked on `/account/security`, with your password. A key has a label, its scopes and an expiry of 30, 90 or 365 days. Its text is shown once, on the page that made it. wasp never logs it or keeps it, and nex-db keeps only a keyed digest. A key acts with its account's roles cut down to its scopes, so it reads only what it was made for. It never reaches the account pages, the content editor or the admin pages, even when its account could, and it can't make more keys. Public content needs no scope. An account holds at most 20 keys. Changing the password or signing out everywhere revokes them all.

A request with a key is judged by the key alone. A key that is malformed, unknown, revoked or expired gets 401 `api.bad_key` on every API request, so a program knows at once that its key stopped working. A key whose account is disabled gets 403 `api.account_disabled`, from the very next request; a ban stops it the same way. A lockout from wrong passwords does not, so no one can break your programs by failing to sign in as you.

Errors are JSON, with the same code, message and reference an error page shows, and they go to the log the same way:

```json
{"status":404,"code":"post.unknown","message":"There is nothing at this address.","reference":"fa6e3a6d3ffd6269"}
```

An unknown address under the prefix is 404 `api.not_found`, and any method but `GET` is 405 `api.method`. What the gateway refuses before the site runs (429, 503) is a plain answer.

API requests run in the bulk lane, so under load they are refused before page views. Each caller has a budget of its own, `api.rate` requests a second in bursts of `api.burst`: an account (all its keys and its browser sessions share one), or a guest's address. Over it the answer is 429 with `Retry-After`, and no other caller slows down.

`[api] enabled = true` turns the API on and `[api] prefix` moves it. A host profile sets its own in `[host.<name>.api]`. With the gatekeeper there is no API.

## WebSockets

A site can hold WebSocket connections through the gateway. Only a route the site declares upgrades; any other request that asks to upgrade is an ordinary request. No route is declared by default. The messenger (below) declares one, and there is an echo route for tests and trials, in a build with the `ws-echo` feature:

```toml
[site]
ws_echo = "/ws/echo"
```

The caller is signed in as for a page: the session cookie, or `Authorization: Bearer <key>` for a program, in the realm the host picks, with the same standing checks. The route's rule is checked before the switch (the echo route takes a signed-in member; a key needs `account:read`), and a refusal is the HTTP status (401, 403), with nothing switched. A page may open one only from the site's own hosts (`Origin`); a request without `Origin` is not a browser and is judged by its credential alone.

While a connection is open it stays held to those rules. Disabling, banning or removing the account, a password change and signing out everywhere end its connections at once, even idle ones; so do revoking one session or one API key. Every `ws.recheck` the caller is checked again, so an expired session or key, or a role given or taken away, ends it too.

Each account may hold `ws.per_account` connections (then 429), each connection may send `ws.rate` messages a second in bursts of `ws.burst` (then the connection closes with 1008), and a frame or message over its size is refused by the protocol (1009). The connection is pinged after `ws.ping` of quiet and closed if a second interval passes without a byte. It works through the Unix socket behind the start shim too.

## Messenger

With nex-db accounts, members can send each other direct messages, talk in groups, and meet in rooms. It is off until `[chat] enabled = true`. Then the site has a WebSocket route at `/ws/chat` and a page at `/chat` that uses it (the default theme has one; a theme without `pages/chat.html` gets the route only).

```toml
[chat]
enabled = true
max_length = 4000      # characters in one message
max_conversations = 500  # conversations one account may start
max_messages = 100000  # messages one account may keep sent; 0 for no cap
rate = 5               # sends a second, per account
fanout = 2000          # deliveries a second, per account

[chat.group]
max_members = 200
invite_days = 14

[chat.rooms]
categories = ["general", "help"]
filter = []            # words no room allows
max_present = 1000     # people in one room at once

[chat.role.member]
page = 50              # messages in one page of history
history = 1000         # how far back a member can page; 0 for all
groups = true          # whether members may start groups
```

With host profiles, each profile takes `[chat]`'s switch and path unless its own `[host.<name>.chat]` sets `enabled` or `path`, so one profile can have the messenger and another not. Profiles in the same realm share its conversations.

`[chat.role.editor]` and `[chat.role.admin]` take the same keys. By default a member pages 50 at a time and 1,000 messages back, and editors and admins 100 at a time with no limit. An account gets the most its roles allow.

A browser connects with its session cookie. A program connects with `Authorization: Bearer <key>`, and the key needs the `chat` scope (made on `/account/security` like any other key). A guest gets 401 and a key without the scope 403, before anything is switched.

Every frame is one JSON object with an `op`. Account and conversation ids are 32 hex characters.

| Send | Answer |
|---|---|
| `{"op":"conversations","after":".."}` | `{"op":"conversations","me":..,"after":..,"items":[..],"more":".."}`, 50 at a time, the most recent first; each item has `id`, `members`, `last`, `at`, `read`, `unread` and `muted`. `more` is the `after` for the next page, or `null`. The first page is sent on connect too, so a member who was away sees what is new |
| `{"op":"open","with":"<account>"}` | `{"op":"conversation","id":..,"members":[..]}`; two accounts have one conversation, so opening it again gives the same id. It shows in the other's list once it has a message |
| `{"op":"history","conversation":..,"before":n,"limit":n}` | `{"op":"history","conversation":..,"messages":[..],"more":n}`, oldest first; `before` and `limit` are optional, and `more` is the `before` for the next page back, or `null` |
| `{"op":"send","conversation":..,"body":[..],"nonce":".."}` | `{"op":"sent","nonce":..,"conversation":..,"number":n}` |
| `{"op":"read","conversation":..,"number":n}` | `{"op":"read","conversation":..,"member":..,"number":n}`, with the marker as it stands (it never goes back) |
| `{"op":"mute","conversation":..,"on":true}` | `{"op":"muted","conversation":..,"on":true}` |
| `{"op":"block","account":..,"on":true}` | `{"op":"blocked","account":..,"on":true}` |

A message is `{"conversation","number","author","at","body"}`: messages are numbered from 1 in each conversation and `at` is milliseconds since 1970. Every open connection of each member gets `{"op":"message","message":..}` when one is sent. The other member gets `{"op":"read",..}` when your read marker moves, but not across a block. A member who muted a conversation gets no pushes from it, but its history is the same. A connection that stops reading its pushes misses them: it is closed with 1013 at its next frame, and catches up when it connects again.

A body is a list of spans, never HTML: `{"text":"hello","marks":["bold"]}`, with `href` for a link. Members may use `bold`, `italic` and `link` (an `http(s)://` address or one on the site, never with a backslash). Editors and admins may also use `code`, `pre`, `quote` and `strike`. A body holds at most 64 spans and `chat.max_length` characters, and no control characters but newlines. The page puts every span on the screen as text.

Each frame is checked on its own: the caller must be a member of the conversation (`chat.not_a_member`). You can write only to an active member of the realm, and a block in either direction stops opening and sending both ways. All of these get the same answer, `chat.cannot_write`, so it never tells whether an account exists or who blocked whom. Past a quota the answer is `chat.quota`. An error is `{"op":"error","code":..,"message":..}`, with the `nonce` when the frame had one. The `[ws]` budgets apply to the connection, and so do the standing checks: a disabled or banned account, a password change or a revoked key ends the connection at once, and a change of roles ends it at the next recheck, so the new limits apply when it connects again.

### Groups

A group is a conversation with a name, one owner, moderators and members. People join by invite only. The roles are the group's own: owning a group gives nothing on the site, and a site admin gets nothing special in someone else's group.

| Send | Who | Answer |
|---|---|---|
| `{"op":"create","name":".."}` | a role with `groups` (members, by default) | `{"op":"group","id":..,"name":..,"owner":..,"moderators":[..],"count":n,"settings":{..}}`; it counts as a conversation started |
| `{"op":"invite","conversation":..,"account":..}` | the owner and moderators, or any member with `members_invite` | `{"op":"invite",..}`; the account gets `{"op":"invited","conversation","name","by"}` |
| `{"op":"invites"}` | anyone | `{"op":"invites","items":[{"conversation","name","by","until"}]}` |
| `{"op":"join","conversation":..}` / `decline` | the one invited | the group's record / `{"op":"declined"}` |
| `{"op":"leave","conversation":..}` | a member | `{"op":"left"}`; an owner who leaves hands the group to the longest-standing moderator, else member, and the last one out deletes the group and its messages |
| `{"op":"kick","conversation":..,"account":..,"ban":true}` | the owner (anyone), a moderator (members) | `{"op":"kicked",..}`; the account gets `{"op":"removed"}`. A ban keeps it from being invited again until `unban` |
| `{"op":"role","conversation":..,"account":..,"role":"moderator"}` | the owner | `{"op":"role",..}`; `member` takes it back |
| `{"op":"transfer","conversation":..,"account":..}` | the owner | the group's record; the old owner stays as a moderator |
| `{"op":"settings","conversation":..,"name":..,"cap":n,"marks":"advanced","history":n,"before_join":true,"members_invite":true}` | the owner | the group's record, pushed to every member too; any key may be left out |
| `{"op":"members","conversation":..,"after":n}` | a member | `{"op":"members","items":[{"account","role","joined"}],"more":n}`, 100 at a time |
| `{"op":"group","conversation":..}` | a member | the group's record |

`history`, `send`, `read` and `mute` work in a group as in a direct conversation. A group's `cap` counts members and open invites together (50 by default, at most `chat.group.max_members`). With `marks = "advanced"`, an author may use the advanced marks only as far as their site role allows. A reader pages back as far as the smaller of the group's `history` and their role's, and a new member sees only what came after they joined unless the group sets `before_join`. Every member's connections get `{"op":"member","conversation","account","event","by"}` when someone joins, leaves, is kicked, changes role or becomes owner. Groups send no read receipts.

An invite is refused with the same `chat.cannot_write` as everywhere else when the account isn't an active member of the realm, is banned from the group, or has a block either way with whoever invites it. A block never takes anyone out of a group, but the blocker gets none of the blocked account's messages, live or in history. Kicks, bans, role changes, transfers and settings go to the log as audit lines, with account ids and never message text. Group ops on a direct conversation answer `chat.not_a_group`, and an op the caller's place doesn't allow answers `chat.not_allowed`.

Every send is charged to two budgets of the account, across all its connections: `chat.rate` sends a second (bursts of `chat.burst`), and `chat.fanout` deliveries a second (bursts of twice that), where a message costs one delivery for each other member. Over either, the answer is `chat.slow_down` with `retry_ms`, and nothing is kept.

### Rooms

A room is a place people walk into, and it's about who is in it right now. A connection enters a room and exits it, and closing the socket exits every room. Everyone inside hears `{"op":"entered","room","account"}` and `{"op":"exited",..}` when someone comes or goes, and a message reaches the connections in the room at that moment. Who is in a room is never shown outside it, and it's never stored. Rooms aren't in the conversation list.

A room is `public` (listed in the directory, open to anyone signed in whose site role reaches the room's `role`, members by default), `unlisted` (the same, but entered by id and never listed) or `private` (entered only by the owner, its moderators and the accounts on its list). It's `persistent` (it keeps its messages, and people page back up to its `scroll`, while it keeps its last `keep`) or ephemeral (it keeps nothing, and `history` is empty). Who may make rooms is per role: `[chat.role.<role>] rooms` is `none`, `private` (private and unlisted rooms) or `public` (any). Members get `private` and editors and admins get `public` by default.

| Send | Who | Answer |
|---|---|---|
| `{"op":"rooms","category":..,"q":..,"after":n}` | anyone | `{"op":"rooms","items":[{"id","name","topic","category","persistent","people"}],"more":n}`: the public rooms open to you, the busiest first, 50 a page; `q` searches the name and topic |
| `{"op":"categories"}` | anyone | `{"op":"categories","items":[{"name","rooms"}]}` |
| `{"op":"create_room","name":..,"topic":..,"category":..,"access":"public","role":"member","persistent":true}` | by `rooms` | the room's record; it counts as a conversation started |
| `{"op":"room","room":..}` | who may enter | `{"op":"room","id","name","topic","category","access","role","owner","moderators","persistent","scroll","keep","marks","slow","people"}`, with `words` for its moderators |
| `{"op":"enter","room":..}` / `exit` | who may enter | the room's record / `{"op":"exited"}` |
| `{"op":"who","room":..,"after":n}` | someone in the room | `{"op":"who","items":[accounts],"more":n}`, 200 a page |
| `{"op":"send","conversation":<room>,..}` | someone in the room | as for any conversation |
| `{"op":"room_mute","room":..,"account":..,"minutes":n}` / `room_unmute` | moderators | `{"op":"muted","until":ms}`; muted, they stay in the room but can't write |
| `{"op":"room_kick","room":..,"account":..,"minutes":5}` | moderators | out now, and back after `minutes` |
| `{"op":"room_ban","room":..,"account":..,"minutes":n}` / `room_unban` | moderators | out, and kept out until it ends; `minutes` 0 (the default for mutes and bans) is until lifted |
| `{"op":"room_role","room":..,"account":..,"role":"moderator"}` | the owner | the room's record; `member` takes it back |
| `{"op":"room_invite","room":..,"account":..}` / `room_uninvite` | moderators of a private room | onto or off its list; the account gets `{"op":"room_invited"}` |
| `{"op":"room_settings","room":..,..}` | the owner: any of `name`, `category`, `access`, `role`, `persistent`, `scroll`, `keep`, `marks`; moderators too: `topic`, `slow`, `words` | the room's record |
| `{"op":"delete_room","room":..}` | the owner, or a site admin (any room) | `{"op":"room_closed"}`, also pushed to everyone in it |
| `{"op":"ban_account","account":..,"room":..}` | a site admin | `{"op":"account_banned"}`: the account is banned from the whole site, and its sessions, keys and connections end. Never another admin. `room`, when given, goes in the audit line |

The target of a mute, kick or ban hears `muted`, `kicked` or `banned` with its end. None of it ever reaches the owner, and a moderator never acts on another moderator. A site admin acts as a moderator in every public and unlisted room. In a private room they can't enter or read anything, but they can close the room and ban an account from the whole site, so abuse there is never out of reach. Every step they take goes to the log as a `staff` audit line. Every moderation step goes to the log, with account ids and never message text. `slow` is slow mode: one message per person per that many seconds, counted from their last one (moderators don't wait). A message that holds a word from the site's `chat.rooms.filter` or the room's `words` (up to 100) as a whole word, ignoring case, is refused with `chat.filtered`. The log counts refusals but never keeps the text. A room you can't enter answers `chat.no_room`, whether it exists or not.

A room holds up to `chat.rooms.max_present` people at once, and a private room's list holds up to the same. A message costs the sender one delivery from `chat.fanout` for each other person in the room, and the whole realm shares `chat.rooms.fanout` deliveries a second, so no number of senders can flood the process. Over either, the answer is `chat.slow_down`. Entered and exited notices are dropped, never queued, when the realm's budget is spent. Rooms live on the process their people connect to for now; one room across several nodes is still to come.

Messages are kept in nex-db, in a content site of their own for each realm, so they survive a restart. A message is written once: its number is taken only if it is free, so nothing is ever written over, even after a crash in the middle of a send. One process sends at a time per conversation for now; several nodes sharing one store is still to come.

## Configuration

A key wasp does not know, in any section, refuses the boot with its name, so a typo never leaves a setting at its default.

| Key | Default | Meaning |
|---|---|---|
| `gateway.listen` | `127.0.0.1:8080` | the listening address, or `unix:<path>` for a Unix socket (owner-only, and only this user's processes may connect); `WASP_SOCKET`, set by the start shim, takes its place, and so does `PORT` |
| `gateway.workers` | logical CPUs, at most 64 (at most 4 when `PORT` or `WASP_SOCKET` is set) | reactor workers (1 to 256); with `blocking`, the connections served at once |
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
| `gateway.cpu_threads` | 2 | threads that answer the slow routes (signing in and every other route that checks a password) so the workers keep answering page views meanwhile; at most 16 waiting per thread, then 503. `0` answers them on the worker. Not used with `blocking` |
| `gateway.stage_timing` | false | record where each request's server time goes; logged per stage when the gateway stops |
| `gateway.ingress` | `direct` | `direct`, or `proxy` behind a reverse proxy: the client is the address in `X-Forwarded-For`, believed only from `gateway.trusted_proxies`, and the door bans and charges that client; a trusted proxy that sends no header is refused |
| `gateway.trusted_proxies` | none | the proxies' addresses or blocks (`127.0.0.1`, `10.0.0.0/8`); required with `ingress = "proxy"` |
| `gateway.forwarded_proto` | true | with `ingress = "proxy"`, take the scheme from `X-Forwarded-Proto` (an https proxy in front makes the site https) |
| `door.ban` | none | addresses refused at the door; changes apply on reload |
| `door.exempt` | none | addresses exempt from the door's budgets (local load tests); changes apply on reload |
| `site.service` | `web` | which service the site profile uses: `web` (web-net) or `hello` (the passport stub) |
| `site.base` | none | the folder the site lives under (`/blog`: a leading `/`, no trailing `/`) |
| `site.hosts` | none | the site's hosts, canonical first; none answers only the development hosts (`localhost`, `127.0.0.1`, `[::1]`), and is refused at boot when `PORT` or `WASP_SOCKET` is set |
| `site.development` | `false` | allows an empty `site.hosts` when `PORT` or `WASP_SOCKET` is set (a local run behind a front end) |
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
| `api.enabled` | false | the JSON API, with nex-db accounts (none with the gatekeeper) |
| `api.prefix` | `/api/v1` | where the API lives, under `site.base`; never a path the site uses (`/admin`, `/account`, `/posts`, ...) |
| `api.rate` | 10 | API requests a second for each caller (an account, all its keys and sessions together, or a guest's address); `0` for no budget. Read at boot |
| `api.burst` | twice `api.rate` | the most at once after a quiet spell, at least `api.rate` |
| `ws.max_frame` | 65536 | the largest WebSocket frame, in bytes |
| `ws.max_message` | 262144 | the largest WebSocket message, in bytes (at least `ws.max_frame`) |
| `ws.ping` | `30s` | a ping after this much quiet; a second interval with no byte back closes the connection |
| `ws.per_account` | 8 | WebSocket connections one account may hold; `0` for no cap |
| `ws.rate` | 20 | messages a second per connection; `0` for no budget |
| `ws.burst` | twice `ws.rate` | the most messages at once after a quiet spell |
| `ws.recheck` | `15s` | how often an open connection's caller is checked again |
| `chat.enabled` | false | the messenger, with nex-db accounts |
| `chat.path` | `/ws/chat` | the messenger's WebSocket route, under `site.base` |
| `chat.max_length` | 4000 | characters in one message |
| `chat.max_conversations` | 500 | conversations one account may start |
| `chat.max_messages` | 100000 | messages one account may keep sent; `0` for no cap |
| `chat.rate` | 5 | sends a second for one account, across its connections; `0` for no budget |
| `chat.burst` | four times `chat.rate` | the most sends at once after a quiet spell |
| `chat.fanout` | 2000 | deliveries a second for one account (a message costs one per other member); `0` for no budget |
| `chat.group.max_members` | 200 | the most members and open invites a group may have (2 to 1,000) |
| `chat.group.invite_days` | 14 | how long an invite lasts, in days |
| `chat.role.<role>.groups` | true | whether the role may start groups |
| `chat.role.<role>.rooms` | `private` (`public` for `editor` and `admin`) | which rooms the role may make: `none`, `private` (private and unlisted) or `public` (any) |
| `chat.rooms.categories` | `["general"]` | the categories a room may be in (lower case letters, digits and `-`) |
| `chat.rooms.filter` | none | words no message in any room may hold, one word each |
| `chat.rooms.max` | 10000 | the most rooms the site may hold |
| `chat.rooms.max_present` | 1000 | the most people in one room at once, and on a private room's list (2 to 10,000) |
| `chat.rooms.max_keep` | 100000 | the most messages a persistent room may keep |
| `chat.rooms.fanout` | 200000 | room deliveries a second across the realm; `0` for no budget |
| `chat.role.<role>.page` | 50 (100 for `editor` and `admin`) | messages in one page of history, 1 to 500 |
| `chat.role.<role>.history` | 1000 (all for `editor` and `admin`) | how many messages back a role can page; `0` for all |
| `site.ws_echo` | none | the echo WebSocket route's path (a build with the `ws-echo` feature; for tests and trials) |
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
