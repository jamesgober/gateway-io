# Backups and restores

A wasp site is its data folder: the nex-db database (`nex/`) and the master secret beside it (`gate.key`). Everything else is files you already have: the configuration, the theme folder and the binary.

Don't copy `nex/` while wasp runs. A copy made mid-write can't be trusted. Let wasp make the backups itself, or copy the folder while it's stopped.

## Turning backups on

```toml
[backup]
path = "/home/you/wasp-backups"   # a folder of its own, not inside the data folder
every = "1h"                      # 1m to 7d
```

wasp then backs up:

- when it starts;
- every `every` while it runs;
- once more when it stops cleanly (SIGTERM, or the start shim letting go).

The first backup writes a full copy, called a base. Writes wait while it's written and reads go on, which takes a fraction of a second for a small site. Every later backup only appends what changed since. Each one goes to the log as `backup made`, and a failure goes to the log as `backup failed` with the reason.

The folder looks like this:

```text
wasp-backups/
├─ nex/              the database's backup: a base, then everything committed since
├─ nex.<time>.old/   an earlier backup the database had moved past (the two newest are kept)
└─ gate.key          the master secret, owner-only
```

When the database is restarted, its log can move past what the backup holds. The next backup then moves the old one aside as `nex.<time>.old` and starts a new base. The two newest of those are kept and older ones are removed.

The backup holds everything needed to sign people in, including the master secret. Keep it as private as the data folder: owner-only, never in a web-served folder.

## Copying it off the server

A backup on the same disk as the site doesn't survive the disk. Copy the folder somewhere else on a schedule, for example with cron on the server:

```bash
rsync -a --delete /home/you/wasp-backups/ backup-host:wasp-backups/
```

A copy can catch a backup being appended. The next copy fixes that, and a restore checks the backup first and refuses a damaged one.

## Restoring

1. Stop the site, or leave it running if you're restoring next to it to check.
2. Make a new data folder from the backup. wasp refuses to restore over a database that's already there:

   ```bash
   ./wasp restore /home/you/wasp-backups /home/you/wasp-data-restored
   ```

   This writes `nex/` and `gate.key` into the new folder and prints what it did.
3. Point the site at the new folder (`nex.path = "/home/you/wasp-data-restored/nex"`) and start it.

If a revocation happened after the last backup (a sign-out everywhere, a ban, a password change, a revoked key), it's applied again when the restored database first opens. A restore never brings back access that was taken away.

## Checking a restore

On the restored site:

- `/ready` answers 200;
- someone signs in with their password;
- a browser that was signed in before the backup is still signed in. That shows the master secret came back;
- an API key made before the backup still works;
- the pages and posts are there;
- in `/chat`, conversations, groups and their messages are there, and so are rooms with their settings. Rooms are empty, since nobody is in them yet.

## What a restore can't bring back

- **Anything after the last backup.** Up to `every` of writes can be lost: new accounts, posts, messages. A shorter `every` loses less.
- **Who is in each room, and open connections.** Presence is never stored. Everyone reconnects, and the page does that by itself.
- **Messages in ephemeral rooms.** They were never stored.
- **The process's own memory:**
  - the guest page cache, which fills again;
  - a sign-in that was half done, which starts over;
  - the per-address sign-in and wrong-code counts;
  - chat and API budgets and slow-mode timers;
  - bans and strikes the door added on its own.

  Bans in the configuration (`door.ban`) come back with the configuration.
- **The configuration, the theme folder and the logs.** They aren't in the backup, so copy them with the rest of your files.
- **Accounts kept by the gatekeeper** (`auth.store = "gatekeeper"`). They live in memory and are never backed up. Backups are for nex-db sites.

## On Windows

`Stop-Process`, which the local preview's `stop.ps1` uses, ends wasp without a clean stop, so the final backup isn't made. The last one is the latest of the timed ones.

Save the configuration file without a byte-order mark, since wasp refuses one that starts with it. PowerShell 5's `Set-Content -Encoding utf8` writes one; use `[IO.File]::WriteAllText` with `UTF8Encoding($false)`.
