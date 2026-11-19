# cPanel checklist

The steps done by hand to put the site on a cPanel host. The background for each one is in [README.md](README.md) (DEPLOY.md in the release bundle).

## 1. Check the bundle

You need two files: the bundle, `wasp-<commit>-x86_64-linux-musl.tar.gz`, and `wasp-<commit>-x86_64-linux-musl.tar.gz.sha256`.

```bash
sha256sum -c wasp-<commit>-x86_64-linux-musl.tar.gz.sha256
```

It should print `OK`.

## 2. Make the application folder

1. Pick a folder outside `public_html`, for example `~/wasp`. Nothing in it should be reachable as a plain file.
2. In cPanel, open **File Manager**, upload the bundle into your home folder, and **Extract** it.
3. Rename the extracted folder to the one you picked, or move its contents into that folder.
4. Make the binary executable: select `wasp`, choose **Permissions**, and set `755`.
5. Make an empty `data` folder in the application folder. Set it to `700`.

The application folder now holds:

```text
wasp                 the site (755)
themes/default       the theme
app.js               the start shim, for Node-only hosts
wasp.conf.example    the configuration to copy
DEPLOY.md            the background
data/                the database (700), empty for now
```

## 3. Write wasp.conf

1. Copy `wasp.conf.example` to `wasp.conf`, in the same folder.
2. Edit `wasp.conf`:
   - Under `[site]`, set `hosts` to your domain names, for example `["example.com", "www.example.com"]`.
   - Under `[auth]`, set `admin` to the email you will sign in with.
   - Under `[nex]`, leave `path = "data/nex"`. That is the database, inside the `data` folder from step 2.
3. Set `wasp.conf` to `600`.

Don't put a password in this file.

## 4. Set up the application in cPanel

Use whichever one your cPanel offers.

**Setup Node.js App** (most shared hosts):

1. Click **Create Application**.
2. Fill in the form:
   - **Application root**: the folder from step 2, for example `wasp`.
   - **Application URL**: your domain.
   - **Application startup file**: `app.js`.
   - **Node.js version**: any version from 18 on.
3. Under **Environment variables**, add `WASP_ADMIN_PASSWORD` with a long password for the admin account.
4. Click **Create**, then **Start**. Don't run `npm install`: the shim needs nothing.

**Application Manager** (Passenger, where it runs any command):

1. Register the application with the folder from step 2 as its path, and your domain.
2. Set the start command to `./wasp`.
3. Add the environment variable `WASP_ADMIN_PASSWORD` as above.
4. Deploy it.

## 5. The first admin account

On its first start, wasp makes the account `auth.admin` with the password from `WASP_ADMIN_PASSWORD`.

- Keep the variable set afterwards: wasp refuses to start while `auth.admin` is set and the variable is missing.
- Changing the variable later does not change the password. The account is made only when it does not exist yet.

Sign in at `https://<your domain>/sign-in`, then open `/admin` to write posts and pages.

## 6. Check it

Run these from your own computer, not the server. A request straight to wasp's local port names no client, so it is refused.

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://<your domain>/ready
```

```bash
curl -sI https://<your domain>/health
```

- `/ready` answers `200` when the site can serve. It answers `503` while the database cannot serve: look in the log.
- `/health` answers `200` while the process is up.

The log is the application's log in cPanel (Passenger keeps the process output). On start it shows `ready`. Look for:

- a `boot notice`: something to fix, such as an empty `site.hosts`;
- `level":"error"` lines;
- with `access_log = true`, one `access` line per request.

## 7. Restarting and updating

- **Restart:** use **Restart** on the application's page in cPanel.
- **Update:**
  1. Stop the application.
  2. Replace `wasp` and `themes/default` with the new bundle's. Keep `wasp.conf` and `data/`.
  3. Start it again.
- **Back up:** copy the `data` folder while the application is stopped. Only one process may open the database at a time.
