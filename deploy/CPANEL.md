# cPanel checklist

The steps done by hand to put the site on a cPanel host. The background for each one is in DEPLOY.md (`deploy/README.md` in the repository).

## 1. Get the bundle

Every push to `main` builds it. Open the commit's CI run on GitHub (**Actions**), then under **Artifacts** download `wasp-bundle-x86_64-linux-musl`. It is a zip that holds two files:

- `wasp-<commit>-x86_64-linux-musl.tar.gz`
- `wasp-<commit>-x86_64-linux-musl.tar.gz.sha256`

To build it yourself on Linux instead, see "Build" in DEPLOY.md.

Check the bundle:

```bash
sha256sum -c wasp-<commit>-x86_64-linux-musl.tar.gz.sha256
```

It should print `OK`.

## 2. Make the application folder

1. Pick a folder outside `public_html`, for example `~/wasp`. Nothing in it should be reachable as a plain file.
2. In cPanel, open **File Manager**, upload the `.tar.gz` into your home folder, and **Extract** it.
3. Rename the extracted folder to the one you picked.
4. Check that `wasp` is executable: select it, choose **Permissions**, and set `755` if it is not.

The application folder now holds:

```text
wasp                 the site
themes/default       the theme
app.js               the start shim
wasp.conf.example    the configuration to copy
DEPLOY.md            the background
CPANEL.md            this checklist
```

wasp makes the `data` folder (owner-only) on its first start.

## 3. Write wasp.conf

1. Copy `wasp.conf.example` to `wasp.conf`, in the same folder.
2. Edit the two lines marked `CHANGE`:
   - `hosts`: your domain names, for example `["example.com", "www.example.com"]`.
   - `admin`: the email you will sign in with. One that is not published on the site is better: anyone who knows it can make sign-in wait for a while by trying wrong passwords.
3. Set `wasp.conf` to `600`.

Don't put a password in this file. A key wasp does not know (a typo) stops it at boot, and the log names the key.

## 4. Force HTTPS

In cPanel, open **Domains** and turn on **Force HTTPS Redirect** for the domain. Signing in needs https: the browser does not keep the sign-in cookie on a plain http page.

## 5. Set up the application in cPanel

Open **Setup Node.js App** (on some hosts, **Application Manager**; it works the same way, by a startup file).

1. Click **Create Application**.
2. Fill in the form:
   - **Node.js version**: any version from 18 on.
   - **Application mode**: **Production**.
   - **Application root**: the folder from step 2, for example `wasp`.
   - **Application URL**: your domain.
   - **Application startup file**: `app.js`.
3. Under **Environment variables**, add `WASP_ADMIN_PASSWORD` with a long password (at least 12 characters) for the admin account.
4. Click **Create**, then **Start**. Don't run `npm install`: the shim needs nothing.

## 6. The first admin account

On its first start, wasp makes the account `admin` with the password from `WASP_ADMIN_PASSWORD`.

- After that first start you can remove the variable: wasp starts without it once the account exists.
- Changing the variable later does not change the password. The account is made only when it does not exist yet.

Sign in at `https://<your domain>/sign-in`, then open `/admin` to write posts and pages.

## 7. Check it

Run these from your own computer, not the server. A request straight to wasp's local port names no client, so it is refused.

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://<your domain>/ready
```

```bash
curl -sI https://<your domain>/health
```

- `/ready` answers `200` when the site can serve. It answers `503` while the database cannot serve; the log says why.
- `/health` answers `200` while the process is up.

The log is the application's log in cPanel (Passenger keeps the process output in a file). It shows warnings and errors only. Look for:

- `refused to load`: wasp did not start, and the line says why (a typo in `wasp.conf`, an empty `hosts`, a missing password);
- `"level":"error"` lines.

To see one line per request for a while, set `access_log = true` under `[gateway]` and restart. Turn it off again afterwards: Passenger never rotates that file.

## 8. Restarting and updating

- **Restart:** use **Restart** on the application's page in cPanel.
- **Update:**
  1. Stop the application.
  2. Replace `wasp`, `app.js` and `themes/default` with the new bundle's. Keep `wasp.conf` and `data/`.
  3. Start it again.
- **Back up:** copy the `data` folder while the application is stopped. Only one process may open the database at a time.
- **A full disk:** when the account's quota fills, the database stops taking writes: sign-in and saves answer 503, and `/ready` answers 503. Free some space, then restart the application.
