# Security model

Security Warden reads sensitive things (where your keys are, which ports are open) and can change some
settings. This page explains what protects that, what is stored, and what goes over the network.

## Scans only read

- Collectors never change anything, never need root and never open a permission prompt. Commands known to
  prompt or need admin rights (keychain queries, `tccutil`, `systemsetup`, `reg add`, `netsh`, `schtasks`,
  package manager refreshes or installs…) are banned by a test, `internal/source/safety_test.go`.
- Folders protected by macOS privacy controls (Documents, Desktop, Downloads, Mail, Messages, Safari,
  iCloud Drive) and other apps' containers are never read, so no "would like to access" dialog appears.
- Package managers are read from their local cache only (for example `dnf --cacheonly`); nothing is
  refreshed.
- A scan makes no network connection.
- Secret values are never shown, stored or sent. Findings carry names, paths, kinds and counts only. Text
  taken from the machine (file, repository or process names) is cleaned of control characters before it
  is printed, and shell-quoted inside fix commands, so a hostile file name cannot rewrite the terminal or
  hide a command.
- Rules cannot run anything either: a rule is a [CEL](https://cel.dev) expression over facts already
  collected, with a cost limit. See [Writing rules](writing-rules.md).

## The web UI

`security-warden start` runs `security-warden serve --background` as a LaunchAgent on macOS, a systemd
user service on Linux or a background process on Windows. It serves the web UI on `127.0.0.1:7348`,
rescans every 30 minutes (every 2 hours while a macOS or Linux laptop runs on battery), sends a
notification about new problems and opens the window for new high or critical ones, at most once an hour.

### Where it listens

`serve --listen IP:PORT` accepts exactly one IP address of this machine:

- never `0.0.0.0`, `::`, an empty host or a host name;
- loopback (`127.0.0.1`, `::1`) and this machine's own Tailscale address (`100.64.0.0/10`,
  `fd7a:115c:a1e0::/48`) are allowed;
- any other address (a LAN address) is refused unless you pass `--allow-lan`, and then a warning is
  printed; link-local and multicast addresses are always refused.

To use it from another device over Tailscale:

```sh
security-warden serve --listen 100.x.y.z:7348
```

The browser opens by itself only on loopback; for a Tailscale address the sign-in link is printed.

### Signing in

- **Passkeys.** The first time, the web UI asks you to add a passkey (Touch ID, Windows Hello or a
  security key); user verification is required. Passkeys need a host name, so they work on
  `http://localhost:7348`, not on a bare IP address. `security-warden passkey list|clear` manages them.
- **One-time tickets.** `start` and `open` ask the running server for a sign-in ticket and open the
  browser with it. The request needs the server secret, which is stored in a file only you can read
  (`server-token`, mode 0600), and must come from loopback. A ticket is valid for 60 seconds and works
  once. The secret itself never appears in a URL.
- **The macOS app.** Security Warden.app runs `security-warden app-url`, which gets a one-time ticket the
  same way (it needs the server secret file) and prints the sign-in link; the app loads it in its own
  window. So the app needs no passkey: being able to read that file already proves it is you on this
  Mac, and WKWebView offers no passkeys on `localhost` anyway. The server is the same one, on loopback
  only; the app keeps every other page (GitHub, docs) out of its window and opens them in the browser.
- **Printed link.** `serve` in a terminal prints a sign-in link with the secret, for a browser on another
  device. Keep it private: it works until the server stops, and a new secret is made at every start. After
  sign-in the browser is redirected so the secret leaves the address bar and history. The background
  service never writes the secret to its log.
- **Lockout.** Five failed attempts from one address lock it out for 15 minutes.

### Sessions

- A session lasts 12 hours. Its cookie is `HttpOnly` and `SameSite=Strict`, and each port gets its own
  cookie name, so a development build never shares sessions with a release.
- Only SHA-256 hashes of session ids and tickets are kept, in memory and in `sessions.json`, so sessions
  survive a restart without storing anything that could be replayed.
- `security-warden logout` signs every browser out.

### Request checks

- **Host allow-list.** A request must carry the listen address (or `localhost:<port>` on loopback) as its
  `Host` header. This defeats DNS rebinding: a page on `evil.example` that resolves to `127.0.0.1` still
  sends `Host: evil.example` and is refused.
- **Same origin.** Every request that changes something must have `Origin` equal to the server's own
  address, and is refused when `Sec-Fetch-Site` is `cross-site`. A page on another site cannot trigger a
  fix.
- **CSRF token.** Every `POST` that needs a session must also send the session's CSRF token in
  `X-CSRF-Token`.
- **Headers.** A strict Content Security Policy (`default-src 'self'`, no inline scripts, no framing,
  `base-uri 'none'`), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` and
  same-origin opener and resource policies. Request bodies are limited to 64 KB.
- Every API call needs a session; only the empty app shell is served without one.

## Fixes

- Rules never carry commands. A rule may name one built-in action, and each action is allowed only for
  certain sources, with each parameter filled from one fixed field of the finding: `chmod_private` can
  only tighten a file found by the credential, SSH key or authorized_keys checks, and only a regular file
  inside your home folder. The actions are: tighten file permissions, turn on the macOS firewall, stealth
  mode or Gatekeeper, turn the guest account off, set AirDrop to contacts only, raise Tailscale shields,
  turn Tailscale SSH off, and upgrade Homebrew packages.
- Nothing changes until you press Fix (web UI) or confirm `security-warden fix` (CLI). `--dry-run` shows
  the commands first.
- Every reversible change is written to a journal (`fixes.jsonl`); `security-warden fix --undo` or the
  Undo button reverts the last batch. Homebrew upgrades cannot be undone.
- `fix` refuses to run as root: actions that need admin rights ask for `sudo` themselves.
- Risky steps (rotating a key, editing an SSH server config) stay written instructions for you to follow.

## Hiding findings

A finding can be hidden for 1, 7 or 30 days, after a confirmation. Nothing can be hidden for longer, so a
forgotten problem always comes back. Hidden findings stay listed at the bottom of the web UI with a
one-click Show again, and in `security-warden ignore list`.

## What is stored

Everything lives in one data folder per user, created with private permissions:

| OS | Data folder | Log of the background service |
|---|---|---|
| macOS | `~/Library/Application Support/security-warden` | `~/Library/Logs/security-warden.log` |
| Linux | `~/.config/security-warden` | `~/.local/state/security-warden/watch.log` |
| Windows | `%APPDATA%\security-warden` | none |

| File | What |
|---|---|
| `passkeys.json` | Public keys of your passkeys |
| `sessions.json` | Hashes of web sessions |
| `server-token` | The running server's secret (0600, removed when it stops) |
| `ignores.json` | Hidden findings and until when |
| `fixes.jsonl` | Journal of applied fixes, for undo |
| `update.json` | Update settings and the last check |
| `vulndb/` | Vulnerability index and its settings |
| `service.pid` | Windows only: the background process |

Development builds use `security-warden-dev` and port 7349 instead.

## Network access

Only two things ever connect to the internet, both from the background service (or when you run the
matching command), and neither sends anything about your machine:

| What | When | Request |
|---|---|---|
| Update check | 2 minutes after start, then daily; when you open Settings (at most hourly); `security-warden update` | `HEAD https://github.com/The-Last-Devops/security-warden/releases/latest`, reading only which version the redirect points to. Homebrew installs then run `brew upgrade security-warden`. |
| Vulnerability data | Daily, only when your code folders have at least one lock file; `security-warden vulndb update` | Plain `GET` of OSV's public files over HTTPS: `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` once, then only the records listed as changed in `modified_id.csv`. A full archive is fetched again every 30 days. |

- Every machine downloads the same OSV files: no package names, versions or paths are sent. Requests carry
  a fixed User-Agent and no cookies, and redirects away from HTTPS are refused.
- The first download is about 270 MB in total (npm alone is 220 MB), read as a stream and deleted; only a
  small gzipped index (about 3 MB) is kept. Daily refreshes are a few KB to a few MB.
- Turn them off: `security-warden update off` (also in ⚙ Settings) and `security-warden vulndb off`.
- `security-warden feedback` (and "Report a false positive", "Suggest a new check" in the web UI, the MCP
  tools `report_false_positive` and `suggest_rule`) make no network call: they only build a GitHub link,
  with identifying details taken out, that you open and submit yourself.
- Notifications are local system notifications. There is no telemetry, analytics or crash reporting.
