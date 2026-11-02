# security-warden

**What doors does your machine leave open, and which secrets are lying around?**

Antivirus looks for malware. security-warden looks for the mistakes we make ourselves: a dev server
listening on every network, a Docker port published to `0.0.0.0`, a tunnel left running, Tailscale
accepting connections, an SSH key without a passphrase, a token in plain text. It explains each finding
and how to fix it, in your language.

It only reads. It changes nothing and sends nothing.

## Install

**Homebrew** (macOS, Linux)

```sh
brew tap the-last-devops/security-warden https://github.com/The-Last-Devops/security-warden
brew trust the-last-devops/security-warden   # recent Homebrew asks you to trust third-party taps
brew install security-warden
security-warden start      # runs in the background and opens Security Warden
```

**macOS disk image**: download `security-warden-<version>-macos.dmg` from
[Releases](https://github.com/The-Last-Devops/security-warden/releases/latest), open it and double-click
`Install.command`: it installs to `/usr/local/bin` and opens Security Warden. The binary is signed with a
Developer ID and notarized by Apple.

**Plain binaries** for macOS, Linux and Windows are on the same Releases page, with `SHA256SUMS`:

```sh
# macOS (Apple silicon) example
curl -LO https://github.com/The-Last-Devops/security-warden/releases/latest/download/security-warden-darwin-arm64
chmod +x security-warden-darwin-arm64 && ./security-warden-darwin-arm64 start
```

**From source** (needs only Docker): `docker build --target export --output dist .`

### Update

```sh
brew update && brew upgrade security-warden   # Homebrew
security-warden stop && security-warden start # restart the background service on the new version
```

With the disk image, download the new `.dmg` and run `Install.command` again. Your passkeys, snoozed
findings and settings are kept.

### Uninstall

```sh
security-warden stop                           # stop it and remove it from login items
brew uninstall security-warden                 # Homebrew (or: sudo rm /usr/local/bin/security-warden)
brew untap the-last-devops/security-warden     # optional
```

To also delete its data (passkeys, sessions, snoozed findings, fix journal, logs):

```sh
rm -rf ~/Library/Application\ Support/security-warden ~/Library/Logs/security-warden.log   # macOS
rm -rf ~/.config/security-warden ~/.local/state/security-warden                             # Linux
```

Run `stop` before uninstalling, otherwise the login item stays behind pointing to a missing program.

## Use

```sh
security-warden start        # run in the background (web UI on http://localhost:7348) and open it
security-warden stop         # stop it, and do not start at login
security-warden status       # is it running?
security-warden open         # open the window, signed in
security-warden              # scan once and print a report
security-warden --lang vi    # in Vietnamese
security-warden --json       # machine-readable report
security-warden rules        # list every rule
security-warden version
```

`sudo security-warden` also sees ports held by other users' processes.

### Web UI and background service

`security-warden start` runs Security Warden in the background (a LaunchAgent on macOS, a systemd user
service on Linux, a background process on Windows), starts it again at login, and opens its window already
signed in. It rescans every 10 minutes, sends a notification for new problems, and brings the window up
for new high or critical problems (at most once an hour). `security-warden stop` stops it.
With Homebrew you can also use `brew services start security-warden`.

- The window is an app-style window of Chrome, Edge, Brave or Chromium (a normal tab otherwise).
- On first sign-in it offers to add a passkey (Touch ID, Windows Hello, security key).
- Always on `127.0.0.1:7348`. `security-warden serve --listen 100.x.y.z:7348` serves this machine's
  Tailscale address instead; `0.0.0.0` and other "every network" addresses are always refused.
- Sign-in: a link kept in a file only you can read (`security-warden open` uses it), or a passkey.
  Sessions survive restarts (stored hashed), last 12 hours, and lock out after 5 failed attempts.
- Protected against cross-site requests and DNS rebinding (Origin, CSRF token, Host allow-list, strict CSP).
- Snooze findings for 1, 7 or 30 days or for good (critical findings: 30 days at most).

### Fix

```sh
security-warden fix --dry-run   # show what would change
security-warden fix             # ask before each fix
security-warden fix --yes       # apply every fix
security-warden fix --undo      # revert the last batch
```

Fixes are built into security-warden, not written in rules: a rule can only point to one of a few known
actions (tighten a file's permissions, turn the firewall on, turn the guest account off, raise Tailscale
shields, upgrade a Homebrew package…). File fixes only touch regular files inside your home folder.
Every reversible change is recorded in `~/Library/Application Support/security-warden/fixes.jsonl`
(`~/.config/security-warden/` on Linux) so `--undo` can put it back. Anything risky, such as rotating a
key or stopping a tunnel you may be using, stays a written instruction.

The language comes from `--lang`, then `SW_LANG`, then your system language. Supported: English, Vietnamese.

## What it checks

90 rules over 25 sources, all read-only. Nothing needs root, nothing opens a permission prompt, and
protected folders (Documents, Desktop, Downloads, Mail, Safari…) are never read.

| Area | What | Platforms |
|---|---|---|
| Security settings | FileVault, firewall, SIP, Gatekeeper, quarantine, library validation, automatic and security-data updates, XProtect age, screen lock, auto login, guest account, AirDrop, DYLD injection | macOS |
| Security settings | LUKS, ufw/firewalld/nftables, unattended upgrades, AppArmor/SELinux, sshd root login and passwords, screen lock | Linux |
| Open doors | Ports reachable from other machines, SSH/Screen Sharing/ARD/RDP/Remote Apple Events, tunnels (ngrok, cloudflared, VS Code tunnel…), remote desktop apps, File/Internet/printer sharing, guest SMB shares | all |
| Docker | Ports on every network, privileged containers, `docker.sock` mounts, daemon on TCP without TLS, insecure registries | all |
| Tailscale | Shields down, Tailscale SSH, exit node and subnet routes, Funnel | all |
| Servers on the host | PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, Kafka, Ollama… reachable from other machines, or better run in Docker | all |
| Out-of-date software | Running Homebrew programs with a newer version (worse when they listen on the network), total outdated packages | macOS, Linux |
| Persistence | Cron jobs that fetch or run code, launchd items that root runs from user-writable files, run from temp folders, are unsigned or point to missing programs; systemd user units | macOS, Linux |
| Network settings | System proxies, PAC over HTTP, `/etc/hosts` redirecting important domains or blocking Apple updates | all |
| Privilege | `sudo` without a password, hijackable folders in `PATH` | macOS, Linux |
| Secrets | SSH keys without passphrase or with loose permissions, plain-text credentials (AWS, kube, Docker, npm, netrc, Git, PyPI, gh, Terraform), long-lived AWS and service-account keys, secrets in shell history and startup files, `.env` and private keys committed to Git or missing from `.gitignore` | all |
| Developer tools | SSH client (agent forwarding everywhere, host key checking off), Git (plain-text credential store, TLS off, `safe.directory *`), npm/pip/conda TLS and indexes, kubeconfig TLS skip and production context | all |
| AI agents | Tokens written into MCP configs (Claude, Cursor, Windsurf, VS Code, Gemini), MCP over plain HTTP, unpinned `npx` servers, agents allowed to run commands without asking | all |
| Browser | Chromium-family extensions that can debug or proxy every site, unpacked extensions | macOS, Linux |

Secret values are never printed, stored or sent: findings name the file, the variable or the kind of
secret, and history findings are counts only.

## Rules

Each check is a small YAML file in [`rules/`](rules). A rule can only read the facts a source collected,
through a [CEL](https://cel.dev) expression. It can never run commands or open files, so a contributed
rule cannot harm the machine.

```yaml
id: docker-port-all-interfaces
severity: high
platforms: [macos, windows, linux]
source: docker_ports
match: item.all_interfaces
title:
  en: "Docker container {container} publishes port {host_port} on every network"
  vi: "Container Docker {container} publish port {host_port} cho mọi mạng"
explain: { en: "...", vi: "..." }
fix: { en: "...", vi: "..." }
tests:
  - {item: {container: db, image: postgres, host_port: 5432, all_interfaces: true}, expect: true}
  - {item: {container: db, image: postgres, host_port: 5432, all_interfaces: false}, expect: false}
```

Every rule must:

- have every text in every supported language;
- ship sample items, at least one it must report and one it must not. CI runs them all.

Tiers: `stable` (on by default), `community`, `experimental` (runs, never reports).

## Build

Everything builds in Docker, so no Go toolchain is needed on the host:

```sh
docker compose run --rm test     # go vet + tests (including every rule's samples)
docker compose run --rm build    # ./dist/security-warden for this Mac (GOOS/GOARCH to change)
./dist/security-warden

docker build --target export --build-arg VERSION=v0.1.0 --output dist .   # every platform
```

Releases: push a `v*` tag. GitHub Actions builds every platform, then signs, notarizes and packages the
`.dmg` on macOS, publishes the release, and updates `Formula/security-warden.rb` (this repository is its own
Homebrew tap).

## Roadmap


- Real-time events: process and network events through Endpoint Security on macOS and ETW on Windows,
  on top of today's polling watch.
- More checks:
  - AI agent configs (tokens in MCP files, agents without a sandbox);
  - login items and LaunchAgents;
  - untrusted root certificates and proxies;
  - `sudo` without a password;
  - SSH client settings;
  - Docker daemon on TCP;
  - `.env` files and shell history;
  - outdated software.
- More languages.
- Windows posture checks.

## Acknowledgements

Ideas on what to check were informed by [bordercheck](https://github.com/ptrinh/bordercheck) (MIT).
