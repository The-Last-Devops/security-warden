<div align="center">

# 🛡️ Security Warden

**What doors does your machine leave open, and which secrets are lying around?**

[![Release](https://img.shields.io/github/v/release/The-Last-Devops/security-warden)](https://github.com/The-Last-Devops/security-warden/releases/latest)
![Platforms](https://img.shields.io/badge/macOS%20·%20Linux%20·%20Windows-555)
![Rules](https://img.shields.io/badge/rules-96-0b6e52)

</div>

Antivirus looks for malware. Security Warden looks for the mistakes we make ourselves: a dev server
listening on every network, a Docker port open to `0.0.0.0`, a tunnel left running, an SSH key without a
passphrase, a token in plain text. It explains each problem and how to fix it, in English or Vietnamese.

- **Local only.** Scanning only reads, and nothing is ever sent anywhere.
- **You stay in control.** Nothing changes until you press Fix, and every fix can be undone.
- **Always watching.** Runs in the background and tells you when something new appears.

## Quick start

```sh
brew tap the-last-devops/security-warden https://github.com/The-Last-Devops/security-warden
brew trust the-last-devops/security-warden
brew install security-warden
security-warden start
```

Your browser opens on Security Warden, already signed in. The first time, it asks you to add a passkey
(Touch ID, Windows Hello or a security key). After that, `security-warden open` brings it back: no link or
password to remember.

## Install

| Method | How |
|---|---|
| **Homebrew** (macOS, Linux) | See [Quick start](#quick-start). `brew trust` is needed once for third-party taps. |
| **macOS disk image** | Download `security-warden-<version>-macos.dmg` from [Releases](https://github.com/The-Last-Devops/security-warden/releases/latest), open it, double-click `Install.command`. Signed and notarized by Apple. |
| **Binary** (macOS, Linux, Windows) | Download from [Releases](https://github.com/The-Last-Devops/security-warden/releases/latest) and check it against `SHA256SUMS`. |
| **From source** | `docker build --target export --output dist .` (needs only Docker) |

<details>
<summary>Binary example (macOS, Apple silicon)</summary>

```sh
curl -L https://github.com/The-Last-Devops/security-warden/releases/latest/download/security-warden-darwin-arm64.tar.gz | tar xz
./security-warden start
```

Other archives: `darwin-amd64`, `linux-amd64`, `linux-arm64` (`.tar.gz`) and `windows-amd64.exe`.
</details>

## Commands

| Command | What it does |
|---|---|
| `security-warden start` | Run in the background, start again at login, open the browser |
| `security-warden open` | Open the browser, signed in |
| `security-warden status` | Is it running? |
| `security-warden stop` | Stop it and remove it from login items |
| `security-warden update` | Update now (`on`/`off` for automatic updates) |
| `security-warden` | Scan once and print a report in the terminal |
| `security-warden fix` | Fix what can be fixed, asking first (`--dry-run`, `--yes`, `--undo`) |
| `security-warden ignore list\|clear` | Snoozed findings |
| `security-warden rules` | List every rule |

Add `--lang vi` or `--lang en` to any command, or `--json` to the scan.

## Update

Homebrew installs **update themselves**: the background service checks once a day and runs
`brew upgrade security-warden`, then restarts on the new version. Turn it off with
`security-warden update off` (or in ⚙ Settings). To update right away:

```sh
security-warden update
```

With the disk image you get a notification; install the new `.dmg` the same way. Passkeys, snoozed findings
and settings are kept. The update check only reads which release is the latest; nothing about your machine
is sent.

## Uninstall

```sh
security-warden stop
brew uninstall security-warden
brew untap the-last-devops/security-warden
```

Run `stop` first, so no login item is left behind. Installed from the disk image? Use
`sudo rm /usr/local/bin/security-warden` instead of `brew uninstall`.

<details>
<summary>Also delete its data (passkeys, sessions, snoozed findings, logs)</summary>

```sh
# macOS
rm -rf ~/Library/Application\ Support/security-warden ~/Library/Logs/security-warden.log
# Linux
rm -rf ~/.config/security-warden ~/.local/state/security-warden
```
</details>

## What it checks

96 rules over 26 sources. Nothing needs root, nothing opens a permission prompt, and protected folders
(Documents, Desktop, Downloads, Mail, Safari…) are never read. Secret values are never shown, stored or
sent: findings name only the file, the variable or the kind of secret.

| Area | Examples |
|---|---|
| 🔑 **Secrets & keys** | Private keys and `.env` committed to Git, SSH keys without a passphrase, plain-text AWS/kube/npm/Git credentials, tokens in shell history |
| 🚪 **Open doors** | Ports reachable from other machines, SSH/Screen Sharing/RDP, tunnels (ngrok, cloudflared, VS Code), remote desktop apps, file sharing |
| 🐳 **Docker** | Ports on every network, privileged containers, `docker.sock` or home folder mounts, host network, dangerous capabilities, secrets in env |
| 🔒 **System settings** | FileVault/LUKS, firewall, SIP, Gatekeeper, automatic updates, XProtect, screen lock, auto login, AirDrop |
| 🔁 **Login items** | Cron jobs that download code, launchd items running from temp or writable files, unsigned or missing programs |
| 🤖 **AI agents** | Tokens written into MCP configs, MCP over plain HTTP, agents allowed to run commands without asking |
| 🧰 **Developer tools** | SSH agent forwarding everywhere, Git TLS off, npm/pip without TLS, kubeconfig TLS skip or production context |
| 📦 **Software** | Out-of-date programs that are running, especially those open to the network; servers better run in Docker |
| 🌐 **Network & Tailscale** | System proxies, `/etc/hosts` redirects, Tailscale shields down, SSH, exit node, Funnel |

<details>
<summary>How the score works</summary>

Each check weighs by severity (critical 10, high 6, medium 3, low 1). The score is the weighted share of
checks that pass, each rule counted once however many places it fires. The worst open problem caps it:
25 while anything critical remains, 50 with three or more high problems, 75 with one or two. Every finding
shows how many points fixing it earns.
</details>

## Web UI and security

`start` runs a small web server on `127.0.0.1:7348` (never on `0.0.0.0`) as a LaunchAgent on macOS, a
systemd user service on Linux or a background process on Windows. It rescans every 10 minutes, notifies
you about new problems, and opens the window for new high or critical ones (at most once an hour).

- **Sign-in:** a passkey, or a one-time ticket the CLI asks for when you run `start` or `open` (valid
  60 seconds, usable once, loopback only). No secret ever appears in a URL or a log.
- **Sessions** last 12 hours and survive restarts (stored hashed). Five failed attempts lock out for 15 minutes.
- **Protected** against cross-site requests and DNS rebinding: Origin and CSRF checks, Host allow-list, strict CSP.
- **Fixes** are built in, never written in rules: tighten file permissions, turn the firewall on, turn the
  guest account off, raise Tailscale shields, upgrade a Homebrew package. Each reversible change is
  journaled for undo. Risky steps (rotating a key) stay written instructions.
- **Snooze** a finding for 1, 7 or 30 days or for good (critical: 30 days at most).

<details>
<summary>Use it from another device over Tailscale</summary>

```sh
security-warden serve --listen 100.x.y.z:7348
```

Only this machine's own Tailscale or loopback address is accepted; LAN addresses need `--allow-lan`.
</details>

## Rules

Each check is a small YAML file in [`rules/`](rules). A rule can only read the facts a source collected,
through a [CEL](https://cel.dev) expression: it can never run commands or open files, so a contributed rule
cannot harm the machine.

<details>
<summary>Example rule</summary>

```yaml
id: docker-port-all-interfaces
severity: high
platforms: [macos, windows, linux]
source: docker_ports
match: item.all_interfaces
title:
  en: "Docker container {container} publishes port {host_port} on every network"
  vi: "Container Docker {container} publish port {host_port} cho mọi mạng"
check: { en: "No container port is open to every network", vi: "Không port container nào mở ra mọi mạng" }
explain: { en: "...", vi: "..." }
fix: { en: "...", vi: "..." }
tests:
  - {item: {container: db, image: postgres, host_port: 5432, all_interfaces: true}, expect: true}
  - {item: {container: db, image: postgres, host_port: 5432, all_interfaces: false}, expect: false}
```

Every text exists in every supported language, and every rule ships samples it must and must not report.
CI runs them all. Tiers: `stable` (on), `community`, `experimental` (runs, never reports).
</details>

## Development

Everything builds in Docker; no Go or Node toolchain is needed on the host.

```sh
docker compose run --rm web      # build the web UI
docker compose run --rm test     # go vet + tests, including every rule's samples
docker compose run --rm build    # ./dist/security-warden for this Mac
```

Development builds use port **7349** and their own data folder and service (`security-warden-dev`), so they
never collide with an installed release. Releases: push a `v*` tag; GitHub Actions builds every platform,
signs and notarizes the `.dmg`, publishes the release and updates `Formula/security-warden.rb` (this
repository is its own Homebrew tap).

## Roadmap

- Signed rule updates without a new release; self-update for direct binary installs.
- Full Windows checks (firewall, BitLocker, Defender, RDP).
- Docker image vulnerability scanning.
- Real-time process and network events (Endpoint Security on macOS, ETW on Windows).
- Desktop app with a menu bar icon, sharing this web UI.

## Acknowledgements

Ideas on what to check were informed by [bordercheck](https://github.com/ptrinh/bordercheck) (MIT).
