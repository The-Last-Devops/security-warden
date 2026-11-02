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
brew install the-last-devops/tap/security-warden
```

**macOS disk image**: download `security-warden-<version>-macos.dmg` from
[Releases](https://github.com/The-Last-Devops/security-warden/releases/latest), open it and double-click
`Install.command`. The binary is signed with a Developer ID and notarized by Apple.

**Plain binaries** for macOS, Linux and Windows are on the same Releases page, with `SHA256SUMS`.

## Use

```sh
security-warden serve        # web UI on http://localhost:7348, opens your browser
security-warden              # scan and print a report
security-warden --lang vi    # in Vietnamese
security-warden --json       # machine-readable report
security-warden rules        # list every rule
security-warden version
```

`sudo security-warden` also sees ports held by other users' processes.

### Web UI

`security-warden serve` starts the web UI on `127.0.0.1:7348` and opens it in your browser, already
signed in. On first sign-in it offers to add a passkey (Touch ID, Windows Hello, security key), so next
time you sign in with a touch. Double-clicking the app (not from a terminal) does the same.

- Listens on one address only: loopback by default, or this machine's Tailscale IP
  (`--listen 100.x.y.z:7348`). `0.0.0.0` and other "every network" addresses are always refused.
- Sign-in: a one-time link printed in the terminal, or a passkey. Sessions survive restarts (stored
  hashed), last 12 hours, and lock out after 5 failed attempts.
- Protected against cross-site requests and DNS rebinding (Origin, CSRF token, Host allow-list, strict CSP).
- Snooze findings for 1, 7 or 30 days or for good (critical findings: 30 days at most).

### Watch

```sh
security-warden watch                  # quick scan every minute, full scan every 30 minutes
security-warden agent install          # run watch in the background at login (no admin rights)
security-warden agent uninstall
```

When something new appears (a port opens, a tunnel starts, a login item is added, a key loses its
passphrase…) you get a desktop notification. Fixed problems are logged as resolved.

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
`.dmg` on macOS, publishes the release, and updates the Homebrew formula.

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
