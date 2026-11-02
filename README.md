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
security-warden              # scan and print a report
security-warden --lang vi    # in Vietnamese
security-warden --json       # machine-readable report
security-warden rules        # list every rule
security-warden version
```

`sudo security-warden` also sees ports held by other users' processes.

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

| Source | What | Platforms |
|---|---|---|
| Security settings | FileVault, firewall, SIP, Gatekeeper, automatic security updates, screen lock, guest account | macOS |
| Security settings | LUKS disk encryption, ufw/firewalld/nftables, unattended upgrades, AppArmor/SELinux, sshd root login and password auth, screen lock | Linux |
| Listening ports | Processes reachable from other machines (not only localhost) | macOS, Linux |
| Servers on the host | PostgreSQL, MySQL, Redis, MongoDB, Elasticsearch, RabbitMQ, Kafka, Ollama… reachable from other machines, or better run in Docker | all |
| Out-of-date software | Running Homebrew programs with a newer version (worse when they listen on the network), total outdated packages | macOS, Linux |
| Remote access | SSH, Screen Sharing, Apple Remote Desktop, RDP turned on | all |
| Tunnels and remote desktop | ngrok, cloudflared, VS Code tunnel, frp, AnyDesk, TeamViewer, RustDesk… running | all |
| Docker | Ports published on every network, privileged containers, `docker.sock` mounted | all |
| Tailscale | Incoming connections allowed (shields down), Tailscale SSH, exit node / subnet routes, Funnel | all |
| SSH keys | Private keys without a passphrase, keys readable by other users | all |
| Credential files | `~/.aws`, kubeconfig, Docker, npm, `.netrc`, `.git-credentials`, PyPI, GitHub CLI, Terraform: plain-text secrets, loose permissions, long-lived AWS keys | all |

Secret values are never printed, stored or sent: findings only name the file and the kind of secret.

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


- Live alerts: a background agent that notifies you when a new port, tunnel, container or login item
  appears (polling plus file events), then real-time process and network events through Endpoint
  Security on macOS and ETW on Windows.
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
