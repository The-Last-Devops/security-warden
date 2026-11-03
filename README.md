<div align="center">

# 🛡️ Security Warden

**What doors does your machine leave open, and which secrets are lying around?**

[![Release](https://img.shields.io/github/v/release/The-Last-Devops/security-warden)](https://github.com/The-Last-Devops/security-warden/releases/latest)
![Platforms](https://img.shields.io/badge/macOS%20·%20Linux%20·%20Windows-555)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Rules](https://img.shields.io/badge/rules-158-0b6e52)

</div>

Antivirus looks for malware. Security Warden looks for the mistakes we make ourselves: a dev server
listening on every network, a Docker port open to `0.0.0.0`, a tunnel left running, an SSH key without a
passphrase, a token in plain text. It explains each problem and how to fix it, in English or Vietnamese.

- **Local only.** Scanning only reads, and nothing about your machine is ever sent anywhere. The only download is
  public vulnerability data from [OSV](https://osv.dev), once a day ([details](#vulnerability-data)).
- **You stay in control.** Nothing changes until you press Fix, and every fix can be undone.
- **Always watching.** Runs in the background and tells you when something new appears.
- **Lightweight.** One self-contained ~20 MB program with nothing else to install. About 25 MB of memory and no CPU while it waits; a full scan takes 3–6 seconds. The vulnerability data is a one-time ~270 MB download (then a few MB a day) that keeps a 3 MB index.

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
| **Debian, Ubuntu** | Download `security-warden_<version>_amd64.deb` (or `arm64`) from [Releases](https://github.com/The-Last-Devops/security-warden/releases/latest), then `sudo apt install ./security-warden_*.deb` |
| **Fedora, RHEL, openSUSE** | Download the `.rpm`, then `sudo rpm -i security-warden-*.rpm` |
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
| `security-warden vulndb` | Vulnerability data: status, `update` now, `on`/`off` for the daily refresh |
| `security-warden` | Scan once and print a report in the terminal: both scores, one entry per problem with its places, fix steps and the command for each place |
| `security-warden --scope machine\|code` | Only the machine itself, or only the code on it |
| `security-warden --category NAME` | Only one category: `secrets`, `exposure`, `settings`, `persistence`, `ai`, `devtools`, `software`, `other`, `code_secrets`, `code_deps` |
| `security-warden --by-repo` | Code problems grouped per repository (the machine first) |
| `security-warden --safe` | What already passes, per category |
| `security-warden --verbose` | Every place, rule ids, and the keys `[in brackets]` that `ignore add` accepts |
| `security-warden fix` | Fix what can be fixed, asking first (`--dry-run`, `--yes`, `--undo`) |
| `security-warden ignore add RULE\|KEY [--days 1\|7\|30]` | Hide a problem for a while (7 days by default, 30 at most): a rule id hides every place, a key one place |
| `security-warden ignore restore RULE\|KEY\|all` | Show hidden problems again |
| `security-warden ignore list` | What is hidden, where, and until when (`clear` shows everything again) |
| `security-warden passkey list\|clear` | Passkeys that sign in to the web UI (`clear` asks first, unless `--yes`) |
| `security-warden logout` | Sign every browser out of the web UI |
| `security-warden rules` | List every rule |

Add `--lang vi` or `--lang en` to any command, or `--json` to the scan (the scope and category
filters apply to the JSON too).

## Update

Homebrew installs **update themselves**: the background service checks once a day and runs
`brew upgrade security-warden`, then restarts on the new version. Turn it off with
`security-warden update off` (or in ⚙ Settings). To update right away, use either:

```sh
security-warden update                                  # upgrades and restarts the service
brew upgrade security-warden && security-warden start   # the same, by hand
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

158 rules over 36 sources. Nothing needs root, nothing opens a permission prompt, and protected folders
(Documents, Desktop, Downloads, Mail, Safari…) are never read. Secret values are never shown, stored or
sent: findings name only the file, the variable or the kind of secret.

| Area | Examples |
|---|---|
| 🔑 **Secrets & keys** | Private keys and `.env` committed to Git, SSH keys without a passphrase or weak (DSA, short RSA), plain-text AWS/kube/npm/Git credentials, tokens in shell history, shell startup files and Git remote URLs (about 200 token formats from gitleaks), secret files deleted but still in Git history |
| 🚪 **Open doors** | Ports reachable from other machines, SSH/Screen Sharing/RDP, tunnels (ngrok, cloudflared, VS Code), remote desktop apps, file sharing |
| 🐳 **Docker** | Ports on every network, privileged containers, `docker.sock` or home folder mounts, host network/UTS/user namespace, shared mount propagation, dangerous capabilities, no `no-new-privileges`, no memory or process limits, secrets in env, images older than 6 months or on `latest` |
| 🔒 **System settings** | macOS out of security support, FileVault/LUKS, firewall and stealth mode, SIP, Gatekeeper, automatic updates, XProtect, screen lock, hot corners that block it, password hints, auto login, AirDrop, Bluetooth/media sharing, content caching |
| 🔁 **Login items** | Cron jobs that download code, launchd items running from temp or writable files, unsigned or missing programs; running crypto miners or programs started from /tmp or Downloads; unsigned apps in /Applications |
| 🤖 **AI agents** | Tokens written into MCP configs, MCP over plain HTTP, agents allowed to run commands without asking |
| 🧰 **Developer tools** | VS Code/Cursor Workspace Trust off, auto-run tasks, secrets in settings, extensions installed from files or removed from the Marketplace (malware, impersonation); browser extensions Google flagged as malware or unwanted; SSH agent forwarding everywhere, Git TLS off, npm/pip without TLS, kubeconfig TLS skip or client certificates |
| 🪟 **Windows** | Windows Firewall off for a network type, BitLocker off, Microsoft Defender real-time protection or Tamper Protection off, definitions older than 7 days, exclusions of whole drives, the user folder, temp or Downloads; Remote Desktop on (worse without NLA), UAC off or set to never notify, automatic updates disabled by policy, SMBv1, Guest account, AutoPlay; Run keys, Startup folder and scheduled tasks starting from %TEMP%, Downloads or loose AppData files, or downloading and decoding scripts |
| 🐧 **Linux** | LUKS disk encryption, firewall (ufw, firewalld, nftables), unattended upgrades, SELinux/AppArmor, screen lock, sshd root and password login, pending apt/dnf updates with security updates counted apart (from the local package cache, no refresh), systemd user units and autostart entries |
| 📦 **Software** | Out-of-date programs that are running, especially those open to the network; Homebrew, apt and dnf updates waiting; servers better run in Docker; project dependencies with known vulnerabilities (CVE/GHSA, matched offline against OSV) |
| 🌐 **Network & Tailscale** | System proxies, `/etc/hosts` redirects, Tailscale shields down, SSH, exit node, Funnel |

### Vulnerability data

Dependencies pinned in the lock files of your code folders (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
`requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock`) are
matched against a local copy of the [OSV](https://osv.dev) database for npm, PyPI, Go, crates.io and RubyGems.
Findings are grouped per repository, name the worst package, its advisories and the release that fixes it,
and give the upgrade command for that package manager.

- **Nothing about your projects leaves the machine.** The background service downloads OSV's public files
  (`https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` once, then only the records that
  changed, listed in `modified_id.csv`) over HTTPS with a plain GET, and only when your code folders have at
  least one lock file. Every machine fetches the same files; no package names or versions are sent. A scan
  never touches the network: with no data yet, these checks show as skipped.
- **Small on disk.** Only what matching needs is kept (package, affected ranges, fixed versions, ids,
  severity), gzipped in the data folder; malicious-package reports and withdrawn advisories are skipped.
  The first download is about 270 MB in total (npm alone is 220 MB), read as a stream and deleted; daily
  refreshes are a few KB to a few MB. `security-warden vulndb` shows the size of each index.
- **Off switch:** `security-warden vulndb off` stops the daily refresh; `security-warden vulndb update`
  refreshes now. A full archive is fetched again every 30 days.
- **Not covered:** Homebrew (OSV has no Homebrew ecosystem), the host's own OS packages and Docker images.

<details>
<summary>How the score works</summary>

Each check weighs by severity (critical 10, high 6, medium 3, low 1). The score is the weighted share of
checks that pass, each rule counted once however many places it fires. The worst open problem caps it:
25 while anything critical remains, 50 with three or more high problems, 75 with one or two. Every finding
shows how many points fixing it earns.
</details>

## Web UI and security

`start` runs a small web server on `127.0.0.1:7348` (never on `0.0.0.0`) as a LaunchAgent on macOS, a
systemd user service on Linux or a background process on Windows. It rescans every 30 minutes (every 2 hours on battery), notifies
you about new problems, and opens the window for new high or critical ones (at most once an hour).

- **Sign-in:** a passkey, or a one-time ticket the CLI asks for when you run `start` or `open` (valid
  60 seconds, usable once, loopback only). No secret ever appears in a URL or a log.
- **Sessions** last 12 hours and survive restarts (stored hashed). Five failed attempts lock out for 15 minutes.
- **Protected** against cross-site requests and DNS rebinding: Origin and CSRF checks, Host allow-list, strict CSP.
- **Fixes** are built in, never written in rules: tighten file permissions, turn the firewall on, turn the
  guest account off, raise Tailscale shields, upgrade a Homebrew package. Each reversible change is
  journaled for undo. Risky steps (rotating a key) stay written instructions.
- **Hide** a finding for 1, 7 or 30 days, never longer, after a confirmation. Hidden findings stay listed at the bottom with a one-click Show again.

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
never collide with an installed release. Every push also runs security scans of this project: govulncheck and OSV-Scanner (vulnerable dependencies), gitleaks (committed secrets), gosec and CodeQL (code analysis); Dependabot proposes dependency updates. Releases: push a `v*` tag; GitHub Actions builds every platform,
signs and notarizes the `.dmg`, publishes the release and updates `Formula/security-warden.rb` (this
repository is its own Homebrew tap).

## Roadmap

- Signed rule updates without a new release; self-update for direct binary installs.
- Docker image vulnerability scanning.
- An apt/dnf repository, so Linux installs update themselves.
- Real-time process and network events (Endpoint Security on macOS, ETW on Windows).
- Desktop app with a menu bar icon, sharing this web UI.

## Acknowledgements

Ideas on what to check were informed by [bordercheck](https://github.com/ptrinh/bordercheck) (MIT).

- Secret patterns adapted from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT), regenerated weekly by
  [`refresh-lists`](.github/workflows/refresh-lists.yml).
- Container checks follow [Docker Bench for Security](https://github.com/docker/docker-bench-security) (Apache-2.0).
- The list of extensions removed from the VS Marketplace comes from
  [microsoft/vsmarketplace](https://github.com/microsoft/vsmarketplace) (MIT), regenerated weekly.
- Flagged browser extensions are read from Chromium's own extension preferences (blocklist state).
- Some macOS checks follow the [macOS Security Compliance Project](https://github.com/usnistgov/macos_security) (CC BY 4.0).
- Vulnerability data comes from [OSV](https://osv.dev) ([data sources and licenses](https://google.github.io/osv.dev/data/)):
  the [GitHub Advisory Database](https://github.com/github/advisory-database) (CC BY 4.0), the
  [PyPI Advisory Database](https://github.com/pypa/advisory-database) (CC BY 4.0), the
  [Python Software Foundation Database](https://github.com/psf/advisory-database) (CC BY 4.0), the
  [Go Vulnerability Database](https://github.com/golang/vulndb) (CC BY 4.0) and the
  [RustSec Advisory Database](https://github.com/rustsec/advisory-db) (CC0 1.0). It is downloaded at run time and
  reduced to package names, version ranges, ids and severity; it is not shipped with Security Warden.

## License

[Apache License 2.0](LICENSE). Rules you contribute are under the same license.
