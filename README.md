<div align="center">

# 🛡️ Security Warden

**What doors does your machine leave open, and which secrets are lying around?**

[![Release](https://img.shields.io/github/v/release/The-Last-Devops/security-warden)](https://github.com/The-Last-Devops/security-warden/releases/latest)
![Platforms](https://img.shields.io/badge/macOS%20·%20Linux%20·%20Windows-555)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Rules](https://img.shields.io/badge/rules-168-0b6e52)

</div>

Antivirus looks for malware. Security Warden looks for the mistakes we make ourselves: a dev server
listening on every network, a Docker port open to `0.0.0.0`, a tunnel left running, an SSH key without a
passphrase, a token in plain text. It explains each problem and how to fix it, in English or Vietnamese.

- **Local only.** Scanning only reads, and nothing about your machine is ever sent anywhere. The only network use
  is a daily check for a new release on GitHub and public vulnerability data from [OSV](https://osv.dev)
  ([details](docs/security-model.md#network-access)).
- **You stay in control.** Nothing changes until you press Fix, and every fix can be undone.
- **Always watching.** Runs in the background and tells you when something new appears.
- **Lightweight.** One self-contained ~20 MB program with nothing else to install. About 25 MB of memory and no CPU while it waits; a full scan takes 3–6 seconds. The vulnerability data is a one-time ~270 MB download (then a few MB a day) that keeps a 3 MB index.

## Quick start

Copy the one line for your system. It installs Security Warden, starts it in the background and opens it in
your browser.

**macOS** (Homebrew)

```sh
brew tap the-last-devops/security-warden https://github.com/The-Last-Devops/security-warden && brew trust the-last-devops/security-warden && brew install security-warden && security-warden start
```

**Ubuntu, Debian**

```sh
wget -qO /tmp/security-warden.deb https://github.com/The-Last-Devops/security-warden/releases/latest/download/security-warden_$(dpkg --print-architecture).deb && sudo apt install -y /tmp/security-warden.deb && security-warden start
```

**Fedora, RHEL**

```sh
sudo dnf install -y https://github.com/The-Last-Devops/security-warden/releases/latest/download/security-warden-$(uname -m).rpm && security-warden start
```

**Windows** (PowerShell)

```powershell
iwr https://github.com/The-Last-Devops/security-warden/releases/latest/download/security-warden-windows-amd64.exe -OutFile "$env:LOCALAPPDATA\security-warden.exe"; & "$env:LOCALAPPDATA\security-warden.exe" start
```

Your browser opens on Security Warden, already signed in. The first time, it asks you to add a passkey
(Touch ID, Windows Hello or a security key). After that, `security-warden open` brings it back: no link or
password to remember.

## Install

| Method | How |
|---|---|
| **Homebrew** (macOS, Linux) | See [Quick start](#quick-start). Updates itself. |
| **macOS disk image** | `security-warden-<version>-macos.dmg` from [Releases](https://github.com/The-Last-Devops/security-warden/releases/latest), then double-click `Install.command`. Signed and notarized. |
| **Debian, Ubuntu** | `sudo apt install ./security-warden_*.deb` |
| **Fedora, RHEL, openSUSE** | `sudo rpm -i security-warden-*.rpm` |
| **Binary** (macOS, Linux, Windows) | From [Releases](https://github.com/The-Last-Devops/security-warden/releases/latest), checked against `SHA256SUMS` |
| **From source** | `docker build --target export --output dist .` (needs only Docker) |

Details, updating and uninstalling: [docs/install.md](docs/install.md).

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
| `security-warden mcp` | MCP server for AI agents (read-only; `--allow-changes` to allow fixes). See [docs/mcp.md](docs/mcp.md) |
| `security-warden rules` | List every rule (`sources`, `new`, `check` for [writing rules](docs/contributing-rules.md)) |

Add `--lang vi` or `--lang en` to any command, or `--json` to the scan (the scope and category
filters apply to the JSON too).

## Use with AI agents

`security-warden --json` gives structured findings with explanations and exact fix steps. Scanning is
read-only and safe to run without asking; every change (`fix`, `ignore`, fix commands) should wait for
the user's yes.

- **Agent guide**: [docs/ai-agents.md](docs/ai-agents.md) covers commands, exit codes, the JSON fields and a workflow.
- **MCP server**: [docs/mcp.md](docs/mcp.md).
- **Claude Code skill**: copy [`skills/security-warden`](skills/security-warden) into `~/.claude/skills/` (or your project's `.claude/skills/`).
- **Changing this repository with an agent**: [AGENTS.md](AGENTS.md).

## What it checks

168 rules over 36 sources: leaked secrets and keys, open ports and tunnels, Docker, system settings, login
items, AI agent configs, developer tools, out-of-date software and vulnerable dependencies, on macOS,
Linux and Windows. Nothing needs root or opens a permission prompt, and secret values are never shown,
stored or sent. Full list: [docs/what-it-checks.md](docs/what-it-checks.md). How the web UI is protected
and what goes over the network: [docs/security-model.md](docs/security-model.md). All docs:
[docs/](docs/README.md).

## Contributing

New checks are one YAML file each, and people and AI agents are both welcome to send them. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) and [Contributing a rule](docs/contributing-rules.md); every pull request
is reviewed and merged by hand ([review guide](docs/review-guide.md)).
A wrong finding or a missing check? `security-warden feedback RULE|KEY` or `feedback --idea "…"` prints a
GitHub issue link with identifying details taken out; nothing is sent until you submit it yourself.
Contributed rules are credited in [CONTRIBUTORS.md](CONTRIBUTORS.md).

## License

[Apache License 2.0](LICENSE). Rules you contribute are under the same license.

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
