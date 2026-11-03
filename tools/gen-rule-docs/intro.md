# What it checks

{{rules}} rules over {{sources}} sources. Nothing needs root, nothing opens a permission prompt, and protected folders
(Documents, Desktop, Downloads, Mail, Safari…) are never read. Secret values are never shown, stored or
sent: findings name only the file, the variable or the kind of secret.

Each rule is a YAML file in [`rules/`](../rules); see [Writing rules](writing-rules.md) to add one.

## Overview

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

## Vulnerable dependencies

Dependencies pinned in the lock files of your code folders (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
`requirements*.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.mod`, `Cargo.lock`, `Gemfile.lock`) are
matched against a local copy of the [OSV](https://osv.dev) database for npm, PyPI, Go, crates.io and RubyGems.
Findings are grouped per repository, name the worst package, its advisories and the release that fixes it,
and give the upgrade command for that package manager.

- **Offline matching.** A scan never touches the network; with no data yet, these checks show as skipped.
  How and when the data is downloaded is in [Security model](security-model.md#network-access).
- **Small on disk.** Only what matching needs is kept (package, affected ranges, fixed versions, ids,
  severity), gzipped in the data folder; malicious-package reports and withdrawn advisories are skipped.
  `security-warden vulndb` shows the size of each index.
- **Not covered:** Homebrew (OSV has no Homebrew ecosystem), the host's own OS packages and Docker images.

## How the score works

Each check weighs by severity (critical 10, high 6, medium 3, low 1). The score is the weighted share of
checks that pass, each rule counted once however many places it fires. The worst open problem sets a
ceiling: 25 while anything critical remains, 50 with three or more high problems, 75 with one or two. The
share of passing checks is scaled to that ceiling, so every fix still moves the score. Every finding shows
how many points fixing it earns.

The report shows two more scores: one for the machine itself and one for the code on it (the
`code_secrets` and `code_deps` categories), so problems in old repositories do not hide how the machine
is doing.
