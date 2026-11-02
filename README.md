# security-warden

A security checkup for work machines (macOS first, Windows later):

- **Posture**: audits security settings (FileVault/BitLocker, firewall, updates…).
- **Exposure**: finds doors open to the outside: listening ports, Docker, Tailscale, tunnels, remote desktop.
- **Secrets**: finds secrets left lying around (SSH keys, `.env`, `~/.aws`, kubeconfig…).

Engine and CLI in Go. Rules are declarative YAML + CEL, contributed by the community.
The app is multilingual: every user-facing string goes through translations.

Status: early design, no code yet.
