# Working on Security Warden

Guide for AI coding agents (and people) changing this repository. For *using*
Security Warden from an agent, see [docs/ai-agents.md](docs/ai-agents.md).

## What it is

A local security checkup for work machines (macOS, Linux, Windows). One Go
binary: it collects facts from the machine, evaluates YAML + CEL rules on them,
and reports problems with explanations and fixes, in a terminal report, as JSON,
or in a small web UI (Vue) served on `127.0.0.1:7348`.

## Layout

| Path | What |
|---|---|
| `cmd/security-warden/` | CLI: commands, flags, background service (`serve`), updates |
| `internal/source/` | Collectors. Each returns `[]Item` (flat `map[string]any`) for one source name; registered in `source.go` `All()`; slow ones in `Slow` |
| `internal/engine/` | Rule loading/validation, CEL evaluation, scoring, placeholder rendering (`Render`, `RenderFix`, `ShellQuote`) |
| `rules/*.yaml` | The checks: one file per rule, embedded into the binary |
| `internal/report/` | Categories and scopes (`category.go`), terminal report (`text.go`, `textreport.go`, `fixtext.go`) |
| `internal/fix/` | Built-in fix actions (allow-listed, journaled, undoable). Rules name an action; they never carry commands to run |
| `internal/web/` | HTTP server, auth (passkeys, one-time tickets, sessions, CSRF), JSON API for the UI |
| `internal/i18n/catalog.go` | Every user-facing string of the Go side, in `en` and `vi` |
| `internal/vulndb/` | Offline OSV vulnerability index for project dependencies |
| `web/src/` | Vue 3 + Tailwind UI (`App.vue`, `components/`, `i18n.js`) |
| `tools/` | Generators for embedded data (gitleaks patterns, removed VS Code extensions) |
| `packaging/`, `scripts/`, `Formula/` | .deb/.rpm, .dmg, Homebrew formula (updated by the release workflow) |

## Build and test (Docker only, nothing to install on the host)

```sh
docker compose run --rm web     # build the web UI into web/dist (needed before Go builds)
docker compose run --rm test    # gofmt gate, go vet for linux/darwin/windows, all tests incl. every rule's samples
docker compose run --rm build   # ./dist/security-warden for this machine
./dist/security-warden --json   # a real scan (exit 1 just means findings)
```

Development builds use port 7349 and their own data folder, so they never touch
an installed release.

## Adding or changing a rule

1. If the facts already exist in a source, write only `rules/<id>.yaml`. Copy an
   existing rule (for example `rules/backup-none.yaml`): `id`, `severity`
   (critical/high/medium/low), `platforms`, `source`, `match` (CEL over `item`),
   and `title`, `check` (the passing state), `explain`, `fix`, each in `en` and `vi`.
2. `tests`: at least one item that must match and one that must not, each with
   every field the `match` uses. CI runs them all.
3. `{field}` placeholders come from the item. In `fix`, wrap commands, paths and
   config keys in `` `backticks` `` and number multi-step fixes `1. … 2. …`;
   the UI and the terminal render steps and copyable commands from that. Values
   inside a command are shell-quoted automatically.
4. Need new facts? Add fields to a collector (or a new source), plus a label
   `source.<name>` in `internal/i18n/catalog.go` (en and vi) and a category in
   `internal/report/category.go`.

## Hard rules (tests enforce most of them)

- **Read-only, silent scans.** Collectors never change anything, never need root,
  and never trigger a permission prompt. `internal/source/safety_test.go` bans
  prompting commands and protected folders (Documents, Desktop, Downloads, Mail,
  other apps' containers). No network during a scan.
- **Never store or print secret values.** Items carry names, paths, kinds and
  counts only. Values from the machine are attacker-controlled text: they go
  through `engine.Clean`, and through `ShellQuote` inside commands.
- **Fix text must be safe to follow.** Verified commands only, nothing
  destructive, never lock the user out (test sshd config, keep the session, add
  the new SSH key before removing the old one), say when admin is needed.
- **Every user-facing string exists in en and vi.** Go strings in the catalog,
  UI strings in `web/src/i18n.js`.
- **Every feature ships on all three surfaces: web UI, CLI and MCP.** A new
  feature (or a change to one) lands in the web UI, the terminal commands and
  the MCP server (`security-warden mcp`) in the same change. MCP tools that
  change the machine are only offered with `--allow-changes`.
- Keep dependencies minimal; no new module without a strong reason.

## Releases

Push a `v*` tag: GitHub Actions builds every platform, signs and notarizes the
macOS disk image, builds .deb/.rpm, publishes the release, updates the Homebrew
formula, then installs the release on macOS, Ubuntu, Debian and Fedora to check
it. Security scans (govulncheck, OSV-Scanner, gitleaks, gosec, CodeQL) run on
every push.
