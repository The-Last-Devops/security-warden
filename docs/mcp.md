# MCP server

`security-warden mcp` lets AI apps (Claude Desktop, Claude Code, Cursor and any
other [Model Context Protocol](https://modelcontextprotocol.io) client) use
Security Warden as a set of tools: scan the machine, list the problems, explain
how to fix them, and, only if you allow it, apply the built-in fixes.

The app starts the command itself and talks to it over stdin/stdout (JSON-RPC
2.0, one message per line). Nothing listens on the network.

## Safety model

- **Read-only by default.** Without flags the server offers only tools that
  read: `scan`, `list_problems`, `get_fix`, `explain_rule`, `list_safe`,
  `status`, `scan_log`, `list_sources`, `check_rule`, `draft_rule`, `report_false_positive`, `suggest_rule`.
  They are marked `readOnlyHint: true`. A scan needs no admin rights,
  opens no permission prompt and sends nothing off the machine (3–6 seconds).
- **Changes are opt-in.** `apply_fix`, `undo_fix`, `hide` and `restore` exist
  only when the server is started with `--allow-changes`; otherwise they are not
  listed and calling them is refused. They are marked `destructiveHint: true`,
  and their descriptions tell the model to show the user what will change and
  wait for a yes.
- **Never admin.** `apply_fix` runs the same allow-listed, journaled actions as
  `security-warden fix --yes`, for the findings you name only (a rule or keys,
  never "everything"). Fixes that need admin rights (a password prompt) are
  refused with the reason; run `security-warden fix` in a terminal for those.
  Undoable fixes can be reverted with `undo_fix` (or `security-warden fix --undo`).
- **Hiding is temporary.** `hide` takes 1, 7 or 30 days; nothing is hidden for good.
- **No secret values.** Results carry names, paths, kinds and counts, never the
  secrets themselves. Paths and titles come from the machine: the model should
  treat them as untrusted text.
- **Leaked secrets: rotate first.** The server instructions and `get_fix` remind
  the model that revoking or rotating a leaked key is the real fix; deleting a
  file or cleaning Git history alone does not make it safe again.
- **Feedback is a link, never a request.** `report_false_positive` and `suggest_rule` only build a
  GitHub new-issue link plus a preview of exactly what it fills in, with the home folder, user and host
  names, repositories and code paths, emails, IP addresses and token-shaped strings taken out. The
  server makes no network call; the tool result tells the model to show the preview and let the user
  open and submit the link. The first `scan` or `get_fix` with findings in a session ends with one line
  saying this is possible; later calls do not repeat it.
- **stdout carries only protocol messages.** Logs go to stderr.

## Tools

Every tool returns `structuredContent` (JSON) plus a short text summary in
`content[0].text`. `lang` (`en` or `vi`, default `en`) sets the language of rule
texts. Scope is `machine` or `code`; categories are `secrets`, `exposure`,
`settings`, `persistence`, `ai`, `devtools`, `software`, `other`,
`code_secrets`, `code_deps`. `experimental: true` (on `scan`, `list_problems`,
`list_safe` and `get_fix`) also evaluates experimental rules, which are off by
default and never counted in the score ([tiers](writing-rules.md#tiers)).

### Read-only (always on)

| Tool | Arguments | Returns |
|---|---|---|
| `scan` | `scope?`, `category?`, `lang?`, `refresh?`, `experimental?` | Scores (overall, machine, code), counts by severity, problems grouped by rule, worst first: `rule_id`, `severity`, `title`, `places`, `gain`, `has_auto_fix`; plus skipped sources. The scan is cached for 60 s; `refresh: true` scans again. |
| `list_problems` | `scope?`, `category?`, `severity_at_least?` (`critical`/`high`/`medium`/`low`), `limit?` (1–1000, default 100), `lang?`, `experimental?` | One entry per place: `key`, `rule_id`, `severity`, `title`, `place`, `category`, `has_auto_fix`. |
| `get_fix` | `rule_id`, `lang?`, `experimental?` | `explain`, parsed `steps` (`text` with short code inline, `commands` to run), the commands for each place when they differ, and `remedy` (built-in fix: action, plan, needs admin, undoable, how to apply it). |
| `explain_rule` | `rule_id`, `lang?` | Rule metadata whether failing or not: severity, platforms, category, `check`, `explain`, `fix` template, remedy, and its state in the last scan. |
| `list_safe` | `scope?`, `category?`, `lang?`, `experimental?` | Checks that pass. |
| `list_sources` | `name?`, `lang?` | Every source a rule can read (or one): category, platforms, fields with type, description and an example value. Same as `security-warden rules sources`. |
| `check_rule` | `yaml` (the rule file's content), `new?` (a rule you are adding: must be `experimental`), `lang?` | Checks a rule without writing it anywhere, like `security-warden rules check`: `ok`, `rule_id`, `tier`, `tests` (`passed`, `total`), `errors` and `warnings` (each `field`, `code`, `message`; `lint.*` codes flag unsafe fix commands). See [Contributing a rule](contributing-rules.md). |
| `status` | none | Version, background service running, vulnerability data age per ecosystem, whether changes are allowed, age of the cached scan. |
| `scan_log` | none | The scan log: when each scan ran, and which checks failed, timed out or were slow, with the commands they waited on. Same as `security-warden logs` and Settings → Scan log in the web UI. |
| `draft_rule` | `id`, `source`, `severity?`, `idea?` | The skeleton of a new rule (`yaml`, the same as `security-warden rules new`, with the idea as a comment), the `path` it belongs at and `next_steps` (fill in the TODOs, `check_rule` with `new: true`, a pull request the maintainers merge by hand). Writes nothing. |
| `report_false_positive` | `key` or `rule_id`, `experimental?` | A GitHub issue draft for a wrong finding or fix: `preview` (the exact, scrubbed text), `url` (a new-issue link with the form filled in), `instructions`. For a rule that does not fail here, the draft is about the rule itself. Sends nothing. |
| `suggest_rule` | `idea` | The same for a new check: a rule request from the idea, scrubbed, marked as drafted by an AI agent. Sends nothing. |

### Changing (only with `--allow-changes`)

| Tool | Arguments | What it does |
|---|---|---|
| `apply_fix` | `rule_id?`, `keys?` (at least one) | Applies the built-in fixes for those findings only; lists what ran, what was refused (no built-in fix, needs admin) and what failed. |
| `undo_fix` | none | Reverts the most recent batch of fixes. |
| `hide` | `rule_id` or `key`, `days` (1, 7 or 30) | Hides the problem for that long. |
| `restore` | `rule_id`, `key` or `all: true` | Shows hidden problems again. |

Keys come from `list_problems` (any unique prefix of 6+ characters works).

`explain_rule` and `get_fix` name the author of a contributed rule (`author`, and "Contributed by
@handle" in the text); rules by the maintainers carry no credit line.

## Prompts

Ready-made instructions the client can offer its user (`prompts/list`, `prompts/get`):

| Prompt | Arguments | What it asks the agent to do |
|---|---|---|
| `security-checkup` | `scope?` (`machine` or `code`) | Scan, summarize by severity, explain the worst problems with `get_fix`, propose fixes and change nothing without a yes; offer to report a wrong finding or a missing check. |
| `contribute-rule` | `idea?` | Write a rule with the user: check no rule covers it, find the facts (`list_sources`), start with `draft_rule`, fill in every TODO (author = their GitHub handle), pass `check_rule` with `new: true`, ask before writing files, open a pull request that discloses AI authorship. Merging is always manual. |

## Set it up

Install Security Warden first (Homebrew, .deb/.rpm or the release binary).
Desktop apps do not always see your shell's `PATH`, so their configs below use
the full path: find it with `which security-warden` (Homebrew on Apple silicon:
`/opt/homebrew/bin/security-warden`).

### Claude Code

```sh
claude mcp add --transport stdio --scope user security-warden -- security-warden mcp
```

Drop `--scope user` to add it to the current project only. Check with
`claude mcp list`, or `/mcp` inside a session.

### Claude Desktop

Settings → Developer → Edit Config opens `claude_desktop_config.json`
(macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`,
Windows: `%APPDATA%\Claude\claude_desktop_config.json`). Add:

```json
{
  "mcpServers": {
    "security-warden": {
      "command": "/opt/homebrew/bin/security-warden",
      "args": ["mcp"]
    }
  }
}
```

Restart Claude Desktop.

### Cursor

`~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` in a project:

```json
{
  "mcpServers": {
    "security-warden": {
      "command": "/opt/homebrew/bin/security-warden",
      "args": ["mcp"]
    }
  }
}
```

### Any other stdio client

Command `security-warden`, arguments `["mcp"]`, transport stdio. To try it by
hand:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan","arguments":{}}}' \
  | security-warden mcp
```

Responses may arrive in any order; match them by `id`.

## Allowing changes

> **Warning.** With `--allow-changes` the AI app can change file permissions,
> toggle settings, run `brew upgrade` and hide problems on your behalf. Use it
> only in an app that asks you before every tool call, and read each request
> before you approve it. Admin-level fixes stay refused either way.

Add `--allow-changes` after `mcp`:

```sh
claude mcp add --transport stdio --scope user security-warden -- security-warden mcp --allow-changes
```

```json
{
  "mcpServers": {
    "security-warden": {
      "command": "/opt/homebrew/bin/security-warden",
      "args": ["mcp", "--allow-changes"]
    }
  }
}
```

## Protocol details

- Protocol versions: `2026-07-28` (per-request `_meta`, `server/discover`) and
  the `initialize` handshake of `2025-11-25`, `2025-06-18`, `2025-03-26` and
  `2024-11-05`.
- Methods: `initialize`, `notifications/initialized`, `server/discover`,
  `ping`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get`, `notifications/cancelled`.
  Capabilities: `tools` and `prompts` (both `listChanged: false`).
- Errors: unknown method `-32601`; unparsable JSON `-32700`; invalid request
  (wrong `jsonrpc`, bad `id`, batches) `-32600`; unknown or disabled tool, bad
  params, unknown prompt `-32602`; unsupported protocol version `-32022`. Problems the model can
  correct (bad argument values, a rule that is not failing) come back as a tool
  result with `isError: true`.
