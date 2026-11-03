# Writing rules

Each check is one YAML file in [`rules/`](../rules), embedded into the binary. A rule can only read the
facts a source collected, through a [CEL](https://cel.dev) expression: it can never run commands or open
files, so a contributed rule cannot harm the machine.

The quickest start is `security-warden rules new <id> --source <source>`, which writes a skeleton with
every field, or copying a rule close to what you need, for example
[`rules/backup-none.yaml`](../rules/backup-none.yaml). `security-warden rules check <file>` then checks it
the way CI does. Step by step, including the pull request: [Contributing a rule](contributing-rules.md).

## A complete rule

```yaml
id: credential-file-readable-by-others
severity: high
platforms: [macos, linux]
source: credential_files
match: item.plaintext_secret && (item.group_readable || item.world_readable)
title:
  en: "Credential file readable by other users: {path}"
  vi: "Người dùng khác đọc được file đăng nhập: {path}"
check:
  en: "Credential files are private"
  vi: "File đăng nhập được giữ kín"
explain:
  en: "{path} ({kind}) holds a secret in plain text and has mode {mode}."
  vi: "{path} ({kind}) chứa secret dạng chữ thường và đang có quyền {mode}."
fix:
  en: "Press Fix to do it automatically, or run: `chmod 600 {path}`"
  vi: "Bấm Sửa để tự sửa, hoặc chạy: `chmod 600 {path}`"
author: the-last-devops
tests:
  - {item: {kind: aws, path: /h/.aws/credentials, mode: "0644", plaintext_secret: true, group_readable: true, world_readable: true}, expect: true}
  - {item: {kind: aws, path: /h/.aws/credentials, mode: "0600", plaintext_secret: true, group_readable: false, world_readable: false}, expect: false}
  - {item: {kind: docker, path: /h/.docker/config.json, mode: "0644", plaintext_secret: false, group_readable: true, world_readable: true}, expect: false, note: uses a credential store}
remedy: {action: chmod_private, params: {path: "{path}"}}
```

## Fields

Unknown fields are an error, so a typo fails loading instead of being ignored.

| Field | Required | What |
|---|---|---|
| `id` | yes | Unique, kebab-case (`a-z`, `0-9`, `-`). Name the file `<id>.yaml`. |
| `severity` | yes | `critical`, `high`, `medium` or `low` (`info` exists but weighs nothing). It sets the score weight (10, 6, 3, 1). |
| `tier` | no | `stable` (default), `community` or `experimental`. See [Tiers](#tiers). |
| `platforms` | yes | Where the rule applies: any of `macos`, `linux`, `windows`. |
| `source` | yes | The collector whose items the rule reads, e.g. `credential_files`. The source also sets the category. |
| `match` | yes | CEL expression over `item`; must return a boolean. True means "report this item". |
| `title` | yes | The problem, one line, usually ending with the place: `…: {path}`. |
| `check` | yes | The check stated positively, shown in the list of what passes. No placeholders. |
| `explain` | yes | Why it matters, in plain words. |
| `fix` | yes | How to fix it. See [Fix text](#fix-text). |
| `references` | no | Links for further reading. |
| `author` | no | Who wrote the rule. |
| `tests` | yes | Sample items with the expected result. See [Tests](#tests). |
| `remedy` | no | A built-in fix action. See [Remedies](#remedies). |

`title`, `check`, `explain` and `fix` must each have a non-empty text in every supported language: `en`
and `vi`. Write the Vietnamese as a native speaker would say it, not word for word.

## Match expressions

`item` is one fact the source collected: a flat map of fields. `security-warden rules sources <source>`
lists a source's fields with their types and example values (also in [Rule sources](rule-sources.md)); a
rule may use only those fields. Examples from real rules:

```yaml
match: "!item.configured"                                          # a boolean field
match: "item.image_age_days > 180"                                 # numbers
match: "item.kind in [\"password_flag\", \"bearer\", \"url_with_password\"]"   # one of several values
match: item.kind == "packages" && item.security <= 0 && item.total >= 10 && item.total < 50
match: has(item.firewall) && !item.firewall && !item.container     # a field that may be missing
```

- A missing field is an error, not false. Guard optional fields with `has(item.x)`.
- Quote the whole expression in YAML when it starts with `!` or contains `: `.
- Each rule has a cost limit, so an expression cannot slow down a scan.

## Placeholders

`{field}` in `title`, `explain` and `fix` is replaced by that field of the item, for example `{path}`.
Placeholders not in the item are left as they are, and the tests fail when a matching sample leaves one
unfilled. Values are cleaned before printing: control characters and bidi overrides are shown escaped.

## Fix text

Fix texts use light markup that the terminal report and the web UI both read:

- **`` `backticks` ``** mark a command, path or config key exactly as it must be typed. Code with a space
  is a command and gets its own line with a copy button; code without a space (a path, a key) stays inline.
- **Numbered steps.** A text that starts with `1. ` is a list of steps: `1. … 2. … 3. …` on one line.
- **Automatic shell quoting.** Inside backticks every placeholder is shell-quoted, so
  `` `chmod 600 {path}` `` stays one safe command even for a file named `a b; rm -rf ~`. A backtick inside
  a value becomes `'`, so a value can never end or start a command.
- **`{field|sh}`** shell-quotes a value outside backticks too.
- Fields that hold whole commands Security Warden assembled itself, already quoted (`upgrade_cmd`,
  `upgrade_command`, `why`), are not quoted again; `stop_cmd` may carry its own markup.

```yaml
fix:
  en: "1. Set up short-lived logins: `aws configure sso`. 2. Check it works: `aws sts get-caller-identity --profile <new profile>`. 3. Deactivate the old key first, which can be undone: `aws iam update-access-key --access-key-id <key id> --status Inactive`. 4. When nothing has broken for a few days, delete the key and remove it from `{path}`."
```

Fix text must be safe to follow: verified commands only, nothing destructive, never lock the user out
(test an sshd config before reloading, add the new SSH key before removing the old one), and say when
admin rights are needed. Leaked secrets are fixed by rotating them, not only by deleting the file.

## Tests

Every rule needs at least one sample that must be reported (`expect: true`) and one that must not
(`expect: false`). Give each sample every field the `match` and the texts use; `note` says why a sample
is there.

```yaml
tests:
  - {item: {path: /h/.aws/credentials, aws_long_term_key: true}, expect: true}
  - {item: {path: /h/.aws/credentials, aws_long_term_key: false}, expect: false}
```

Check a rule with the installed binary alone:

```sh
security-warden rules check --strict rules/<id>.yaml    # add --new for a rule you are adding
```

It loads the file exactly as the scanner does (fields, translations, CEL, remedies), runs every sample,
checks that no placeholder stays unfilled, that every field exists in the source with the right type,
and lints the fix text for unsafe commands ([the lint codes](contributing-rules.md#5-check-it)). The Go
tests run the same checks on every rule; in Docker:

```sh
docker compose run --rm test
```

Then regenerate the rule list in [What it checks](what-it-checks.md); CI fails when it is stale:

```sh
docker compose run --rm docs     # or: go run ./tools/gen-rule-docs/main.go
```

To see a rule on your own machine, build with `docker compose run --rm build` and run
`./dist/security-warden --verbose`.

## Tiers

| Tier | Runs by default | Score | Label | Who |
|---|---|---|---|---|
| `experimental` | No: only with `--experimental`, MCP `experimental: true` or the web UI's "Show experimental checks" | Never counted | "experimental" | Every new contributed rule starts here |
| `community` | Yes | Counted | "community" | Contributed rules the maintainer reviewed and promoted |
| `stable` (default) | Yes | Counted | none | Rules the project maintains |

Experimental rules are always loaded and their tests run in CI, so they cannot break anything; they are
just not evaluated unless asked. The tier also appears as `tier` on each finding in the JSON. Promotion
is a maintainer pull request that changes `tier:`; a rule goes back to `experimental` when it reports
false positives. See the [Review guide](review-guide.md#promoting-a-rule).

## Remedies

A remedy lets Fix change something for the user. Rules never carry commands: a rule names one of the
built-in actions in [`internal/fix/`](../internal/fix), and each action is allowed only with certain
sources, with each parameter filled from exactly one item field. Anything else fails loading.

| Action | Sources | Params |
|---|---|---|
| `chmod_private` | `credential_files`, `ssh_keys`, `authorized_keys` | `path: "{path}"` |
| `brew_upgrade` | `outdated_software` | `name: "{name}"` |
| `brew_upgrade_all` | `outdated_software` | none |
| `macos_firewall_on`, `macos_stealth_on`, `macos_gatekeeper_on`, `macos_guest_off`, `macos_airdrop_contacts` | `posture` | none |
| `tailscale_shields_up`, `tailscale_ssh_off` | `tailscale` | none |

Keep a manual `fix` text as well: it is shown next to the Fix button and is the only fix when the action
cannot run. A new action is a code change in `internal/fix/` (validated input, a dry-run plan, and undo
when possible), not a rule change.

## Adding a source

When no source collects the facts you need, add fields to an existing collector or a new source in
[`internal/source/`](../internal/source): register it in `All()` in `source.go` (and in `Slow` if it walks
files or calls a package manager), add its label `source.<name>` in `internal/i18n/catalog.go` (en and
vi), and its category in `internal/report/category.go`. Collectors must stay read-only, silent and offline,
and never keep secret values. [AGENTS.md](../AGENTS.md) has the full list of rules every change must keep.
