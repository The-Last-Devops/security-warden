# Contributing a rule

A rule is one YAML file in [`rules/`](../rules). It reads facts that a source already collected,
through a [CEL](https://cel.dev) expression, and cannot run commands or open files, so a rule cannot
harm anyone's machine. What can do harm is its **fix text**: people copy those commands into a
terminal. That is what review looks at hardest.

You need only the `security-warden` binary ([install](install.md)): the commands below read the
rules and sources built into it. These steps are the same for people and for AI agents; agents can
also use the ready-made skill [`skills/security-warden-rule-author`](../skills/security-warden-rule-author/SKILL.md).

## Not ready to write a rule?

Reports help too. If a finding is wrong (a false positive, or a fix that does not work), or a check is
missing:

```sh
security-warden feedback RULE|KEY             # a wrong finding or fix (KEY from security-warden --verbose)
security-warden feedback --idea "check ~/.npmrc for auth tokens in plain text"
```

Each prints a GitHub "new issue" link with the form filled in, and the exact text it fills in. The home
folder, user and host names, repositories and code paths, emails, IP addresses and anything that looks
like a token are taken out first. Nothing is sent: you open the link (or add `--open`), read and edit
the text, and submit it yourself. The web UI has the same as "Report a false positive" in an opened
finding and "Suggest a new check" at the end of the list; MCP clients have `report_false_positive` and
`suggest_rule`.

## 1. Find a gap

Look through [What it checks](what-it-checks.md) or `security-warden rules`, and make sure no rule
already covers what you have in mind. A good rule finds a state that is risky on a real work machine,
rarely fires on a machine that is fine, and has a clear, safe fix. Keep a reference handy (vendor
docs, a CIS or NIST benchmark, an advisory).

## 2. Find the facts

```sh
security-warden rules sources              # every source: category, platforms, fields
security-warden rules sources tailscale    # one source: each field with its type, meaning and an example
```

The same list is in [Rule sources](rule-sources.md). A rule can use only these fields. If the facts
you need are not collected, the rule needs a code change in a source first: open a
[rule request](https://github.com/The-Last-Devops/security-warden/issues/new/choose) or see
[Adding a source](writing-rules.md#adding-a-source).

## 3. Start the file

```sh
security-warden rules new tailscale-example --source tailscale --severity medium
```

This writes `rules/tailscale-example.yaml` with every field filled with a placeholder: `tier:
experimental`, English and Vietnamese texts marked `TODO`, `author` (your GitHub handle, without `@`),
and two tests built from the source's fields. Options: `--platforms macos,linux` (default: where the source runs), `--dir DIR` (default
`rules`). It never overwrites a file, and the id must be kebab-case.

## 4. Write the rule

Follow [Writing rules](writing-rules.md):

- `match`: true for the risky state only. Guard optional fields with `has(item.x)`.
- `title` (the problem, usually ending in the place), `check` (the passing state, no placeholders),
  `explain` (why it matters, in plain words) and `fix`, each in `en` and `vi`. Write Vietnamese as a
  native speaker would, not word for word.
- `fix`: commands in `` `backticks` ``, steps as `1. … 2. …`, verified commands only, nothing
  destructive, say when admin rights are needed. See [Fix text](writing-rules.md#fix-text).
- `tests`: realistic samples, at least one that must report and one that must not.
- `references`: where the risk and the fix are documented.
- `author`: your GitHub handle, without `@`. Contributed rules show "by @handle" (linking to your
  profile) in the terminal, the web UI and the MCP server, and you are listed in
  [CONTRIBUTORS.md](../CONTRIBUTORS.md), generated from these fields.
- Keep `tier: experimental`. The maintainer promotes it after review ([Tiers](writing-rules.md#tiers)).

## 5. Check it

```sh
security-warden rules check --strict --new rules/tailscale-example.yaml
```

It loads the file exactly as the scanner does and reports, with the file and the field:

- **Errors** (exit 1): unknown fields, bad severity or platforms, a missing translation, CEL that does
  not compile or is not boolean, failing tests, placeholders left unfilled, fields that the source
  does not have (or with the wrong type), platforms the source does not run on, unbalanced
  `` ` `` or `{ }`, `TODO` left in a text, an `author` that is not a GitHub handle.
- **Warnings** (exit 0, or 1 with `--strict`): the fix-text safety lint (below), a Vietnamese text
  identical to the English one, and with `--new` a tier other than `experimental` or no `author`.

| Lint code | Flags a command that |
|---|---|
| `lint.pipe_to_shell` | pipes a download into a shell (`curl … \| sh`) |
| `lint.rm_rf` | deletes recursively and by force |
| `lint.chmod_777` | makes files writable by everyone |
| `lint.disable_security` | turns off a security feature (Gatekeeper, SIP, SELinux, a firewall, Defender) |
| `lint.sudo_unannounced` | uses `sudo` while the text never says admin rights are needed |
| `lint.etc_no_backup` | writes to `/etc` without a backup step |
| `lint.force_push` | force-pushes to a Git remote |
| `lint.history_rewrite_no_warning` | rewrites Git history without warning what that means |

`--json` prints the same results for scripts. Building from source is optional; if you have Docker,
`docker compose run --rm test` runs every check CI runs, and `docker compose run --rm docs` updates
[What it checks](what-it-checks.md) and [CONTRIBUTORS.md](../CONTRIBUTORS.md) (commit them with the rule).

## 6. Open a pull request

Fork the repository, commit only your rule file (and the regenerated docs) on a branch, and open a
pull request. Fill in the template: the gap, the references, the `rules check` output, the systems
you tested the fix commands on.

A workflow runs `rules check --strict` on every rule file the PR adds or changes and posts the result
as a comment. It labels the PR `rule`, `ai-generated` when it looks written by an agent, and
`needs-careful-review` when the lint flags a command or a fix text changed. It never merges anything.

## AI-written pull requests

Welcome. Two conditions:

1. **Say so.** Tick the AI box in the template and name the tool and model. A PR that hides it will be
   closed.
2. **It passes `rules check --strict`.** A person should still read the whole diff before opening it.

## What reviewers look for

The maintainer's checklist is in [Review guide](review-guide.md). In short: does it catch a real risk,
how often would it fire on a machine that is fine, is the severity right, is every fix command safe
and correct, are both languages good, and do the tests show the edges. **Merging is always manual**;
nothing is merged automatically.
