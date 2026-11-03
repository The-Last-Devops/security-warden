# Review guide

For the maintainer reviewing pull requests. Nothing is merged automatically: every PR is read and
merged by hand.

## Every pull request

- CI is green (`build` in ci.yml, `rules-check` for rule files).
- The diff does only what it says. Watch for changes outside the stated scope, above all in
  `.github/`, `internal/fix/`, `internal/web/`, the install scripts and `go.mod`.
- AI-written: the template says so and names the tool. Read it as carefully as any other PR; agents
  write confident text that can be wrong.
- No secret values, real tokens or personal data in code, tests or texts.

## Rule pull requests

Read the bot's comment first, then the YAML.

1. **Real risk.** The rule finds a state that matters on a work machine, and `references` back it
   (vendor docs, CIS/NIST, an advisory). No reference, no merge.
2. **False positives.** When would it fire on a machine that is fine? Rules that cry wolf teach people
   to ignore the report. If unsure, keep it `experimental` longer.
3. **Severity.** critical: a secret or full access is exposed now; high: an open door others can use;
   medium: a weakened default; low: hygiene. It sets the score weight (10, 6, 3, 1).
4. **Fix text safety.** Run every command in a throwaway VM or container on each platform it claims.
   The lint flags the obvious cases; you still read every command:
   - `lint.pipe_to_shell`, `lint.rm_rf`, `lint.chmod_777`, `lint.disable_security`: almost never
     acceptable in a fix.
   - `lint.sudo_unannounced`: the text must say admin rights are needed.
   - `lint.etc_no_backup`: back up first (`sudo cp /etc/x /etc/x.bak`) or use a safe editor (`visudo`).
   - `lint.force_push`, `lint.history_rewrite_no_warning`: only with a clear warning, and after the
     secret was rotated.
   - Never lock the user out: test sshd configs, keep the session, add a new key before removing the
     old one. Leaked secrets: rotate first.
   - A built-in exception for an existing rule goes in the allowlist in `internal/fixlint`, with a reason.
5. **Translations.** English plain and short; Vietnamese natural, not word for word. `check` states
   the passing state and has no placeholders.
6. **Tests.** Realistic values, at least one positive and one negative, and the edges the `match`
   cares about (missing optional field, boundary numbers).
7. **Tier.** New rules arrive as `experimental`. Merge them that way.

## Promoting a rule

Tiers are described in [Writing rules](writing-rules.md#tiers).

- **experimental → community**: after the rule has been tried (run `security-warden --experimental`
  on a few real machines, macOS, Linux and Windows as it claims) with no false positives and fixes
  that work. Open a PR that changes `tier: community` and regenerates the docs
  (`docker compose run --rm docs`). From then on it runs by default, counts in the score and is
  labeled "community".
- **community → stable**: when the project takes over its maintenance. Change `tier: stable` (or
  remove the line).
- **Back down**: when false positives are reported, move the rule back to `experimental` in a patch
  release.

## Repository settings to enable by hand

These cannot be set from a pull request. Without them, `CODEOWNERS` is only a hint.

**Protect `main`**: Settings → Rules → Rulesets → New ruleset → New branch ruleset:

1. Name `main`, Enforcement status **Active**, Target branches → Add target → **Include default branch**.
2. Bypass list: leave **empty**.
3. Turn on:
   - **Restrict deletions**
   - **Require a pull request before merging**: Required approvals **1**, **Dismiss stale pull request
     approvals when new commits are pushed**, **Require review from Code Owners**, **Require
     conversation resolution before merging**
   - **Require status checks to pass**: add `build` (ci.yml) and `rules-check` (rules-pr.yml). Do not
     tick "Require branches to be up to date" unless you want to rebase every PR.
   - **Block force pushes**
4. Create.

(Classic alternative: Settings → Branches → Add branch protection rule for `main` with the same boxes,
plus "Do not allow bypassing the above settings".)

**Actions**: Settings → Actions → General:

- Fork pull request workflows from outside collaborators: **Require approval for all external
  contributors**.
- Workflow permissions: **Read repository contents and packages permissions**; leave **Allow GitHub
  Actions to create and approve pull requests** off.

**Merging**: Settings → General → Pull Requests: leave **Allow auto-merge** off.

**Labels**: `rules-pr-comment.yml` creates `rule`, `ai-generated` and `needs-careful-review` the first
time it needs them. To create them up front:

```sh
gh label create rule --color 0b6e52 --description "Adds or changes a rule"
gh label create ai-generated --color 8250df --description "Written with an AI agent"
gh label create needs-careful-review --color d93f0b --description "Fix commands to check by hand"
```
