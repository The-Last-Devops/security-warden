---
name: security-warden-rule-author
description: Write a new Security Warden rule (YAML + CEL) with tests and open a pull request for it. Use when the user wants to add a check to Security Warden, cover a security gap it misses, or contribute a rule to https://github.com/The-Last-Devops/security-warden.
---

# Write a Security Warden rule

A rule is one YAML file in `rules/`: a CEL expression over the facts a source
already collects, texts in English and Vietnamese, and sample items as tests.
Rules cannot run code. The risk is in the fix text, which people paste into a
terminal, so it must be safe. Full guide:
https://github.com/The-Last-Devops/security-warden/blob/main/docs/contributing-rules.md

Merging is always done by hand by the maintainer. Your job ends at an open,
passing pull request that says it was written with AI.

## Steps

1. **Find the gap.** Read `docs/what-it-checks.md` and run
   `security-warden rules` to be sure no rule covers it already. Note what can
   go wrong and find a reference (vendor docs, CIS/NIST benchmark, advisory).
2. **Find the facts.** `security-warden rules sources` lists every source with
   its fields; `security-warden rules sources NAME` shows one, with types and
   example values (also in `docs/rule-sources.md`). If no source has the facts,
   stop and tell the user: a new field is a Go change in `internal/source/`,
   not a rule (see AGENTS.md).
3. **Start the file** from a fork and a branch:

   ```sh
   gh repo fork The-Last-Devops/security-warden --clone && cd security-warden
   git switch -c rule/<id>
   security-warden rules new <id> --source <source> --severity medium
   ```

   It writes `rules/<id>.yaml` with `tier: experimental`, every field, `TODO`
   texts and two tests. Keep the tier: new rules always start experimental.
4. **Write the rule.** `match` returns true for the risky state only; guard
   optional fields with `has(item.x)`. Write `title`, `check` (the passing
   state, no placeholders), `explain` and `fix` in plain English and natural
   Vietnamese (not word for word). Tests: at least one realistic sample that
   must report and one that must not, each with every field the match and
   texts use; add a `note` for edge cases. `author` is the user's GitHub
   handle without `@` (ask them); the rule is credited to them as "by @handle"
   and in `CONTRIBUTORS.md`.
5. **Fix text safety.** Verified commands only, in `` `backticks` ``,
   multi-step as `1. … 2. …`. Never pipe a download to a shell, `rm -rf`,
   `chmod 777`, turn off a security feature, force-push or rewrite Git history
   without saying what it does. Say when admin rights (sudo) are needed; back
   up a file in `/etc` before editing it; never lock the user out. For leaked
   secrets, rotating the secret comes first.
6. **Check it** until there is nothing left to fix:

   ```sh
   security-warden rules check --strict --new rules/<id>.yaml
   ```

   If Docker is available, also run `docker compose run --rm test` and
   `docker compose run --rm docs` (it regenerates `docs/what-it-checks.md` and
   `CONTRIBUTORS.md`; commit those files too).
7. **Open the pull request.** Touch only the rule file (and the regenerated
   docs). Commit, push, and create the PR with the template filled in:

   ```sh
   git add rules/<id>.yaml docs/what-it-checks.md
   git commit -m "Rule <id>: <one line>"
   git push -u origin rule/<id>
   gh pr create --repo The-Last-Devops/security-warden --title "Rule <id>: <one line>" --body-file pr.md
   ```

   `pr.md` is `.github/PULL_REQUEST_TEMPLATE.md` filled in (keep it out of the commit): the gap, references,
   the `rules check` output, the systems the fix commands were tested on, and
   **the AI authorship box ticked with the tool and model**. Do not hide that
   an AI wrote it.
8. Tell the user the PR link and that a maintainer reviews and merges it by
   hand. Do not ask anyone to merge it, and do not open the PR without the
   user's go-ahead.
