---
name: security-warden
description: Check this machine's security with Security Warden - open ports and remote access, leaked keys and tokens, risky settings, Docker, AI agent configs, vulnerable project dependencies - and help fix what it finds. Use when the user asks if their machine or repositories are secure, wants a security checkup, or asks about exposed services, leaked secrets or vulnerable dependencies.
---

# Security Warden

Security Warden (`security-warden`) is a local, read-only security scanner.
Install: `brew tap the-last-devops/security-warden https://github.com/The-Last-Devops/security-warden && brew trust the-last-devops/security-warden && brew install security-warden`
(Linux: .deb/.rpm from the GitHub releases page). Full reference:
https://github.com/The-Last-Devops/security-warden/blob/main/docs/ai-agents.md

## Steps

1. Run the scan; it is safe without asking (read-only, no admin, no network,
   a few seconds). Exit status 1 only means problems were found.

   ```sh
   security-warden --json --lang en
   ```

   Narrow it when the user asks about one area: `--scope machine`,
   `--scope code`, or `--category secrets|exposure|settings|persistence|ai|devtools|software|code_secrets|code_deps`.

2. Summarize for the user: `score_machine` and `score_code` (0–100), then the
   problems grouped by `rule_id`, most severe first (critical, high, medium,
   low), with how many places each has. Keep paths as given; never invent
   values. The output contains no secret values.

3. Propose fixes, most severe first. Quote the `fix` text: backticked parts are
   commands or paths to use exactly, `1. 2.` are steps. Entries with a `remedy`
   can be fixed with `security-warden fix` (it shows a plan and can be undone
   with `security-warden fix --undo`).

4. **Ask before changing anything.** Do not run `security-warden fix`, commands
   from `fix` texts, `ignore add`, `passkey clear` or `logout` until the user
   says yes. For leaked keys or tokens, tell the user to revoke or rotate the
   credential first; deleting the file is not enough.

5. After changes, scan again and report what improved.

If the user says a finding is wrong, or asks about a risk that is not checked,
you may offer once to report it: `security-warden feedback <rule_id or key>` or
`security-warden feedback --idea "what to check and why"`. It only prints a
preview (identifying details already taken out) and a GitHub link. Show the
preview; the user opens the link and submits it. Never open, post or submit it
yourself. To write the rule with them, use the `security-warden-rule-author`
skill.

To hide a problem the user accepts for now: `security-warden ignore add <rule_id or key> --days 7`
(1, 7 or 30 days; `ignore restore` shows it again). Mention `ignored`
findings only if asked.
