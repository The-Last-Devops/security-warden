## What and why

<!-- What does this change, and why is it needed? Link the issue if there is one. -->

## Checklist

- [ ] `docker compose run --rm test` passes, or this PR only touches `rules/` and `security-warden rules check --strict` passes
- [ ] User-facing text exists in English and Vietnamese
- [ ] No secret values, real tokens or personal data in code, tests or texts

## AI authorship

- [ ] An AI agent wrote some or all of this PR. Tool and model: <!-- e.g. Claude Code, Opus 5.5 -->
- [ ] I (a person) read the whole diff before opening the PR

<!-- AI-written PRs are welcome. Say so here; it does not change how the PR is reviewed. -->

## For a rule (delete if not a rule)

- Rule id: `...`
- The gap: <!-- what risky state on a real machine this catches, and why no existing rule does -->
- References: <!-- vendor docs, CIS/NIST benchmark, advisory, blog post that show the risk and the fix -->
- Tier: `experimental` (new rules always start here; the maintainer promotes them)
- Fix commands tested on: <!-- macOS 15 / Ubuntu 24.04 / Windows 11 ..., or "no commands" -->

- [ ] Tests have at least one sample that must report and one that must not, with realistic values
- [ ] Fix text: commands are safe to paste, nothing destructive, says when admin rights are needed
- [ ] False positives considered: <!-- when could this fire on a machine that is fine? -->

<details><summary><code>security-warden rules check --strict --new rules/&lt;id&gt;.yaml</code> output</summary>

```
paste here
```

</details>

Merging is done by hand by a maintainer after review.
