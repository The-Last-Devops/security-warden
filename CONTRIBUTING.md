# Contributing

Thank you for helping. People and AI agents are both welcome to open pull
requests; every one is reviewed and merged by hand by the maintainer.

- **A new check (rule):** [docs/contributing-rules.md](docs/contributing-rules.md). Most
  contributions are one YAML file, checked with `security-warden rules check`; no Go needed.
- **Code changes** (sources, fixes, web UI, MCP): read [AGENTS.md](AGENTS.md) and
  [docs/development.md](docs/development.md). Build and test with Docker only:
  `docker compose run --rm web && docker compose run --rm test`.
- **Bugs and ideas:** open an issue with a template. A rule you would like but cannot write:
  the "Rule request" template.
- **Security problems in Security Warden itself:** report them privately in
  [security advisories](https://github.com/The-Last-Devops/security-warden/security/advisories/new),
  not in an issue.

Written with an AI agent? Say so in the pull request (the template has a box). It does not
change how the PR is reviewed, but reviewers read it with that in mind.

How pull requests are reviewed: [docs/review-guide.md](docs/review-guide.md). Contributions are
under the [Apache License 2.0](LICENSE).
