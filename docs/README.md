# Security Warden docs

| Page | What |
|---|---|
| [Install](install.md) | Every way to install, update and uninstall, and where data lives |
| [What it checks](what-it-checks.md) | Every rule by category, vulnerability data and how the score works (generated from `rules/`) |
| [Security model](security-model.md) | How the web UI is protected, what is stored, what goes over the network, fixes and undo |
| [Using from AI agents](ai-agents.md) | Commands, exit codes, the JSON output and a workflow for agents |
| [MCP server](mcp.md) | Security Warden as an MCP server for AI agents |
| [Writing rules](writing-rules.md) | Rule format, CEL, fix text, tests, tiers, remedies, adding a source |
| [Rule sources](rule-sources.md) | Every source and the fields a rule can use (generated from the source schema) |
| [Contributing a rule](contributing-rules.md) | Step by step from a gap to a pull request, for people and AI agents |
| [Review guide](review-guide.md) | The maintainer's checklist, tier promotion, repository settings |
| [Development](development.md) | Building and testing in Docker, CI, releases, roadmap |

Also: the [Claude Code skill](../skills/security-warden/SKILL.md), the
[rule-author skill](../skills/security-warden-rule-author/SKILL.md) and [AGENTS.md](../AGENTS.md) for
agents changing this repository.
