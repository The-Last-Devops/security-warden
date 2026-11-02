package source

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	secretKeyName = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|auth|credential|private[_-]?key|access[_-]?key)`)
	tokenShape    = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|npm_[A-Za-z0-9]{36})\b|Bearer\s+[A-Za-z0-9._-]{20,}`)
)

type mcpServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

// aiAgents reads AI coding agent and MCP configs. It records which keys
// hold literal secrets and which safety prompts are turned off; values are
// classified in memory and dropped.
func aiAgents(ctx context.Context) ([]Item, error) {
	h := home()
	var items []Item

	mcpFiles := []struct{ tool, path, key string }{
		{"Claude Code", filepath.Join(h, ".claude.json"), "mcpServers"},
		{"Claude Desktop", filepath.Join(h, "Library/Application Support/Claude/claude_desktop_config.json"), "mcpServers"},
		{"Claude Desktop", filepath.Join(h, ".config/Claude/claude_desktop_config.json"), "mcpServers"},
		{"Cursor", filepath.Join(h, ".cursor/mcp.json"), "mcpServers"},
		{"Windsurf", filepath.Join(h, ".codeium/windsurf/mcp_config.json"), "mcpServers"},
		{"VS Code", filepath.Join(h, "Library/Application Support/Code/User/mcp.json"), "servers"},
		{"VS Code", filepath.Join(h, ".config/Code/User/mcp.json"), "servers"},
		{"Gemini CLI", filepath.Join(h, ".gemini/settings.json"), "mcpServers"},
	}
	for _, f := range mcpFiles {
		b, err := readSmallN(f.path, 8<<20)
		if err != nil {
			continue
		}
		var root map[string]json.RawMessage
		if json.Unmarshal(b, &root) != nil {
			continue
		}
		groups := []json.RawMessage{root[f.key]}
		// Claude Code also keeps per-project servers.
		if projects, ok := root["projects"]; ok {
			var ps map[string]map[string]json.RawMessage
			if json.Unmarshal(projects, &ps) == nil {
				for _, p := range ps {
					groups = append(groups, p["mcpServers"])
				}
			}
		}
		for _, g := range groups {
			var servers map[string]mcpServer
			if len(g) == 0 || json.Unmarshal(g, &servers) != nil {
				continue
			}
			for name, s := range servers {
				var keys []string
				for k, v := range s.Env {
					if isLiteralSecret(k, v) {
						keys = append(keys, k)
					}
				}
				for k, v := range s.Headers {
					if isLiteralSecret(k, v) {
						keys = append(keys, k)
					}
				}
				sort.Strings(keys)
				inArgs := tokenShape.MatchString(strings.Join(s.Args, " ")) || tokenShape.MatchString(s.URL)
				unpinned := false
				if filepath.Base(s.Command) == "npx" {
					for _, a := range s.Args {
						if !strings.HasPrefix(a, "-") {
							unpinned = !strings.Contains(strings.TrimPrefix(a, "@"), "@") || strings.HasSuffix(a, "@latest")
							break
						}
					}
				}
				items = append(items, Item{
					"kind": "mcp", "tool": f.tool, "file": f.path, "server": name,
					"secret_keys":    strings.Join(keys, ", "),
					"has_secret":     len(keys) > 0 || inArgs,
					"plain_http":     strings.HasPrefix(s.URL, "http://") && !strings.Contains(s.URL, "localhost") && !strings.Contains(s.URL, "127.0.0.1"),
					"unpinned_npx":   unpinned,
					"world_readable": worldReadable(f.path),
				})
			}
		}
	}

	// Safety switches that let an agent run commands without asking.
	add := func(tool, file, setting string) {
		items = append(items, Item{"kind": "auto_approve", "tool": tool, "file": file, "setting": setting,
			"has_secret": false, "plain_http": false, "unpinned_npx": false, "world_readable": false})
	}
	claude := filepath.Join(h, ".claude/settings.json")
	if b, err := readSmall(claude); err == nil {
		var s struct {
			Permissions struct {
				DefaultMode string   `json:"defaultMode"`
				Allow       []string `json:"allow"`
			} `json:"permissions"`
			SkipDangerous   bool `json:"skipDangerousModePermissionPrompt"`
			EnableAllProjMC bool `json:"enableAllProjectMcpServers"`
		}
		if json.Unmarshal(b, &s) == nil {
			if s.Permissions.DefaultMode == "bypassPermissions" || s.SkipDangerous {
				add("Claude Code", claude, "bypassPermissions")
			}
			for _, a := range s.Permissions.Allow {
				if a == "Bash" || a == "Bash(*)" || a == "Bash(*:*)" {
					add("Claude Code", claude, "allow "+a)
					break
				}
			}
			if s.EnableAllProjMC {
				add("Claude Code", claude, "enableAllProjectMcpServers")
			}
		}
	}
	codex := filepath.Join(h, ".codex/config.toml")
	if b, err := readSmall(codex); err == nil {
		s := string(b)
		if regexp.MustCompile(`(?m)^\s*approval_policy\s*=\s*"never"`).MatchString(s) &&
			regexp.MustCompile(`(?m)^\s*sandbox_mode\s*=\s*"danger-full-access"`).MatchString(s) {
			add("Codex", codex, `approval_policy = "never" + danger-full-access`)
		}
	}
	for _, vs := range []string{
		filepath.Join(h, "Library/Application Support/Code/User/settings.json"),
		filepath.Join(h, ".config/Code/User/settings.json"),
		filepath.Join(h, "Library/Application Support/Cursor/User/settings.json"),
	} {
		if b, err := readSmall(vs); err == nil {
			s := string(b)
			if regexp.MustCompile(`"chat\.tools\.(global\.)?autoApprove"\s*:\s*true`).MatchString(s) {
				add("VS Code", vs, "chat.tools.autoApprove")
			}
		}
	}
	return items, nil
}

func isLiteralSecret(key, val string) bool {
	if val == "" || strings.Contains(val, "${") || strings.HasPrefix(val, "$") {
		return false
	}
	if tokenShape.MatchString(val) {
		return true
	}
	return secretKeyName.MatchString(key) && len(val) >= 12 && !strings.ContainsAny(val, " /") && !looksPlaceholder(val)
}

func looksPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, p := range []string{"your", "xxxx", "example", "changeme", "placeholder", "redacted", "<", "dummy", "test"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func worldReadable(path string) bool {
	if fi, err := statFile(path); err == nil {
		return fi.Mode().Perm()&0o004 != 0
	}
	return false
}
