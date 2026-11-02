package source

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// editors: VS Code and its forks share the settings and extension layout.
var editors = []struct{ name, config, ext string }{
	{"VS Code", "Code", ".vscode"},
	{"VS Code Insiders", "Code - Insiders", ".vscode-insiders"},
	{"VSCodium", "VSCodium", ".vscode-oss"},
	{"Cursor", "Cursor", ".cursor"},
	{"Windsurf", "Windsurf", ".windsurf"},
}

// editorSettings reads each editor's user settings.json. It records which
// protections are off and the names of settings holding literal secrets,
// never their values.
func editorSettings(ctx context.Context) ([]Item, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return nil, nil
	}
	var items []Item
	for _, e := range editors {
		file := filepath.Join(cfg, e.config, "User", "settings.json")
		b, err := readSmallN(file, 4<<20)
		if err != nil {
			continue
		}
		var m map[string]any
		if json.Unmarshal(stripJSONC(b), &m) != nil {
			continue
		}
		var secrets []string
		kinds := map[string]bool{}
		walkSecrets("", m, &secrets, kinds)
		sort.Strings(secrets)
		items = append(items, Item{
			"editor":                e.name,
			"file":                  file,
			"workspace_trust_off":   setting(m, "security.workspace.trust.enabled") == false,
			"untrusted_files_open":  setting(m, "security.workspace.trust.untrustedFiles") == "open",
			"auto_tasks_on":         setting(m, "task.allowAutomaticTasks") == "on",
			"proxy_strict_ssl_off":  setting(m, "http.proxyStrictSSL") == false,
			"extension_updates_off": setting(m, "extensions.autoUpdate") == false,
			"secret_settings":       strings.Join(secrets, ", "),
			"secret_kinds":          joinSet(kinds),
			"has_secret":            len(secrets) > 0,
		})
	}
	return items, nil
}

// editorExtensions lists installed extensions: whether they came from a
// .vsix file (nobody reviewed them and they never update), and why the
// Marketplace removed them, if it did (removedextensions_gen.go).
func editorExtensions(ctx context.Context) ([]Item, error) {
	var items []Item
	for _, e := range editors {
		file := filepath.Join(home(), e.ext, "extensions", "extensions.json")
		b, err := readSmallN(file, 8<<20)
		if err != nil {
			continue
		}
		var list []struct {
			Identifier struct {
				ID string `json:"id"`
			} `json:"identifier"`
			Version  string `json:"version"`
			Metadata struct {
				Source string `json:"source"`
			} `json:"metadata"`
		}
		if json.Unmarshal(b, &list) != nil {
			continue
		}
		for _, x := range list {
			if x.Identifier.ID == "" {
				continue
			}
			items = append(items, Item{"editor": e.name, "extension": x.Identifier.ID, "version": x.Version,
				"from_file":    x.Metadata.Source == "vsix",
				"removed_type": removedExtensions[strings.ToLower(x.Identifier.ID)]})
		}
	}
	return items, nil
}

// setting looks a key up flat ("a.b.c": v) or nested ({"a": {"b": ...}}).
func setting(m map[string]any, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	parts := strings.Split(key, ".")
	for i := len(parts) - 1; i > 0; i-- {
		if sub, ok := m[strings.Join(parts[:i], ".")].(map[string]any); ok {
			if v := setting(sub, strings.Join(parts[i:], ".")); v != nil {
				return v
			}
		}
	}
	return nil
}

// walkSecrets collects the paths of settings holding literal secrets, and
// the gitleaks rule ids of the token formats found.
func walkSecrets(path string, v any, out *[]string, kinds map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			p := k
			if path != "" {
				p = path + "." + k
			}
			walkSecrets(p, val, out, kinds)
		}
	case []any:
		for _, val := range x {
			walkSecrets(path, val, out, kinds)
		}
	case string:
		key := path[strings.LastIndex(path, ".")+1:]
		ok, kind := literalSecret(key, x)
		if !ok {
			return
		}
		if kind != "" {
			kinds[kind] = true
		}
		if !contains(*out, path) {
			*out = append(*out, path)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// stripJSONC turns VS Code's JSON-with-comments into plain JSON: comments
// and trailing commas go, strings stay untouched.
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				i++
				out = append(out, b[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++
		case c == '}' || c == ']':
			j := len(out) - 1
			for j >= 0 && strings.ContainsRune(" \t\r\n", rune(out[j])) {
				j--
			}
			if j >= 0 && out[j] == ',' {
				out = append(out[:j], out[j+1:]...)
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
