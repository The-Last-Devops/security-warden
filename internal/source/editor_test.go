package source

import (
	"encoding/json"
	"testing"
)

func TestStripJSONC(t *testing.T) {
	in := `{
	// comment
	"a.b": false, /* block */
	"url": "http://x//y", "s": "say \"/*hi*/\"",
	"n": {"c": [1, 2,],},
}`
	var m map[string]any
	if err := json.Unmarshal(stripJSONC([]byte(in)), &m); err != nil {
		t.Fatalf("%v: %s", err, stripJSONC([]byte(in)))
	}
	if m["url"] != "http://x//y" || m["s"] != `say "/*hi*/"` {
		t.Errorf("strings changed: %v", m)
	}
	if setting(m, "a.b") != false {
		t.Error("flat key")
	}
}

func TestSettingNested(t *testing.T) {
	m := map[string]any{"security": map[string]any{"workspace.trust": map[string]any{"enabled": false}}}
	if setting(m, "security.workspace.trust.enabled") != false {
		t.Error("nested key")
	}
	if setting(m, "task.allowAutomaticTasks") != nil {
		t.Error("missing key should be nil")
	}
}

func TestWalkSecretsNamesOnly(t *testing.T) {
	var out []string
	walkSecrets("", map[string]any{"rest": map[string]any{"apiToken": "ghp_abcdefghijklmnopqrstuvwxyz0123"}, "theme": "dark"}, &out)
	if len(out) != 1 || out[0] != "rest.apiToken" {
		t.Errorf("got %v", out)
	}
}
