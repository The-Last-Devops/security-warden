package source

import (
	"encoding/json"
	"strings"
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
	walkSecrets("", map[string]any{"rest": map[string]any{"apiToken": "ghp_abcdefghijklmnopqrstuvwxyz0123"}, "theme": "dark"}, &out, map[string]bool{})
	if len(out) != 1 || out[0] != "rest.apiToken" {
		t.Errorf("got %v", out)
	}
}

func TestExtensionBlocklisted(t *testing.T) {
	n := func(v int) *int { return &v }
	cases := []struct {
		s    extSetting
		want string
	}{
		{extSetting{}, ""},
		{extSetting{BlocklistState: n(0)}, ""},
		{extSetting{BlocklistState: n(1)}, "malware"},
		{extSetting{BlocklistState: n(2)}, "security_vulnerability"},
		{extSetting{TelemetryState: n(3)}, "policy_violation"},
		{extSetting{OmahaState: n(8)}, "potentially_unwanted"},
		{extSetting{BlocklistState: n(2), OmahaState: n(1)}, "malware"},
		{extSetting{BlocklistState: n(5)}, ""}, // unknown is never stored
	}
	for _, c := range cases {
		if got := c.s.blocklisted(); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.s, got, c.want)
		}
	}
}

func TestRemovedExtensionsList(t *testing.T) {
	if len(removedExtensions) < 1000 {
		t.Fatalf("only %d removed extensions", len(removedExtensions))
	}
	for id, k := range removedExtensions {
		if id != strings.ToLower(id) || !strings.Contains(id, ".") {
			t.Errorf("bad id %q", id)
		}
		switch k {
		case "Malware", "Impersonation", "Untrustworthy", "Expired domain":
		default:
			t.Errorf("%s: unexpected type %q", id, k)
		}
	}
}
