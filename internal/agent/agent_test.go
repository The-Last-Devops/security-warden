package agent

import (
	"strings"
	"testing"
)

func TestPlistEscapesAndRunsWatch(t *testing.T) {
	p := Plist("/Users/a&b/bin/security-warden", "vi", "/Users/a&b/Library/Logs/sw.log")
	for _, want := range []string{"<string>/Users/a&amp;b/bin/security-warden</string>", "<string>watch</string>", "<string>vi</string>", "<key>KeepAlive</key><true/>"} {
		if !strings.Contains(p, want) {
			t.Errorf("plist missing %q", want)
		}
	}
	if strings.Contains(p, "a&b") {
		t.Error("unescaped ampersand in plist")
	}
}

func TestUnitQuotesBinary(t *testing.T) {
	u := Unit("/home/a b/security-warden", "")
	if !strings.Contains(u, `ExecStart="/home/a b/security-warden" watch`) {
		t.Errorf("unit: %s", u)
	}
}
