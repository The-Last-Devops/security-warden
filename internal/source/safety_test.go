package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Collectors must stay silent: no admin dialogs, no keychain or privacy
// prompts, no changes. These commands are known to prompt or need root, so
// no source file may call them.
func TestNoPromptingCommands(t *testing.T) {
	banned := []string{`"sfltool"`, `"tccutil"`, `"profiles"`, `"systemsetup"`, `"bputil"`, `"firmwarepasswd"`,
		`"find-generic-password"`, `"find-internet-password"`, `"dump-keychain"`, `"nvram", "-p"`, `"sudo", "-v"`}
	// Folders protected by macOS privacy controls (TCC).
	tcc := []string{`"Documents"`, `"Desktop"`, `"Downloads"`, `"Library/Mail"`, `"Library/Messages"`, `"Library/Safari"`, `"Library/Mobile Documents"`}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, s := range append(banned, tcc...) {
			if strings.Contains(string(b), s) {
				t.Errorf("%s uses %s, which can prompt the user or needs root", f, s)
			}
		}
	}
}

func TestParseHostsAndProxy(t *testing.T) {
	hs := parseHosts("127.0.0.1 localhost\n10.0.0.5 github.com api.example.dev\n0.0.0.0 ads.example.com\n# 1.2.3.4 pypi.org\n")
	var gh Item
	for _, h := range hs {
		if h["name"] == "github.com" {
			gh = h
		}
	}
	if gh == nil || gh["high_value"] != true || gh["blocks"] != false {
		t.Errorf("github.com override not flagged: %v", hs)
	}
	if len(hs) != 3 {
		t.Errorf("want 3 host entries (comment and localhost skipped), got %d", len(hs))
	}
	ps := parseScutilProxy("<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : proxy.corp.example\n  HTTPPort : 8080\n  SOCKSEnable : 0\n}")
	if len(ps) != 1 || ps[0]["loopback"] != false || ps[0]["port"] != 8080 {
		t.Errorf("proxy parse: %v", ps)
	}
}

func TestLiteralSecret(t *testing.T) {
	if !isLiteralSecret("GITHUB_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Error("github token not detected")
	}
	for _, v := range []string{"${GITHUB_TOKEN}", "$TOKEN", "your-token-here", ""} {
		if isLiteralSecret("API_KEY", v) {
			t.Errorf("%q taken for a secret", v)
		}
	}
	if !literalValue(`"s3cr3t-value-123"`) || literalValue(`"$(op read op://x)"`) {
		t.Error("literalValue")
	}
}
