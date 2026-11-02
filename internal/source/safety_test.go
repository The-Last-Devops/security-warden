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
		`"find-generic-password"`, `"find-internet-password"`, `"dump-keychain"`, `"nvram", "-p"`, `"sudo", "-v"`,
		// Package managers: only read the local cache, never refresh or install.
		`"apt-get"`, `"apt", "update"`, `"upgrade"`, `"makecache"`, `"--refresh"`, `"install"`,
		// Windows: tools that change settings, elevate or need an administrator.
		`"reg", "add"`, `"reg", "delete"`, `"manage-bde"`, `"runas"`, `"RunAs"`, `"Set-MpPreference"`, `"Update-MpSignature"`,
		`"schtasks"`, `"netsh"`, `"sc.exe"`, `"bcdedit"`, `"-EncodedCommand"`}
	// Folders protected by macOS privacy controls (TCC).
	tcc := []string{`"Documents"`, `"Desktop"`, `"Downloads"`, `"Library/Mail"`, `"Library/Messages"`, `"Library/Safari"`, `"Library/Mobile Documents"`,
		// Other apps' data: macOS asks "would like to access data from other
		// apps" for anything inside these (seen with Docker Desktop's group).
		`Group Containers`, `Library/Containers`}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "tcc.go" {
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

// dnf refreshes its metadata over the network unless told not to.
func TestDnfCacheOnly(t *testing.T) {
	b, err := os.ReadFile("packages.go")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "dnfRun(ctx, ") {
			n++
			if !strings.Contains(line, `"--cacheonly"`) {
				t.Errorf("dnf call without --cacheonly: %s", strings.TrimSpace(line))
			}
		}
	}
	if n == 0 {
		t.Error("no dnf calls found")
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

func TestReadSmallRefusesFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := mkfifo(fifo); err != nil {
		t.Skip("mkfifo not available:", err)
	}
	if _, err := readSmall(fifo); err == nil {
		t.Error("readSmall read from a FIFO instead of refusing it")
	}
}
