package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v0.2.1", "v0.2.0", true}, {"v0.10.0", "v0.9.9", true}, {"v1.0.0", "v0.99.0", true},
		{"v0.2.0", "v0.2.0", false}, {"v0.1.9", "v0.2.0", false}, {"v9.9.9", "dev", false},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%s, %s) = %v", c.latest, c.current, got)
		}
	}
}

// fakeBrew installs a fake Homebrew in a temp prefix: <prefix>/bin/brew logs
// its arguments, and "upgrade" switches the linked binary in
// <prefix>/opt/security-warden/bin to newVersion (empty: upgrade does nothing,
// the bug where brew had not refreshed the tap).
func fakeBrew(t *testing.T, oldVersion, newVersion string, failOn string) (logFile string) {
	t.Helper()
	prefix := t.TempDir()
	logFile = filepath.Join(prefix, "brew.log")
	verFile := filepath.Join(prefix, "version")
	mustWrite(t, verFile, oldVersion, 0o644)
	mustWrite(t, filepath.Join(prefix, "opt", "security-warden", "bin", "security-warden"),
		"#!/bin/sh\ncat '"+verFile+"'\n", 0o755)
	script := "#!/bin/sh\necho \"$@\" >> '" + logFile + "'\n"
	if failOn != "" {
		script += "[ \"$1\" = " + failOn + " ] && { echo 'Error: boom' >&2; exit 1; }\n"
	}
	if newVersion != "" {
		script += "[ \"$1\" = upgrade ] && printf '%s' '" + newVersion + "' > '" + verFile + "'\n"
	}
	script += "exit 0\n"
	mustWrite(t, filepath.Join(prefix, "bin", "brew"), script, 0o755)
	old := brewPath
	brewPath = func() string { return filepath.Join(prefix, "bin", "brew") }
	t.Cleanup(func() { brewPath = old })
	return logFile
}

func mustWrite(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeBrewRefreshesTapFirst(t *testing.T) {
	log := fakeBrew(t, "v0.2.5", "v0.2.6", "")
	got, err := UpgradeBrew(context.Background(), "v0.2.5")
	if err != nil || got != "v0.2.6" {
		t.Fatalf("got %q, %v", got, err)
	}
	b, _ := os.ReadFile(log)
	if string(b) != "update --quiet\nupgrade security-warden\n" {
		t.Errorf("brew calls:\n%s", b)
	}
}

func TestUpgradeBrewReportsNothingInstalled(t *testing.T) {
	fakeBrew(t, "v0.2.5", "", "")
	got, err := UpgradeBrew(context.Background(), "v0.2.5")
	if !errors.Is(err, ErrNotUpdated) || got != "v0.2.5" {
		t.Fatalf("a no-op upgrade must not count as success: %q, %v", got, err)
	}
}

func TestUpgradeBrewStopsOnBrewError(t *testing.T) {
	log := fakeBrew(t, "v0.2.5", "v0.2.6", "update")
	if _, err := UpgradeBrew(context.Background(), "v0.2.5"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want brew's error, got %v", err)
	}
	if b, _ := os.ReadFile(log); strings.Contains(string(b), "upgrade") {
		t.Error("upgrade ran after update failed")
	}
}

func TestUpgradeBrewWithoutBrew(t *testing.T) {
	old := brewPath
	brewPath = func() string { return "" }
	defer func() { brewPath = old }()
	if _, err := UpgradeBrew(context.Background(), "v0.2.5"); err == nil {
		t.Fatal("want an error without brew")
	}
}
