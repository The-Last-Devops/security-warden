package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	home = func() string { return dir }
	JournalPath = func() string { return filepath.Join(dir, "state", "fixes.jsonl") }
	return dir
}

func TestChmodApplyAndUndo(t *testing.T) {
	dir := setup(t)
	f := filepath.Join(dir, ".aws", "credentials")
	os.MkdirAll(filepath.Dir(f), 0o700)
	os.WriteFile(f, []byte("x"), 0o644)

	if err := Apply("b1", "credential-file-readable-by-others", "chmod_private", map[string]string{"path": f}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode after fix = %o", fi.Mode().Perm())
	}
	done, err := UndoLast()
	if err != nil || len(done) != 1 {
		t.Fatalf("undo: %v %v", done, err)
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode after undo = %o", fi.Mode().Perm())
	}
	// A second undo has nothing left to revert.
	if done, _ := UndoLast(); len(done) != 0 {
		t.Fatalf("second undo reverted %d entries", len(done))
	}
}

func TestChmodRefusesOutsideHome(t *testing.T) {
	setup(t)
	for _, p := range []string{"/etc/passwd", "relative/file", "", "/tmp/../etc/hosts"} {
		if err := Apply("b", "r", "chmod_private", map[string]string{"path": p}); err == nil {
			t.Errorf("chmod accepted %q", p)
		}
	}
}

func TestChmodRefusesSymlink(t *testing.T) {
	dir := setup(t)
	link := filepath.Join(dir, "link")
	os.Symlink("/etc/hosts", link)
	if err := Apply("b", "r", "chmod_private", map[string]string{"path": link}); err == nil {
		t.Error("chmod followed a symlink out of home")
	}
}

func TestCommandsAreFixed(t *testing.T) {
	setup(t)
	var ran [][]string
	Runner = func(argv ...string) error { ran = append(ran, argv); return nil }
	if err := Apply("b2", "tailscale-shields-down", "tailscale_shields_up", nil); err != nil {
		t.Fatal(err)
	}
	if err := Apply("b2", "r", "brew_upgrade", map[string]string{"name": "redis; rm -rf ~"}); err == nil {
		t.Error("brew_upgrade accepted a shell injection")
	}
	if len(ran) != 1 || !strings.HasSuffix(ran[0][0], "ailscale") || ran[0][2] != "--shields-up=true" {
		t.Fatalf("unexpected commands: %v", ran)
	}
	UndoLast()
	if len(ran) != 2 || ran[1][2] != "--shields-up=false" {
		t.Fatalf("undo ran: %v", ran)
	}
}
