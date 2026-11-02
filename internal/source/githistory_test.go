package source

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDeletedSecretFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	write := func(name, body string) {
		p := filepath.Join(repo, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q")
	write(".env", "TOKEN=x\n")
	write("config/prod.env", "A=b\n")
	write("certs/ca.pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	write("deploy/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbg==\n-----END OPENSSH PRIVATE KEY-----\n")
	write(".env.example", "TOKEN=\n")
	write("node_modules/pkg/.env", "X=1\n")
	write("README.md", "hi\n")
	run("add", "-A")
	run("commit", "-q", "-m", "one")
	run("rm", "-q", ".env", "certs/ca.pem", "deploy/id_rsa", ".env.example", "node_modules/pkg/.env")
	run("mv", "config/prod.env", "config/prod.env.bak")
	run("commit", "-q", "-m", "two")
	// Re-added later: dev_files reports it, not the history check.
	write(".env", "TOKEN=y\n")
	run("add", ".env")
	run("commit", "-q", "-m", "three")

	got := map[string]bool{}
	files, complete := deletedSecretFiles(context.Background(), repo)
	if !complete {
		t.Error("history read not complete")
	}
	for _, f := range files {
		got[f] = true
	}
	it := historyItem(context.Background(), repo)
	if it == nil || it["count"] != 2 || it["file"] != "config/prod.env" {
		t.Errorf("item: %v", it)
	}
	// A linked worktree shares the history of its main repo.
	wt := filepath.Join(t.TempDir(), "wt")
	run("worktree", "add", "-q", wt)
	if got := historyRepos([]string{wt, repo}); len(got) != 1 || got[0] != repo {
		t.Errorf("worktree not folded into its repo: %v", got)
	}
	for _, f := range []string{".env", "config/prod.env", "deploy/id_rsa"} {
		if !got[f] {
			t.Errorf("%s not found in history: %v", f, got)
		}
	}
	for _, f := range []string{"certs/ca.pem", ".env.example", "node_modules/pkg/.env", "README.md"} {
		if got[f] {
			t.Errorf("%s should not be reported: %v", f, got)
		}
	}
	tracked, _ := gitStatus(context.Background(), repo, []string{".env", "deploy/id_rsa"})
	if !tracked[".env"] || tracked["deploy/id_rsa"] {
		t.Errorf("tracked: %v", tracked)
	}
}
