package source

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// gitAvailable reports whether a real git exists. On macOS /usr/bin/git is
// a shim that opens the "install developer tools" dialog when the Command
// Line Tools are missing, so ask xcode-select first (it never prompts).
var gitAvailable = sync.OnceValue(func() bool {
	if _, err := exec.LookPath("git"); err != nil {
		return false
	}
	if runtime.GOOS == "darwin" {
		if p, err := exec.LookPath("git"); err == nil && p == "/usr/bin/git" {
			return exec.Command("xcode-select", "-p").Run() == nil
		}
	}
	return true
})

// gitSafe runs git so that a repository we did not create cannot run code
// through its own config: no fsmonitor, no hooks, no system or global
// config, no prompts, no locks, and a short timeout.
func gitSafe(ctx context.Context, repo string, stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	full := []string{"--no-optional-locks",
		"-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
		"-c", "core.hooksPath=/dev/null", "-c", "protocol.allow=never",
		"-C", repo}
	cmd := exec.CommandContext(ctx, "git", append(full, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_ASKPASS=/bin/false")
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd.Output()
}

// gitStatus tells, for files of one repo (paths relative to it), which are
// tracked and which are ignored, with two git calls in total.
func gitStatus(ctx context.Context, repo string, files []string) (tracked, ignored map[string]bool) {
	tracked, ignored = map[string]bool{}, map[string]bool{}
	in := []byte(strings.Join(files, "\x00") + "\x00")
	if out, err := gitSafe(ctx, repo, nil, append([]string{"ls-files", "-z", "--cached", "--"}, files...)...); err == nil {
		for _, f := range strings.Split(string(out), "\x00") {
			if f != "" {
				tracked[f] = true
			}
		}
	}
	// check-ignore exits 1 when nothing is ignored; the output still counts.
	out, _ := gitSafe(ctx, repo, in, "check-ignore", "-z", "--stdin", "--no-index")
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			ignored[f] = true
		}
	}
	return tracked, ignored
}
