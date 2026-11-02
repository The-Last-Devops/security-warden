// Package update keeps Security Warden current. It asks GitHub which
// release is the latest (reading only the redirect of releases/latest,
// sending nothing about this machine) and, for Homebrew installs, runs
// "brew upgrade security-warden". Other installs are told to update.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/appdir"
)

const latestURL = "https://github.com/The-Last-Devops/security-warden/releases/latest"

var tagRe = regexp.MustCompile(`/releases/tag/(v\d+\.\d+\.\d+)$`)

// Latest returns the newest release tag, e.g. "v0.2.1".
func Latest(ctx context.Context) (string, error) {
	c := http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "HEAD", latestURL, nil)
	req.Header.Set("User-Agent", "security-warden-update-check")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	m := tagRe.FindStringSubmatch(resp.Header.Get("Location"))
	if m == nil {
		return "", errors.New("no release found")
	}
	return m[1], nil
}

func parse(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
		n, _ := strconv.Atoi(strings.TrimFunc(p, func(r rune) bool { return r < '0' || r > '9' }))
		out[i] = n
	}
	return out
}

// Newer reports whether latest is a higher version than current.
func Newer(latest, current string) bool {
	if current == "" || current == "dev" {
		return false
	}
	a, b := parse(latest), parse(current)
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// Method is how this copy was installed: "brew" or "manual".
func Method() string {
	exe, err := os.Executable()
	if err != nil {
		return "manual"
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if strings.Contains(exe, "/Cellar/security-warden/") {
		return "brew"
	}
	return "manual"
}

// StableExecutable is the path to run at login: for Homebrew, the opt
// path that survives upgrades (Cellar/<version> is removed on cleanup).
func StableExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	if i := strings.Index(real, "/Cellar/security-warden/"); i >= 0 {
		opt := real[:i] + "/opt/security-warden/bin/security-warden"
		if _, err := os.Stat(opt); err == nil {
			return opt, nil
		}
	}
	return real, nil
}

func brewBin() string {
	if p, err := exec.LookPath("brew"); err == nil {
		return p
	}
	for _, p := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew", "/home/linuxbrew/.linuxbrew/bin/brew"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ApplyBrew runs brew upgrade for this formula.
func ApplyBrew(ctx context.Context) error {
	b := brewBin()
	if b == "" {
		return errors.New("brew not found")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	env := append(os.Environ(), "HOMEBREW_NO_ENV_HINTS=1", "HOMEBREW_NO_ANALYTICS=1", "HOMEBREW_NO_AUTO_UPDATE=1")
	// Refresh the tap first: without it brew still knows only the old
	// formula and "upgrade" quietly does nothing.
	for _, args := range [][]string{{"update", "--quiet"}, {"upgrade", "security-warden"}} {
		cmd := exec.CommandContext(ctx, b, args...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("brew %s: %v: %s", args[0], err, lastLine(string(out)))
		}
	}
	return nil
}

// InstalledVersion asks the binary Homebrew links (the one the service
// runs) for its version, e.g. "v0.2.5".
func InstalledVersion(ctx context.Context) string {
	exe, err := StableExecutable()
	if err != nil {
		return ""
	}
	out, err := exec.CommandContext(ctx, exe, "version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// State is remembered between checks.
type State struct {
	Auto      bool      `json:"auto"`
	Checked   time.Time `json:"checked"`
	Latest    string    `json:"latest"`
	Applied   string    `json:"applied,omitempty"`
	Notified  string    `json:"notified,omitempty"`
	LastError string    `json:"last_error,omitempty"`
}

func statePath() string { return appdir.File("update.json") }

// Load reads the state; auto-update is on by default.
func Load() State {
	st := State{Auto: true}
	if b, err := os.ReadFile(statePath()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	return st
}

// Save writes the state (0600).
func Save(st State) error {
	if err := os.MkdirAll(appdir.Dir(), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := statePath() + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, statePath())
}
