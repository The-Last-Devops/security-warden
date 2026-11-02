// Package fix applies the remedies that rules point to. Rules never carry
// commands: a rule names one of the actions below and passes values from
// the finding. Every action validates its input, and every applied change
// is journaled so it can be undone.
package fix

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Action is one kind of change security-warden knows how to make.
type Action struct {
	ID        string
	NeedsRoot bool
	Undoable  bool
	// Apply makes the change and returns what Undo needs to revert it.
	Apply func(p map[string]string) (undo map[string]string, err error)
	// Undo reverts a change from the values Apply returned.
	Undo func(p map[string]string) error
	// Plan describes the commands Apply would run, for --dry-run.
	Plan func(p map[string]string) []string
}

var registry = map[string]*Action{}

func register(a *Action) { registry[a.ID] = a }

// Get returns an action by id.
func Get(id string) (*Action, bool) {
	a, ok := registry[id]
	return a, ok
}

// IDs lists every registered action, for rule validation.
func IDs() []string {
	var ids []string
	for id := range registry {
		ids = append(ids, id)
	}
	return ids
}

// Runner executes external commands; tests replace it.
var Runner = func(argv ...string) error {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stderr, os.Stderr, os.Stdin
	return cmd.Run()
}

func sudo(argv ...string) []string {
	if os.Geteuid() == 0 {
		return argv
	}
	return append([]string{"sudo"}, argv...)
}

// home is overridable in tests.
var home = func() string { h, _ := os.UserHomeDir(); return h }

// privatePath accepts only a regular file inside the user's home folder.
func privatePath(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) {
		return "", fmt.Errorf("path must be absolute: %q", p)
	}
	clean := filepath.Clean(p)
	h := filepath.Clean(home())
	if h == "" || !strings.HasPrefix(clean, h+string(filepath.Separator)) {
		return "", fmt.Errorf("path is outside the home folder: %q", p)
	}
	fi, err := os.Lstat(clean)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %q", p)
	}
	return clean, nil
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,100}$`)

func init() {
	register(&Action{
		ID:       "chmod_private",
		Undoable: true,
		Plan:     func(p map[string]string) []string { return []string{"chmod 600 " + p["path"]} },
		Apply: func(p map[string]string) (map[string]string, error) {
			path, err := privatePath(p["path"])
			if err != nil {
				return nil, err
			}
			fi, err := os.Stat(path)
			if err != nil {
				return nil, err
			}
			if err := os.Chmod(path, 0o600); err != nil {
				return nil, err
			}
			return map[string]string{"path": path, "mode": fmt.Sprintf("%04o", fi.Mode().Perm())}, nil
		},
		Undo: func(p map[string]string) error {
			path, err := privatePath(p["path"])
			if err != nil {
				return err
			}
			m, err := strconv.ParseUint(p["mode"], 8, 32)
			if err != nil {
				return err
			}
			return os.Chmod(path, fs.FileMode(m))
		},
	})

	macToggle := func(id string, on, off []string) {
		register(&Action{
			ID: id, NeedsRoot: true, Undoable: true,
			Plan:  func(map[string]string) []string { return []string{strings.Join(sudo(on...), " ")} },
			Apply: func(map[string]string) (map[string]string, error) { return map[string]string{}, Runner(sudo(on...)...) },
			Undo:  func(map[string]string) error { return Runner(sudo(off...)...) },
		})
	}
	const fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	macToggle("macos_firewall_on", []string{fw, "--setglobalstate", "on"}, []string{fw, "--setglobalstate", "off"})
	macToggle("macos_stealth_on", []string{fw, "--setstealthmode", "on"}, []string{fw, "--setstealthmode", "off"})
	macToggle("macos_gatekeeper_on", []string{"spctl", "--global-enable"}, []string{"spctl", "--global-disable"})
	macToggle("macos_guest_off",
		[]string{"defaults", "write", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled", "-bool", "NO"},
		[]string{"defaults", "write", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled", "-bool", "YES"})

	tsToggle := func(id string, on, off string) {
		register(&Action{
			ID: id, Undoable: true,
			Plan:  func(map[string]string) []string { return []string{"tailscale set " + on} },
			Apply: func(map[string]string) (map[string]string, error) { return map[string]string{}, Runner(tailscaleBin(), "set", on) },
			Undo:  func(map[string]string) error { return Runner(tailscaleBin(), "set", off) },
		})
	}
	tsToggle("tailscale_shields_up", "--shields-up=true", "--shields-up=false")
	tsToggle("tailscale_ssh_off", "--ssh=false", "--ssh=true")

	register(&Action{
		ID:   "brew_upgrade",
		Plan: func(p map[string]string) []string { return []string{"brew upgrade " + p["name"]} },
		Apply: func(p map[string]string) (map[string]string, error) {
			if !safeName.MatchString(p["name"]) {
				return nil, fmt.Errorf("bad package name %q", p["name"])
			}
			return nil, Runner(brewBin(), "upgrade", p["name"])
		},
	})
	register(&Action{
		ID:    "brew_upgrade_all",
		Plan:  func(map[string]string) []string { return []string{"brew upgrade"} },
		Apply: func(map[string]string) (map[string]string, error) { return nil, Runner(brewBin(), "upgrade") },
	})
}

func tailscaleBin() string {
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p
	}
	if runtime.GOOS == "darwin" {
		return "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
	}
	return "tailscale"
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
	return "brew"
}

// Entry is one applied change in the journal.
type Entry struct {
	Batch  string            `json:"batch"`
	Time   string            `json:"time"`
	RuleID string            `json:"rule_id"`
	Action string            `json:"action"`
	Undo   map[string]string `json:"undo,omitempty"`
	Undone bool              `json:"undone,omitempty"`
}

// JournalPath is where applied changes are recorded.
var JournalPath = func() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = filepath.Join(home(), ".config")
	}
	return filepath.Join(base, "security-warden", "fixes.jsonl")
}

func appendEntry(e Entry) error {
	p := JournalPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	_, err = f.Write(append(b, '\n'))
	return err
}

func readJournal() ([]Entry, error) {
	f, err := os.Open(JournalPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var es []Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			es = append(es, e)
		}
	}
	return es, sc.Err()
}

func writeJournal(es []Entry) error {
	p := JournalPath()
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, e := range es {
		b, _ := json.Marshal(e)
		f.Write(append(b, '\n'))
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// NewBatch returns an id grouping the changes of one fix run.
func NewBatch() string { return time.Now().UTC().Format("20060102T150405Z") }

// Apply runs one action and journals it when it can be undone.
func Apply(batch, ruleID, actionID string, params map[string]string) error {
	a, ok := Get(actionID)
	if !ok {
		return fmt.Errorf("unknown action %q", actionID)
	}
	undo, err := a.Apply(params)
	if err != nil {
		return err
	}
	if a.Undoable {
		return appendEntry(Entry{Batch: batch, Time: time.Now().UTC().Format(time.RFC3339), RuleID: ruleID, Action: actionID, Undo: undo})
	}
	return nil
}

// UndoLast reverts every change of the most recent batch that is not undone
// yet, newest first. It returns the reverted entries.
func UndoLast() ([]Entry, error) {
	es, err := readJournal()
	if err != nil || len(es) == 0 {
		return nil, err
	}
	batch := ""
	for i := len(es) - 1; i >= 0; i-- {
		if !es[i].Undone {
			batch = es[i].Batch
			break
		}
	}
	if batch == "" {
		return nil, nil
	}
	var done []Entry
	var errs []error
	for i := len(es) - 1; i >= 0; i-- {
		e := &es[i]
		if e.Batch != batch || e.Undone {
			continue
		}
		a, ok := Get(e.Action)
		if !ok || a.Undo == nil {
			continue
		}
		if err := a.Undo(e.Undo); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", e.RuleID, err))
			continue
		}
		e.Undone = true
		done = append(done, *e)
	}
	if err := writeJournal(es); err != nil {
		errs = append(errs, err)
	}
	return done, errors.Join(errs...)
}
