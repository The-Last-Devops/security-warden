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
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("path must not contain ..: %q", p)
	}
	h, err := filepath.EvalSymlinks(filepath.Clean(home()))
	if err != nil || h == "" {
		return "", fmt.Errorf("cannot resolve home folder")
	}
	// Resolve the folder part, so a symlinked folder inside home
	// (~/a -> /etc) cannot lead outside it.
	dir, err := filepath.EvalSymlinks(filepath.Dir(filepath.Clean(p)))
	if err != nil {
		return "", err
	}
	clean := filepath.Join(dir, filepath.Base(p))
	if !strings.HasPrefix(clean, h+string(filepath.Separator)) {
		return "", fmt.Errorf("path is outside the home folder: %q", p)
	}
	fi, err := os.Lstat(clean)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file: %q", p)
	}
	if !ownedByUser(fi) {
		return "", fmt.Errorf("not owned by you: %q", p)
	}
	return clean, nil
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@._+-]{0,99}$`)

// allowed lists, per action, the sources a rule may use it with and which
// item field may fill each parameter. A rule cannot point an action at any
// other value, so a careless or hostile rule cannot chmod arbitrary files.
var allowed = map[string]struct {
	sources []string
	params  map[string]string // param -> required "{field}"
}{
	"chmod_private":          {[]string{"credential_files", "ssh_keys", "authorized_keys"}, map[string]string{"path": "{path}"}},
	"brew_upgrade":           {[]string{"outdated_software"}, map[string]string{"name": "{name}"}},
	"brew_upgrade_all":       {[]string{"outdated_software"}, nil},
	"macos_firewall_on":      {[]string{"posture"}, nil},
	"macos_stealth_on":       {[]string{"posture"}, nil},
	"macos_gatekeeper_on":    {[]string{"posture"}, nil},
	"macos_guest_off":        {[]string{"posture"}, nil},
	"macos_airdrop_contacts": {[]string{"posture"}, nil},
	"tailscale_shields_up":   {[]string{"tailscale"}, nil},
	"tailscale_ssh_off":      {[]string{"tailscale"}, nil},
}

// CheckRemedy is the engine's check for a rule's remedy block.
func CheckRemedy(action, source string, params map[string]string) error {
	if _, ok := registry[action]; !ok {
		return fmt.Errorf("unknown action %q", action)
	}
	a, ok := allowed[action]
	if !ok {
		return fmt.Errorf("action %q has no allow-list", action)
	}
	okSource := false
	for _, s := range a.sources {
		okSource = okSource || s == source
	}
	if !okSource {
		return fmt.Errorf("action %q cannot be used with source %q", action, source)
	}
	if len(params) != len(a.params) {
		return fmt.Errorf("action %q takes params %v", action, a.params)
	}
	for k, v := range params {
		if a.params[k] != v {
			return fmt.Errorf("param %s must be exactly %q", k, a.params[k])
		}
	}
	return nil
}

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
			prev, err := chmodNoFollow(path, 0o600)
			if err != nil {
				return nil, err
			}
			return map[string]string{"path": path, "mode": fmt.Sprintf("%04o", prev)}, nil
		},
		Undo: func(p map[string]string) error {
			path, err := privatePath(p["path"])
			if err != nil {
				return err
			}
			m, err := strconv.ParseUint(p["mode"], 8, 32)
			// The journal is a user file; never let it widen permissions
			// beyond what a home file normally has.
			if err != nil || m > 0o777 || m&0o022 != 0 {
				return fmt.Errorf("refusing to restore mode %q", p["mode"])
			}
			_, err = chmodNoFollow(path, fs.FileMode(m))
			return err
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

	register(&Action{
		ID: "macos_airdrop_contacts", Undoable: true,
		Plan: func(map[string]string) []string {
			return []string{`defaults write com.apple.sharingd DiscoverableMode -string "Contacts Only"`}
		},
		Apply: func(map[string]string) (map[string]string, error) {
			prev, _ := exec.Command("defaults", "read", "com.apple.sharingd", "DiscoverableMode").Output()
			undo := map[string]string{"mode": strings.TrimSpace(string(prev))}
			return undo, Runner("defaults", "write", "com.apple.sharingd", "DiscoverableMode", "-string", "Contacts Only")
		},
		Undo: func(p map[string]string) error {
			mode := p["mode"]
			if mode != "Everyone" && mode != "Off" && mode != "Contacts Only" {
				mode = "Everyone"
			}
			return Runner("defaults", "write", "com.apple.sharingd", "DiscoverableMode", "-string", mode)
		},
	})

	tsToggle := func(id string, on, off string) {
		register(&Action{
			ID: id, Undoable: true,
			Plan: func(map[string]string) []string { return []string{"tailscale set " + on} },
			Apply: func(map[string]string) (map[string]string, error) {
				return map[string]string{}, Runner(tailscaleBin(), "set", on)
			},
			Undo: func(map[string]string) error { return Runner(tailscaleBin(), "set", off) },
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
			return nil, Runner(brewBin(), "upgrade", "--", p["name"])
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
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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

// ErrRoot is returned when fix runs as root: actions ask for sudo themselves,
// and running everything as root would touch root-owned files and journal.
var ErrRoot = errors.New("run security-warden fix as your normal user; it asks for admin rights only when needed")

// Apply runs one action and journals it when it can be undone.
func Apply(batch, ruleID, actionID string, params map[string]string) error {
	if os.Geteuid() == 0 && !allowRoot {
		return ErrRoot
	}
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

// allowRoot is set by tests that run as root in a container.
var allowRoot = false

// UndoLast reverts every change of the most recent batch that is not undone
// yet, newest first. It returns the reverted entries.
func UndoLast() ([]Entry, error) {
	if os.Geteuid() == 0 && !allowRoot {
		return nil, ErrRoot
	}
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
