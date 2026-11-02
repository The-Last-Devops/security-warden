// Package source collects read-only facts about the machine. Each source
// returns a list of items (flat maps) that rules match against with CEL.
//
// Sources never return secret values: only locations, flags and metadata.
package source

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Item is one fact a rule can match, e.g. one listening port.
type Item = map[string]any

// Skip means the source does not apply to this machine (tool not installed,
// daemon not running). Key is an i18n message key explaining why.
type Skip struct{ Key string }

func (s Skip) Error() string { return s.Key }

// Collector produces the items of one source.
type Collector struct {
	Name    string
	Collect func(ctx context.Context) ([]Item, error)
}

// Result is the outcome of running one collector.
type Result struct {
	Name    string
	Items   []Item
	SkipKey string // set when the source does not apply
	Err     error  // set when the source failed
}

// All returns every collector, in report order.
func All() []Collector {
	return []Collector{
		{"posture", posture},
		{"defender", defender},
		{"backup", backup},
		{"listening_ports", listeningPorts},
		{"remote_services", remoteServices},
		{"remote_tools", remoteTools},
		{"services", services},
		{"outdated_software", outdatedSoftware},
		{"docker_containers", dockerContainers},
		{"docker_ports", dockerPorts},
		{"tailscale", tailscale},
		{"ssh_keys", sshKeys},
		{"credential_files", credentialFiles},
		{"persistence", persistence},
		{"processes", processes},
		{"apps", apps},
		{"network_config", networkConfig},
		{"privilege", privilege},
		{"shell_rc", shellRC},
		{"ssh_config", sshClientConfig},
		{"git_config", gitConfig},
		{"pkg_config", pkgConfig},
		{"docker_config", dockerDaemonConfig},
		{"ai_agents", aiAgents},
		{"cloud_config", cloudConfig},
		{"shell_history", shellHistory},
		{"sharing", sharing},
		{"authorized_keys", authorizedKeys},
		{"browser_extensions", browserExtensions},
		{"browser_settings", browserSettings},
		{"editor_settings", editorSettings},
		{"editor_extensions", editorExtensions},
		{"dev_files", devFiles},
		{"git_remotes", gitRemotes},
		{"git_history", gitHistory},
		{"project_deps", projectDeps},
	}
}

// Slow lists sources that are costly (file walks, package manager calls);
// watch mode runs them less often.
var Slow = map[string]bool{"outdated_software": true, "dev_files": true, "git_remotes": true, "git_history": true, "project_deps": true, "browser_extensions": true, "shell_history": true, "apps": true, "defender": true}

// Run executes the collectors in parallel. done, if not nil, is called with
// each collector's name as it finishes.
func Run(ctx context.Context, cs []Collector, done func(name string)) []Result {
	// No source may hold up a scan: after the deadline, the ones still
	// running are reported as timed out and their late results dropped.
	ctx, cancel := context.WithTimeout(ctx, RunTimeout)
	defer cancel()
	type res struct {
		i int
		r Result
	}
	ch := make(chan res, len(cs))
	for i, c := range cs {
		go func() {
			items, err := c.Collect(ctx)
			r := Result{Name: c.Name, Items: items}
			var s Skip
			if errors.As(err, &s) {
				r.SkipKey = s.Key
			} else if err != nil {
				r.Err = err
			}
			ch <- res{i, r}
		}()
	}
	out := make([]Result, len(cs))
	got := make([]bool, len(cs))
	for n := 0; n < len(cs); n++ {
		select {
		case x := <-ch:
			out[x.i], got[x.i] = x.r, true
			if done != nil {
				done(x.r.Name)
			}
		case <-ctx.Done():
			for i, c := range cs {
				if !got[i] {
					out[i] = Result{Name: c.Name, Err: errors.New("timed out")}
				}
			}
			return out
		}
	}
	return out
}

// RunTimeout bounds one scan.
var RunTimeout = 60 * time.Second

// run executes a command with a timeout and returns stdout only, so stderr
// warnings never corrupt JSON or lsof output.
func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).Output()
	return string(b), err
}

// runCombined is for tools that print their answer on stderr (spctl,
// sysadminctl).
func runCombined(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(b), err
}

// ResetCaches drops the per-scan caches so the next scan sees fresh data.
// One scan shares them across sources; watch mode resets between scans.
func ResetCaches() {
	processPaths = sync.OnceValue(load_processPaths)
	lsofOnce = sync.OnceValues(load_lsofOnce)
	dockerOnce = sync.OnceValues(load_dockerOnce)
	outdatedOnce = sync.OnceValues(load_outdatedOnce)
	codeWalk = sync.OnceValue(load_codeWalk)
}

// processPaths maps pid -> executable path for every process we can see.
var processPaths = sync.OnceValue(load_processPaths)

func load_processPaths() map[int]string {
	if runtime.GOOS == "linux" {
		return procExePaths()
	}
	if runtime.GOOS == "windows" {
		out, _ := runPS(context.Background(), winProcessScript)
		return parseWinProcesses(out)
	}
	m := map[int]string{}
	out, err := run(context.Background(), "ps", "-axww", "-o", "pid=,comm=")
	if err != nil {
		return m
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		pid, path, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		n := atoi(pid)
		if n > 0 {
			m[n] = strings.TrimSpace(path)
		}
	}
	return m
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// systemBinary reports whether a path belongs to the OS itself. On Linux,
// distribution packages also live in /usr/bin, so nothing counts as "part of
// the OS" there: every listener is worth a look.
func systemBinary(path string) bool {
	if runtime.GOOS == "linux" {
		return false
	}
	if runtime.GOOS == "windows" {
		return winSystemProcess(path, envLookup("SystemRoot"))
	}
	for _, p := range []string{"/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
