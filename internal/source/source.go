// Package source collects read-only facts about the machine. Each source
// returns a list of items (flat maps) that rules match against with CEL.
//
// Sources never return secret values: only locations, flags and metadata.
package source

import (
	"context"
	"errors"
	"os/exec"
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
	}
}

// Run executes the collectors in parallel. done, if not nil, is called with
// each collector's name as it finishes.
func Run(ctx context.Context, cs []Collector, done func(name string)) []Result {
	out := make([]Result, len(cs))
	var wg sync.WaitGroup
	for i, c := range cs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			items, err := c.Collect(ctx)
			r := Result{Name: c.Name, Items: items}
			var s Skip
			if errors.As(err, &s) {
				r.SkipKey = s.Key
			} else if err != nil {
				r.Err = err
			}
			out[i] = r
			if done != nil {
				done(c.Name)
			}
		}()
	}
	wg.Wait()
	return out
}

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

// processPaths maps pid -> executable path for every process we can see.
var processPaths = sync.OnceValue(func() map[int]string {
	m := map[int]string{}
	out, err := run(context.Background(), "ps", "-axo", "pid=,comm=")
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
})

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

// systemBinary reports whether a path belongs to the OS itself.
func systemBinary(path string) bool {
	for _, p := range []string{"/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
