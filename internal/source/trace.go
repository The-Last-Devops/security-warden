package source

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// SlowCommand is how long a command may take before the scan log names it.
const SlowCommand = 2 * time.Second

// waitDelay bounds how long a killed command may keep its output pipes open
// (a child it spawned can hold them, and Output would then wait forever).
const waitDelay = 2 * time.Second

// trace records, for one collector, the commands that were slow or failed
// and the ones still running, so a scan that times out says what it waited
// on. It holds command lines only, never their output.
type trace struct {
	mu      sync.Mutex
	next    int
	running map[int]traceCmd
	lines   []string
}

type traceCmd struct {
	line  string
	start time.Time
}

type traceKey struct{}

func withTrace(ctx context.Context) (context.Context, *trace) {
	t := &trace{running: map[int]traceCmd{}}
	return context.WithValue(ctx, traceKey{}, t), t
}

// traced runs cmd (Output when combined is false), noting it in the
// collector's trace and bounding the wait after a kill.
func traced(ctx context.Context, cmd *exec.Cmd, combined bool) ([]byte, error) {
	cmd.WaitDelay = waitDelay
	t, _ := ctx.Value(traceKey{}).(*trace)
	if t == nil {
		if combined {
			return cmd.CombinedOutput()
		}
		return cmd.Output()
	}
	line := cmdLine(cmd.Args)
	start := time.Now()
	t.mu.Lock()
	id := t.next
	t.next++
	t.running[id] = traceCmd{line, start}
	t.mu.Unlock()
	var b []byte
	var err error
	if combined {
		b, err = cmd.CombinedOutput()
	} else {
		b, err = cmd.Output()
	}
	took := time.Since(start)
	t.mu.Lock()
	delete(t.running, id)
	if took >= SlowCommand || (err != nil && ctx.Err() != nil) {
		msg := fmt.Sprintf("%s (%.1fs)", line, took.Seconds())
		if err != nil {
			msg += ": " + err.Error()
		}
		t.lines = append(t.lines, msg)
	}
	t.mu.Unlock()
	return b, err
}

// report lists what was noted, then what is still running.
func (t *trace) report() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := append([]string(nil), t.lines...)
	var still []string
	for _, c := range t.running {
		still = append(still, fmt.Sprintf("%s (still running after %.1fs)", c.line, time.Since(c.start).Seconds()))
	}
	sort.Strings(still)
	return append(out, still...)
}

// cmdLine is the command for the log, shortened: git calls start with the
// same safety options (left out) and can carry long file lists.
func cmdLine(args []string) string {
	if len(args) > 0 && args[0] == "git" {
		var kept []string
		for i := 0; i < len(args); i++ {
			switch {
			case args[i] == "-c" && i+1 < len(args):
				i++
			case args[i] != "--no-optional-locks":
				kept = append(kept, args[i])
			}
		}
		args = kept
	}
	s := strings.Join(args, " ")
	if r := []rune(s); len(r) > 160 {
		s = string(r[:159]) + "…"
	}
	return s
}
