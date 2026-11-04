//go:build !windows

package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTimedOutSourceNamesStuckCommand(t *testing.T) {
	old, oldLog := RunTimeout, LogDir
	t.Cleanup(func() { RunTimeout, LogDir = old, oldLog })
	RunTimeout = 300 * time.Millisecond
	LogDir = t.TempDir()
	stuck := Collector{"posture", func(ctx context.Context) ([]Item, error) {
		_, err := run(ctx, "sleep", "30")
		return nil, err
	}}
	quick := Collector{"backup", func(ctx context.Context) ([]Item, error) { return nil, nil }}
	start := time.Now()
	rs := Run(context.Background(), []Collector{stuck, quick}, nil)
	if time.Since(start) > 5*time.Second {
		t.Fatalf("Run waited %v past its deadline", time.Since(start))
	}
	if rs[0].Err == nil || len(rs[0].Trace) != 1 || !strings.Contains(rs[0].Trace[0], "sleep 30 (still running") {
		t.Fatalf("stuck source: err=%v trace=%q", rs[0].Err, rs[0].Trace)
	}
	if rs[1].Err != nil || len(rs[1].Trace) != 0 {
		t.Fatalf("quick source: err=%v trace=%q", rs[1].Err, rs[1].Trace)
	}
	if _, err := os.Stat(filepath.Join(LogDir, "warn.log")); !os.IsNotExist(err) {
		t.Fatalf("warn.log written with nothing slow: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(LogDir, "error.log")); strings.Contains(string(b), "INFO") || !strings.Contains(string(b), "ERROR [posture]") {
		t.Fatalf("error.log:\n%s", b)
	}
	log, err := ReadLog()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(log, "20") || strings.Index(log, "INFO") > strings.Index(log, "ERROR") {
		t.Fatalf("merged log not in time order:\n%s", log)
	}
	if !strings.Contains(log, "posture") || !strings.Contains(log, " INFO  [scan] done in ") || !strings.Contains(log, " ERROR [posture] timed out after ") || !strings.Contains(log, " ERROR [posture] command: sleep 30 (still running") || !strings.Contains(log, "timed out") || !strings.Contains(log, "sleep 30") || strings.Contains(log, "backup") {
		t.Fatalf("log:\n%s", log)
	}
}

func TestCmdLineShortensGit(t *testing.T) {
	got := cmdLine([]string{"git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "protocol.allow=never", "-C", "/repo", "log", "--diff-filter=D"})
	if got != "git -C /repo log --diff-filter=D" {
		t.Fatalf("cmdLine = %q", got)
	}
}
