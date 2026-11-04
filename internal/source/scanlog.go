package source

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// LogDir, when set, is the folder where Run records each scan, one file per
// level: info.log (each scan: when, how long, version), warn.log (slow
// sources) and error.log (sources that failed or timed out), with the
// commands they waited on. It names commands and durations only, never what
// they printed. The CLI sets it at startup; tests leave it "".
var LogDir string

// LogLevels are the levels, each with its own file LEVEL.log.
var LogLevels = []string{"info", "warn", "error"}

// Version goes into each scan record.
var Version = "dev"

// logMax is the size at which a log file moves to NAME.1 and starts over.
const logMax = 512 << 10

// slowSource is how long a source may take before the log names it.
const slowSource = 5 * time.Second

func writeLog(rs []Result, took time.Duration) {
	if LogDir == "" {
		return
	}
	// One event per line: time, level, [source], message. The commands a
	// source waited on get its level too.
	byLevel := map[string]*strings.Builder{}
	add := func(level, format string, a ...any) {
		b := byLevel[level]
		if b == nil {
			b = &strings.Builder{}
			byLevel[level] = b
		}
		fmt.Fprintf(b, format, a...)
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	add("info", "%s INFO  [scan] done in %.1fs, %d sources, %s %s/%s\n", now,
		took.Seconds(), len(rs), Version, runtime.GOOS, runtime.GOARCH)
	for _, r := range rs {
		if r.Err == nil && r.Took < slowSource {
			continue
		}
		level, tag, msg := "warn", "WARN ", fmt.Sprintf("slow: %.1fs", r.Took.Seconds())
		if r.Err != nil {
			level, tag, msg = "error", "ERROR", fmt.Sprintf("%s after %.1fs", r.Err, r.Took.Seconds())
		}
		add(level, "%s %s [%s] %s\n", now, tag, r.Name, msg)
		for _, t := range r.Trace {
			add(level, "%s %s [%s] command: %s\n", now, tag, r.Name, t)
		}
	}
	_ = os.MkdirAll(LogDir, 0o700)
	for level, b := range byLevel {
		appendLog(LogFile(level), b.String())
	}
}

// LogFile is the file of one level.
func LogFile(level string) string { return filepath.Join(LogDir, level+".log") }

func appendLog(path, text string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > logMax {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(text)
}

// logShow bounds what ReadLog returns: the newest lines are the ones worth
// reading.
const logShow = 64 << 10

// ReadLog returns the newest lines of the given levels (all when none),
// merged from their files in time order. It is "" before the first scan.
func ReadLog(levels ...string) (string, error) {
	if LogDir == "" {
		return "", nil
	}
	if len(levels) == 0 {
		levels = LogLevels
	}
	var lines []string
	for _, level := range levels {
		for _, p := range []string{LogFile(level) + ".1", LogFile(level)} {
			b, err := os.ReadFile(p)
			if err != nil && !os.IsNotExist(err) {
				return "", err
			}
			for _, l := range strings.Split(string(b), "\n") {
				if l != "" {
					lines = append(lines, l)
				}
			}
		}
	}
	// Lines start with "2006-01-02 15:04:05", so text order is time order;
	// within one second the scan's INFO line stays before its warnings.
	sort.SliceStable(lines, func(i, j int) bool { return stamp(lines[i]) < stamp(lines[j]) })
	n := 0
	for i := len(lines) - 1; i >= 0; i-- {
		if n += len(lines[i]) + 1; n > logShow {
			lines = lines[i+1:]
			break
		}
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func stamp(l string) string {
	if len(l) < 19 {
		return l
	}
	return l[:19]
}
