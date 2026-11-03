// Package report prints scan results for people (text) and tools (JSON).
package report

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

// Scan is everything one run produced.
type Scan struct {
	Version  string `json:"version"`
	Lang     string `json:"lang"`
	Platform string `json:"platform"`
	Host     string `json:"host"`
	Time     string `json:"time"`
	Score    int    `json:"score"`
	// ScoreMachine and ScoreCode score the two scopes on their own.
	ScoreMachine int              `json:"score_machine"`
	ScoreCode    int              `json:"score_code"`
	Gain         map[string]int   `json:"gain"`
	Checked      int              `json:"checked"`
	Passed       []string         `json:"passed"`
	Sources      []SourceStatus   `json:"sources"`
	Findings     []engine.Finding `json:"findings"`
	Ignored      []engine.Finding `json:"ignored"`
	Root         bool             `json:"root"`
}

// SourceStatus says whether a source ran, and how many items it found.
type SourceStatus struct {
	Name    string `json:"name"`
	Items   int    `json:"items"`
	Skipped string `json:"skipped,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Statuses summarises collector results.
func Statuses(rs []source.Result) []SourceStatus {
	out := make([]SourceStatus, 0, len(rs))
	for _, r := range rs {
		s := SourceStatus{Name: r.Name, Items: len(r.Items), Skipped: r.SkipKey}
		if r.Err != nil {
			s.Error = r.Err.Error()
		}
		out = append(out, s)
	}
	return out
}

// JSON writes the scan as indented JSON.
func JSON(w io.Writer, s Scan) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// Options changes what the text report shows.
type Options struct {
	Verbose  bool           // every place, rule ids and keys, and the list of passed checks
	Scope    string         // "machine" or "code": only that part ("" = all)
	Category string         // one category, see Category ("" = all)
	ByRepo   bool           // group code findings per repository
	Safe     bool           // show what already passes instead of the problems
	Rules    []*engine.Rule // for the labels of passed checks (--safe)
}

// Categories lists the categories in the order the UI shows them.
var Categories = []string{"secrets", "exposure", "settings", "persistence", "ai", "devtools", "software", "other", "code_secrets", "code_deps"}

// Keep returns whether a finding of source passes the scope and category filters.
func (o Options) Keep(source string) bool {
	return (o.Scope == "" || Scope(source) == o.Scope) && (o.Category == "" || Category(source) == o.Category)
}

// Filter keeps the findings that pass the scope and category filters.
func (o Options) Filter(fs []engine.Finding) []engine.Finding {
	var out []engine.Finding
	for _, f := range fs {
		if o.Keep(f.Source) {
			out = append(out, f)
		}
	}
	return out
}

// ShortKey is the part of a finding key shown to people (enough to be
// unique on one machine; ignore add accepts any unique prefix).
func ShortKey(f engine.Finding) string { return engine.FindingID(f)[:8] }

// IsTerminal reports whether w is an interactive terminal that may get
// colors and live progress.
func IsTerminal(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// style wraps text in ANSI codes, or not at all when color is off.
type style struct{ on bool }

func (s style) wrap(code, text string) string {
	if !s.on || code == "" {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}
func (s style) bold(t string) string { return s.wrap("1", t) }
func (s style) dim(t string) string  { return s.wrap("2", t) }

var sevColor = map[string]string{
	"critical": "1;91", "high": "91", "medium": "33", "low": "36", "info": "37",
}
var sevPill = map[string]string{
	"critical": "1;97;41", "high": "1;30;101", "medium": "1;30;43", "low": "1;30;46", "info": "1;30;47",
}

const green = "32"

// pad right-pads to n display columns (Vietnamese labels are multi-byte).
func pad(s string, n int) string {
	if k := utf8.RuneCountInString(s); k < n {
		return s + strings.Repeat(" ", n-k)
	}
	return s
}
