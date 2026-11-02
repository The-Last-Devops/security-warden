// Package report prints scan results for people (text) and tools (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

// Scan is everything one run produced.
type Scan struct {
	Version  string           `json:"version"`
	Lang     string           `json:"lang"`
	Platform string           `json:"platform"`
	Host     string           `json:"host"`
	Time     string           `json:"time"`
	Score    int              `json:"score"`
	Checked  int              `json:"checked"`
	Passed   []string         `json:"passed"`
	Sources  []SourceStatus   `json:"sources"`
	Findings []engine.Finding `json:"findings"`
	Root     bool             `json:"root"`
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

// Options changes how much the text report shows.
type Options struct {
	Verbose bool // details for every finding, and the list of passed checks
}

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

// tilde shortens the home folder in text meant for people.
func tilde(s string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return strings.ReplaceAll(s, h, "~")
	}
	return s
}

// pad right-pads to n display columns (Vietnamese labels are multi-byte).
func pad(s string, n int) string {
	if k := utf8.RuneCountInString(s); k < n {
		return s + strings.Repeat(" ", n-k)
	}
	return s
}

// Text writes the human report in s.Lang.
func Text(w io.Writer, s Scan, o Options) {
	t := func(k string) string { return i18n.T(s.Lang, k) }
	c := style{on: IsTerminal(w)}

	shield := "🛡  "
	if !c.on {
		shield = ""
	}
	fmt.Fprintf(w, "\n  %s%s %s\n\n", shield, c.bold("security-warden"),
		c.dim(fmt.Sprintf("%s · %s · %s", s.Version, s.Host, s.Time)))

	// Score bar and counts.
	n := map[string]int{}
	for _, f := range s.Findings {
		n[f.Severity]++
	}
	barColor := green
	switch {
	case s.Score < 50:
		barColor = sevColor["high"]
	case s.Score < 80:
		barColor = sevColor["medium"]
	}
	filled := s.Score / 5
	bar := c.wrap(barColor, strings.Repeat("█", filled)) + c.dim(strings.Repeat("░", 20-filled))
	if !c.on {
		bar = "[" + strings.Repeat("#", filled) + strings.Repeat(".", 20-filled) + "]"
	}
	fmt.Fprintf(w, "  %s  %s  %s%s  ", c.bold(t("report.score")), bar, c.wrap(barColor+";1", fmt.Sprint(s.Score)), c.dim("/100"))
	for _, sev := range engine.Severities {
		if n[sev] > 0 && sev != "info" {
			fmt.Fprintf(w, " %s", c.wrap(sevColor[sev], fmt.Sprintf("● %d %s", n[sev], t("count."+sev))))
		}
	}
	fmt.Fprint(w, "\n\n")

	if len(s.Findings) == 0 {
		fmt.Fprintf(w, "  %s %s\n\n", c.wrap(green, "✓"), c.bold(t("report.none")))
	}

	// Findings, worst first. Low and info get one line unless --verbose.
	width := 0
	for _, f := range s.Findings {
		width = max(width, utf8.RuneCountInString(t("severity."+f.Severity)))
	}
	for _, f := range s.Findings {
		rail := c.wrap(sevColor[f.Severity], "┃")
		if !c.on {
			rail = "|"
		}
		label := t("severity." + f.Severity)
		pill := c.wrap(sevPill[f.Severity], " "+pad(label, width)+" ")
		if !c.on {
			pill = pad("["+label+"]", width+2)
		}
		fmt.Fprintf(w, "  %s %s  %s\n", rail, pill, c.bold(tilde(f.Title)))
		short := f.Severity == "low" || f.Severity == "info"
		indent := strings.Repeat(" ", width+4)
		if short && !o.Verbose {
			// One line of advice is enough for minor findings.
			fmt.Fprintf(w, "  %s %s%s %s\n", rail, indent, c.wrap(green, "→"), tilde(f.Fix))
			continue
		}
		fmt.Fprintf(w, "  %s %s%s\n", rail, indent, c.dim(tilde(f.Explain)))
		fmt.Fprintf(w, "  %s %s%s %s\n", rail, indent, c.wrap(green, "→"), tilde(f.Fix))
		if o.Verbose {
			fmt.Fprintf(w, "  %s %s%s\n", rail, indent, c.dim(f.RuleID))
		}
		fmt.Fprintln(w)
	}
	if len(s.Findings) > 0 && !o.Verbose && (n["low"] > 0 || n["info"] > 0) {
		fmt.Fprintln(w)
	}

	// What passed, and what could not be checked.
	fmt.Fprintf(w, "  %s %s\n", c.wrap(green, "✓"), c.dim(fmt.Sprintf(t("report.passed"), len(s.Passed), s.Checked)))
	if o.Verbose {
		for _, id := range s.Passed {
			fmt.Fprintf(w, "      %s\n", c.dim(id))
		}
	}
	for _, st := range s.Sources {
		switch {
		case st.Error != "":
			fmt.Fprintf(w, "  %s %s\n", c.wrap(sevColor["medium"], "!"), c.dim(t("source."+st.Name)+": "+fmt.Sprintf(t("source.error"), st.Error)))
		case st.Skipped != "" && o.Verbose:
			fmt.Fprintf(w, "  %s %s\n", c.dim("–"), c.dim(t("source."+st.Name)+": "+t(st.Skipped)))
		}
	}
	if !o.Verbose {
		fmt.Fprintf(w, "  %s\n", c.dim(t("report.more")))
	}
	if !s.Root {
		fmt.Fprintf(w, "  %s\n", c.dim(t("report.not_root")))
	}
	fmt.Fprintf(w, "  %s\n\n", c.dim(t("report.private")))
}
