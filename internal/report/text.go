// Package report prints scan results for people (text) and tools (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

// Scan is everything one run produced.
type Scan struct {
	Version  string           `json:"version"`
	Lang     string           `json:"lang"`
	Platform string           `json:"platform"`
	Score    int              `json:"score"`
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

type palette struct{ bold, dim, reset string }

var colors = map[string]string{
	"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m", "low": "\033[36m", "info": "\033[37m",
}

func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// Text writes the human report in s.Lang.
func Text(w io.Writer, s Scan) {
	t := func(k string) string { return i18n.T(s.Lang, k) }
	color := useColor(w)
	p := palette{}
	if color {
		p = palette{"\033[1m", "\033[2m", "\033[0m"}
	}

	fmt.Fprintf(w, "%s%s%s  %s\n\n", p.bold, t("report.title"), p.reset, s.Version)

	fmt.Fprintf(w, "%s%s%s\n", p.bold, t("report.sources"), p.reset)
	for _, st := range s.Sources {
		var state string
		switch {
		case st.Error != "":
			state = fmt.Sprintf(t("source.error"), st.Error)
		case st.Skipped != "":
			state = t(st.Skipped)
		default:
			state = fmt.Sprintf(t("source.ok"), st.Items)
		}
		fmt.Fprintf(w, "  %-34s %s%s%s\n", t("source."+st.Name), p.dim, state, p.reset)
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%s%s%s\n", p.bold, t("report.findings"), p.reset)
	if len(s.Findings) == 0 {
		fmt.Fprintf(w, "  %s\n", t("report.none"))
	}
	for _, f := range s.Findings {
		label := t("severity." + f.Severity)
		if color {
			label = colors[f.Severity] + " " + label + " " + p.reset
		} else {
			label = "[" + label + "]"
		}
		fmt.Fprintf(w, "\n  %s %s%s%s\n", label, p.bold, f.Title, p.reset)
		fmt.Fprintf(w, "    %s\n", f.Explain)
		fmt.Fprintf(w, "    %s%s:%s %s\n", p.bold, t("report.fix"), p.reset, f.Fix)
		fmt.Fprintf(w, "    %s%s%s\n", p.dim, f.RuleID, p.reset)
	}
	fmt.Fprintln(w)

	n := map[string]int{}
	for _, f := range s.Findings {
		n[f.Severity]++
	}
	fmt.Fprintf(w, "%s%s: %d/100%s  %s\n", p.bold, t("report.score"), s.Score, p.reset,
		fmt.Sprintf(t("report.summary"), len(s.Findings), n["critical"], n["high"], n["medium"], n["low"]))
	var notes []string
	if !s.Root {
		notes = append(notes, t("report.not_root"))
	}
	notes = append(notes, t("report.private"))
	fmt.Fprintf(w, "%s%s%s\n", p.dim, strings.Join(notes, "\n"), p.reset)
}
