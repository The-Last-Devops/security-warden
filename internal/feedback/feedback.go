package feedback

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/report"
)

// Repo is where issues go.
const Repo = "The-Last-Devops/security-warden"

// MaxURL bounds a link: browsers and GitHub refuse much longer ones.
const MaxURL = 6000

// MaxIdea bounds the text of an idea.
const MaxIdea = 4000

// Info describes where a report comes from.
type Info struct {
	Version  string
	Platform string // macos, linux, windows
	Via      string // cli, web or mcp
}

// Field is one field of the GitHub issue form, already scrubbed.
type Field struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// Draft is an issue ready to be opened by the user. Preview is exactly the
// text the link fills in.
type Draft struct {
	Kind      string  `json:"kind"` // false_positive, idea or bug
	Title     string  `json:"title"`
	Fields    []Field `json:"fields"`
	Preview   string  `json:"preview"`
	URL       string  `json:"url"`
	Shortened bool    `json:"shortened"`
}

var osName = map[string]string{"macos": "macOS", "linux": "Linux", "windows": "Windows"}

var surface = map[string]string{"cli": "Terminal report", "web": "Web UI", "mcp": "MCP server"}

const shortNote = "\n… (shortened to fit in the link)"

// FalsePositive drafts a "this finding is wrong" report: the rule, where it
// was found and what the user was told, scrubbed. f's texts should be in
// English (the issue tracker's language). r may be nil.
func FalsePositive(f engine.Finding, r *engine.Rule, info Info, s *Scrubber) Draft {
	s = s.ForFinding(f)
	tier := f.Tier
	if r != nil {
		tier = r.Tier
	}
	if tier == "" {
		tier = "stable"
	}
	place := ""
	if len(f.Item) > 0 && report.PlaceOf(f) != report.Tilde(engine.Clean(f.Title)) {
		place = s.Scrub(report.PlaceOf(f))
	}
	var b strings.Builder
	b.WriteString("Security Warden reported this and I think it is wrong (a false positive, or a fix that does not work).\n\n")
	fmt.Fprintf(&b, "Rule: %s (%s, tier %s)\n", f.RuleID, f.Severity, tier)
	fmt.Fprintf(&b, "Source: %s\n", f.Source)
	fmt.Fprintf(&b, "Version: %s on %s\n", clean(info.Version), osName[info.Platform])
	if place != "" {
		fmt.Fprintf(&b, "Place: %s\n", place)
	}
	fmt.Fprintf(&b, "Title: %s\n", s.Scrub(f.Title))
	b.WriteString("\nWhat is wrong:\n(Describe it here: why this is not a problem on your machine, or what is wrong with the fix.)")
	var out strings.Builder
	fmt.Fprintf(&out, "Explanation shown:\n%s\n\nFix shown:\n%s", s.Scrub(f.Explain), s.Scrub(f.Fix))
	fields := []Field{
		{"what", "What happened", b.String()},
		{"version", "Version", clean(info.Version)},
		{"os", "System", osName[info.Platform]},
		{"surface", "Where", surface[info.Via]},
		{"output", "Output", out.String()},
	}
	return build("false_positive", "bug.yml", "False positive: "+f.RuleID, fields)
}

// ForRule drafts a report about a rule that has no finding here (for a fix
// text that is wrong, say): its texts as templates, nothing from the machine.
func ForRule(r *engine.Rule, info Info, s *Scrubber) Draft {
	return FalsePositive(engine.Finding{RuleID: r.ID, Severity: r.Severity, Source: r.Source, Tier: r.Tier,
		Title: r.Title.Get("en"), Explain: r.Explain.Get("en"), Fix: r.Fix.Get("en")}, r, info, s)
}

// Idea drafts a "new check" request from the user's (or agent's) words.
func Idea(text string, info Info, s *Scrubber) (Draft, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Draft{}, fmt.Errorf("the idea is empty")
	}
	if len(text) > MaxIdea {
		text = text[:MaxIdea]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	body := s.Scrub(text)
	first := strings.TrimSpace(strings.SplitN(body, "\n", 2)[0])
	if r := []rune(first); len(r) > 70 {
		first = string(r[:69]) + "…"
	}
	risk := body + fmt.Sprintf("\n\n(Sent from Security Warden %s on %s, %s.", clean(info.Version), osName[info.Platform], surface[info.Via])
	if info.Via == "mcp" {
		risk += " Drafted by an AI agent."
	}
	risk += ")"
	fields := []Field{
		{"risk", "The risk", risk},
		{"platforms", "Platforms", osName[info.Platform]},
	}
	return build("idea", "rule-request.yml", "Rule: "+first, fields), nil
}

// bugLogLines is how many recent log lines a bug report picks from; the
// link's length decides how many fit.
const bugLogLines = 300

// Bug drafts a "something does not work" report: the user's words (may be
// empty) and the scan log lines that matter most (see pickLog), both
// scrubbed.
func Bug(text, log string, info Info, s *Scrubber) Draft {
	text = strings.TrimSpace(text)
	if len(text) > MaxIdea {
		text = text[:MaxIdea]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	what := s.Scrub(text)
	title := "Bug report"
	if what == "" {
		what = "(Describe it here: what you did, what you expected and what you saw.)"
	} else {
		first := strings.TrimSpace(strings.SplitN(what, "\n", 2)[0])
		if r := []rune(first); len(r) > 70 {
			first = string(r[:69]) + "…"
		}
		title = "Bug: " + first
	}
	var out strings.Builder
	if lines := pickLog(log); len(lines) > 0 {
		out.WriteString("Scan log (errors, then warnings, then scans; newest first):\n")
		for _, l := range lines {
			out.WriteString(s.Scrub(clean(l)) + "\n")
		}
	}
	fields := []Field{
		{"what", "What happened", what},
		{"version", "Version", clean(info.Version)},
		{"os", "System", osName[info.Platform]},
		{"surface", "Where", surface[info.Via]},
		{"output", "Output", strings.TrimRight(out.String(), "\n")},
	}
	return build("bug", "bug.yml", title, fields)
}

// pickLog orders the newest log lines for a report: errors, then warnings,
// then the rest, newest first within each, with repeats of the same event
// (same level, source and message at another time) folded into one line
// marked (×N). Shortening the link then drops the least useful lines.
func pickLog(log string) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(log), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > bugLogLines {
		lines = lines[len(lines)-bugLogLines:]
	}
	type event struct {
		line string
		n    int
	}
	var order []string
	seen := map[string]*event{}
	for i := len(lines) - 1; i >= 0; i-- {
		key := lines[i]
		if len(key) > 20 && key[4] == '-' {
			key = key[20:] // without "2006-01-02 15:04:05 "
		}
		// Durations differ between scans; the event is the same.
		key = durations.ReplaceAllString(key, "")
		if e := seen[key]; e != nil {
			e.n++
			continue
		}
		seen[key] = &event{line: lines[i], n: 1}
		order = append(order, key)
	}
	rank := func(l string) int {
		switch {
		case strings.Contains(l, " ERROR "):
			return 0
		case strings.Contains(l, " WARN "):
			return 1
		}
		return 2
	}
	sort.SliceStable(order, func(i, j int) bool { return rank(seen[order[i]].line) < rank(seen[order[j]].line) })
	out := make([]string, 0, len(order))
	for _, k := range order {
		e := seen[k]
		if e.n > 1 {
			out = append(out, fmt.Sprintf("%s (×%d)", e.line, e.n))
		} else {
			out = append(out, e.line)
		}
	}
	return out
}

var durations = regexp.MustCompile(`\d+(\.\d+)?s\b`)

// ScrubLog takes identifying details out of each line of a scan log, for a
// file to attach to a bug report.
func ScrubLog(log string, s *Scrubber) string {
	var b strings.Builder
	for _, l := range strings.Split(log, "\n") {
		if l != "" {
			b.WriteString(s.Scrub(clean(l)) + "\n")
		}
	}
	return b.String()
}

func clean(s string) string { return engine.Clean(s) }

// build makes the link, shortening the longest field until it fits.
func build(kind, template, title string, fields []Field) Draft {
	d := Draft{Kind: kind, Title: title, Fields: fields}
	for {
		d.URL = link(template, d.Title, d.Fields)
		if len(d.URL) <= MaxURL {
			break
		}
		long := -1
		for i, f := range d.Fields {
			if long < 0 || len(f.Value) > len(d.Fields[long].Value) {
				long = i
			}
		}
		v := strings.TrimSuffix(d.Fields[long].Value, shortNote)
		r := []rune(v)
		if len(r) < 40 { // nothing left to cut
			break
		}
		d.Fields[long].Value = string(r[:len(r)*3/4]) + shortNote
		d.Shortened = true
	}
	var p strings.Builder
	fmt.Fprintf(&p, "Title: %s\n", d.Title)
	for _, f := range d.Fields {
		if f.Value == "" {
			continue
		}
		fmt.Fprintf(&p, "\n%s:\n%s\n", f.Label, f.Value)
	}
	d.Preview = strings.TrimRight(p.String(), "\n")
	return d
}

func link(template, title string, fields []Field) string {
	q := url.Values{}
	q.Set("template", template)
	q.Set("title", title)
	for _, f := range fields {
		if f.Value != "" {
			q.Set(f.ID, f.Value)
		}
	}
	return "https://github.com/" + Repo + "/issues/new?" + q.Encode()
}
