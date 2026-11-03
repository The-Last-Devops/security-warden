package feedback

import (
	"fmt"
	"net/url"
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
	Kind      string  `json:"kind"` // false_positive or idea
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
