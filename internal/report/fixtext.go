package report

import (
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
)

// Fix texts carry light markup, read the same way as the web UI does
// (web/src/components/FixSteps.vue and web/src/fixgroup.js):
//   - `backticks` mark code; code with a space, or longer than 32
//     characters, is a command that gets its own line;
//   - a text that starts with "1. " is a list of numbered steps.

// IsBlock reports whether code is a command (its own line) rather than a
// short name kept inline.
func IsBlock(code string) bool {
	return strings.Contains(code, " ") || len([]rune(code)) > 32
}

// Part is a piece of one step: plain text, or code.
type Part struct {
	Text   string
	Code   string
	IsCode bool
}

var (
	stepStart = regexp.MustCompile(`^1\.\s`)
	stepNum   = regexp.MustCompile(`^\d{1,2}\.\s+`)
	codeSpan  = regexp.MustCompile("`[^`]+`")
	separator = regexp.MustCompile(`^\s*[·,;]?\s*$`)
)

// splitSteps is s.split(/\s(?=\d{1,2}\.\s)/): Go's regexp has no
// lookahead, so it is done by hand.
func splitSteps(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' && s[i] != '\n' && s[i] != '\r' {
			continue
		}
		j := i + 1
		k := j
		for k < len(s) && k-j < 2 && s[k] >= '0' && s[k] <= '9' {
			k++
		}
		if k == j || k+1 >= len(s) || s[k] != '.' {
			continue
		}
		if c := s[k+1]; c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			continue
		}
		out = append(out, s[start:i])
		start = j
	}
	return append(out, s[start:])
}

// ParseSteps turns a fix text into steps (one when the text is not a
// numbered list), each a sequence of text and code parts.
func ParseSteps(fix string) [][]Part {
	s := strings.TrimSpace(fix)
	items := []string{s}
	if stepStart.MatchString(s) {
		items = nil
		for _, x := range splitSteps(s) {
			items = append(items, stepNum.ReplaceAllString(x, ""))
		}
	}
	out := make([][]Part, 0, len(items))
	for _, it := range items {
		out = append(out, parseParts(it))
	}
	return out
}

func parseParts(step string) []Part {
	var parts []Part
	last := 0
	for _, m := range codeSpan.FindAllStringIndex(step, -1) {
		if m[0] > last {
			parts = append(parts, Part{Text: step[last:m[0]]})
		}
		parts = append(parts, Part{Code: step[m[0]+1 : m[1]-1], IsCode: true})
		last = m[1]
	}
	if last < len(step) {
		parts = append(parts, Part{Text: step[last:]})
	}
	// Separators between two commands ("·", ",") are noise once each
	// command has its own line.
	block := func(i int) bool { return i >= 0 && i < len(parts) && parts[i].IsCode && IsBlock(parts[i].Code) }
	var keep []Part
	for i, p := range parts {
		if !p.IsCode && separator.MatchString(p.Text) && block(i-1) && block(i+1) {
			continue
		}
		keep = append(keep, p)
	}
	return keep
}

// Commands lists the block commands of a fix text, in order.
func Commands(fix string) []string {
	var out []string
	for _, m := range codeSpan.FindAllString(fix, -1) {
		if c := m[1 : len(m)-1]; IsBlock(c) {
			out = append(out, c)
		}
	}
	return out
}

// PlaceCmds is one place of a problem and the commands for it.
type PlaceCmds struct {
	Place string
	Cmds  []string
}

// PerPlace says which commands differ between the places of one problem.
type PerPlace struct {
	Hide   map[string]bool // commands left out of the steps (listed per place)
	Places []PlaceCmds
	Plan   bool // the commands are auto-fix plans
}

// PerPlaceOf returns nil when every place shares the same commands (or
// there is one place). plans[i] is the auto-fix plan of fs[i], if any; when
// the first finding has a plan, each place lists its plan.
func PerPlaceOf(fs []engine.Finding, plans [][]string) *PerPlace {
	if len(fs) < 2 {
		return nil
	}
	if len(plans) > 0 && len(plans[0]) > 0 {
		pp := &PerPlace{Hide: map[string]bool{}, Plan: true}
		for i, f := range fs {
			var cmds []string
			if i < len(plans) {
				cmds = plans[i]
			}
			pp.Places = append(pp.Places, PlaceCmds{PlaceOf(f), cmds})
		}
		return pp
	}
	lists := make([][]string, len(fs))
	for i, f := range fs {
		lists[i] = Commands(Tilde(engine.Clean(f.Fix)))
	}
	in := func(l []string, c string) bool {
		for _, x := range l {
			if x == c {
				return true
			}
		}
		return false
	}
	shared := map[string]bool{}
	for _, c := range lists[0] {
		all := true
		for _, l := range lists {
			if !in(l, c) {
				all = false
				break
			}
		}
		if all {
			shared[c] = true
		}
	}
	differ := make([][]string, len(lists))
	for i, l := range lists {
		for _, c := range l {
			if !shared[c] {
				differ[i] = append(differ[i], c)
			}
		}
	}
	if len(differ[0]) == 0 {
		return nil
	}
	pp := &PerPlace{Hide: map[string]bool{}}
	for _, c := range differ[0] {
		pp.Hide[c] = true
	}
	for i, f := range fs {
		pp.Places = append(pp.Places, PlaceCmds{PlaceOf(f), differ[i]})
	}
	return pp
}

// Plan lists the commands the auto-fix of f would run, shortened for
// people; nil when f has no auto-fix.
func Plan(f engine.Finding) []string {
	if f.Remedy == nil {
		return nil
	}
	a, ok := fix.Get(f.Remedy.Action)
	if !ok {
		return nil
	}
	var out []string
	for _, p := range a.Plan(f.Remedy.Params) {
		out = append(out, Tilde(engine.Clean(p)))
	}
	return out
}

// Tilde shows the home folder as ~. A quoted path keeps working once
// shortened: '/home/u/a b' becomes ~/'a b' (inside quotes ~ would not mean
// the home folder).
func Tilde(s string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		s = strings.ReplaceAll(s, "'"+h+"/", "~/'")
		return strings.ReplaceAll(s, h, "~")
	}
	return s
}

// Repo is the repository a code finding is in ("" for the machine).
func Repo(f engine.Finding) string {
	if Scope(f.Source) != "code" {
		return ""
	}
	if v, ok := f.Item["repo_name"].(string); ok {
		return engine.Clean(v)
	}
	return ""
}

// Place is where a finding is, from its item: a file, path or name.
func Place(f engine.Finding) string {
	for _, k := range []string{"file", "path", "name"} {
		if v, ok := f.Item[k].(string); ok && v != "" {
			p := Tilde(engine.Clean(v))
			if r := Repo(f); r != "" && k == "file" {
				p = r + "/" + p
			}
			return p
		}
	}
	return ""
}

// PlaceOf is the short place to list under a problem: the part of the
// title after ": ", else the item's place, else the title.
func PlaceOf(f engine.Finding) string {
	t := Tilde(engine.Clean(f.Title))
	if i := strings.Index(t, ": "); i >= 0 {
		return t[i+2:]
	}
	if p := Place(f); p != "" {
		return p
	}
	return t
}

// Headline is the problem without the specific place ("X: detail" -> X).
func Headline(title string) string {
	if i := strings.Index(title, ": "); i > 0 {
		return title[:i]
	}
	return title
}

// Group is one problem (a rule) with every place it was found.
type Group struct {
	RuleID string
	All    []engine.Finding // the first one leads
}

// Groups puts findings of one rule together, worst severity first, keeping
// the order in which rules first appear otherwise.
func Groups(fs []engine.Finding) []Group {
	idx := map[string]int{}
	var out []Group
	for _, f := range fs {
		i, ok := idx[f.RuleID]
		if !ok {
			i = len(out)
			idx[f.RuleID] = i
			out = append(out, Group{RuleID: f.RuleID})
		}
		out[i].All = append(out[i].All, f)
	}
	rank := sevRank()
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].All[0].Severity] < rank[out[j].All[0].Severity] })
	return out
}

func sevRank() map[string]int {
	r := map[string]int{}
	for i, s := range engine.Severities {
		r[s] = i
	}
	return r
}
