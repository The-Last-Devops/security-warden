// Package engine loads declarative rules and matches them against the items
// collected by the sources. Rules can only read items through CEL; they can
// never run commands or touch files.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"gopkg.in/yaml.v3"

	"github.com/The-Last-Devops/security-warden/internal/i18n"
)

// Item mirrors source.Item without importing it.
type Item = map[string]any

// Text is a translated string: language code -> text.
type Text map[string]string

// Get returns the text in lang, falling back to English.
func (t Text) Get(lang string) string {
	if s := t[lang]; s != "" {
		return s
	}
	return t[i18n.Default]
}

// Test is a sample item and whether the rule must report it.
type Test struct {
	Item   Item   `yaml:"item"`
	Expect bool   `yaml:"expect"`
	Note   string `yaml:"note"`
}

// Rule is one check, loaded from a YAML file.
type Rule struct {
	ID         string   `yaml:"id"`
	Severity   string   `yaml:"severity"`
	Tier       string   `yaml:"tier"`
	Platforms  []string `yaml:"platforms"`
	Source     string   `yaml:"source"`
	Match      string   `yaml:"match"`
	Title      Text     `yaml:"title"`
	Check      Text     `yaml:"check"` // the check stated positively, for the passed list
	Explain    Text     `yaml:"explain"`
	Fix        Text     `yaml:"fix"`
	References []string `yaml:"references"`
	Author     string   `yaml:"author"`
	Tests      []Test   `yaml:"tests"`
	// Remedy names a built-in fix action; rules never carry commands.
	Remedy *Remedy `yaml:"remedy"`

	file string
	prg  cel.Program
}

// Remedy points a rule at a fix action, with parameters filled from the
// finding ({field} placeholders).
type Remedy struct {
	Action string            `yaml:"action" json:"action"`
	Params map[string]string `yaml:"params" json:"params,omitempty"`
}

// File is where the rule was loaded from.
func (r *Rule) File() string { return r.file }

// Severities in report order, with the points each finding costs.
var Severities = []string{"critical", "high", "medium", "low", "info"}

var penalty = map[string]int{"critical": 30, "high": 10, "medium": 4, "low": 1, "info": 0}

var tiers = map[string]bool{"stable": true, "community": true, "experimental": true}

var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func newEnv() (*cel.Env, error) {
	return cel.NewEnv(cel.Variable("item", cel.MapType(cel.StringType, cel.DynType)))
}

// Load parses and compiles every *.yaml rule in fsys. knownSources lists the
// source names a rule may refer to.
// RemedyCheck validates a rule's remedy for its source; the fix package
// supplies it, so only allowed (action, source, field) combinations load.
type RemedyCheck func(action, source string, params map[string]string) error

func Load(fsys fs.FS, knownSources []string, checkRemedy RemedyCheck) ([]*Rule, error) {
	env, err := newEnv()
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, s := range knownSources {
		known[s] = true
	}

	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	seen := map[string]string{}
	var rules []*Rule
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		var r Rule
		dec := yaml.NewDecoder(strings.NewReader(string(b)))
		dec.KnownFields(true)
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		r.file = path.Base(f)
		if r.Remedy != nil {
			if err := checkRemedy(r.Remedy.Action, r.Source, r.Remedy.Params); err != nil {
				return nil, fmt.Errorf("%s: remedy: %w", f, err)
			}
		}
		if err := validate(&r, known); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if other, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("%s: id %q already used by %s", f, r.ID, other)
		}
		seen[r.ID] = f
		ast, iss := env.Compile(r.Match)
		if iss.Err() != nil {
			return nil, fmt.Errorf("%s: match: %w", f, iss.Err())
		}
		// item fields are dyn, so "item.x" alone type-checks as dyn; Matches
		// still rejects a non-boolean result at run time.
		if t := ast.OutputType(); t != cel.BoolType && t != cel.DynType {
			return nil, fmt.Errorf("%s: match must be a boolean expression", f)
		}
		// Cost limit: a rule cannot make a scan or watch tick spin.
		if r.prg, err = env.Program(ast, cel.CostLimit(100_000), cel.InterruptCheckFrequency(100)); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		rules = append(rules, &r)
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}

func validate(r *Rule, known map[string]bool) error {
	if !idPattern.MatchString(r.ID) {
		return fmt.Errorf("id %q must be kebab-case", r.ID)
	}
	if _, ok := penalty[r.Severity]; !ok {
		return fmt.Errorf("unknown severity %q", r.Severity)
	}
	if r.Tier == "" {
		r.Tier = "stable"
	}
	if !tiers[r.Tier] {
		return fmt.Errorf("unknown tier %q", r.Tier)
	}
	if !known[r.Source] {
		return fmt.Errorf("unknown source %q", r.Source)
	}
	if len(r.Platforms) == 0 {
		return fmt.Errorf("platforms is required")
	}
	for name, t := range map[string]Text{"title": r.Title, "check": r.Check, "explain": r.Explain, "fix": r.Fix} {
		for _, lang := range i18n.Supported {
			if strings.TrimSpace(t[lang]) == "" {
				return fmt.Errorf("%s: missing %q translation", name, lang)
			}
		}
	}
	var pos, neg bool
	for _, t := range r.Tests {
		pos = pos || t.Expect
		neg = neg || !t.Expect
	}
	if !pos || !neg {
		return fmt.Errorf("needs at least one test that must report and one that must not")
	}
	return nil
}

// Matches evaluates the rule on one item. A missing field is an error, so
// rules guard optional fields with has(item.x).
func (r *Rule) Matches(it Item) (bool, error) {
	out, _, err := r.prg.Eval(map[string]any{"item": it})
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("match did not return a boolean")
	}
	return b, nil
}

var placeholder = regexp.MustCompile(`\{([a-z0-9_]+)\}`)

// Render fills {field} placeholders from the item.
func Render(s string, it Item) string {
	return placeholder.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := it[m[1:len(m)-1]]; ok {
			return Clean(fmt.Sprint(v))
		}
		return m
	})
}

// Clean makes a value from the machine (a file, repo, process or extension
// name, all of which an attacker can choose) safe to print: control
// characters and bidi overrides are shown escaped, so they cannot move the
// cursor, rewrite earlier lines or reorder text on screen.
func Clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError, unicode.IsControl(r),
			r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F, r == 0x061C:
			b.WriteString(strings.Trim(strconv.QuoteRune(r), "'"))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// FindingID names a finding by its rule and the facts it matched, so the
// id is the same in every language and across rescans.
func FindingID(f Finding) string {
	b, _ := json.Marshal(f.Item) // map keys are sorted: stable
	h := sha256.Sum256(append([]byte(f.RuleID+"\x00"), b...))
	return hex.EncodeToString(h[:12])
}

// Finding is one rule matching one item, rendered in one language.
type Finding struct {
	RuleID   string  `json:"rule_id"`
	Severity string  `json:"severity"`
	Source   string  `json:"source"`
	Title    string  `json:"title"`
	Explain  string  `json:"explain"`
	Fix      string  `json:"fix"`
	Remedy   *Remedy `json:"remedy,omitempty"`
	Item     Item    `json:"item"`
}

// Evaluate runs the rules that apply to platform on the collected items.
// Experimental rules run but never report.
func Evaluate(rules []*Rule, items map[string][]Item, platform, lang string) []Finding {
	var out []Finding
	for _, r := range rules {
		if r.Tier == "experimental" || !contains(r.Platforms, platform) {
			continue
		}
		for _, it := range items[r.Source] {
			ok, err := r.Matches(it)
			if err != nil || !ok {
				continue
			}
			out = append(out, Finding{
				RuleID:   r.ID,
				Severity: r.Severity,
				Source:   r.Source,
				Title:    Render(r.Title.Get(lang), it),
				Explain:  Render(r.Explain.Get(lang), it),
				Fix:      Render(r.Fix.Get(lang), it),
				Remedy:   renderRemedy(r.Remedy, it),
				Item:     it,
			})
		}
	}
	rank := map[string]int{}
	for i, s := range Severities {
		rank[s] = i
	}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

// Coverage lists the rules that ran on platform against a source that
// worked (ran is the set of such sources) and did not report anything.
func Coverage(rules []*Rule, findings []Finding, ran map[string]bool, platform string) (checked int, passed []string) {
	hit := map[string]bool{}
	for _, f := range findings {
		hit[f.RuleID] = true
	}
	for _, r := range rules {
		if r.Tier == "experimental" || !contains(r.Platforms, platform) || !ran[r.Source] {
			continue
		}
		checked++
		if !hit[r.ID] {
			passed = append(passed, r.ID)
		}
	}
	return checked, passed
}

func renderRemedy(r *Remedy, it Item) *Remedy {
	if r == nil {
		return nil
	}
	out := &Remedy{Action: r.Action, Params: map[string]string{}}
	for k, v := range r.Params {
		out.Params[k] = Render(v, it)
	}
	return out
}

// Weights per severity: how much a check counts toward the score.
var weight = map[string]int{"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}

// Score is the share of applicable checks that pass, weighted by
// severity: a rule counts once however many places it fires. While a
// critical problem remains the score stays below 70, so a leaked key never
// reads as "good". Gain is how many points fixing each failing rule earns.
func Score(rules []*Rule, findings []Finding, ran map[string]bool, platform string) (score int, gain map[string]int) {
	failing := map[string]string{} // rule -> severity
	for _, f := range findings {
		failing[f.RuleID] = f.Severity
	}
	var applicable []*Rule
	for _, r := range rules {
		if r.Tier != "experimental" && contains(r.Platforms, platform) && ran[r.Source] {
			applicable = append(applicable, r)
		}
	}
	// scoreWithout computes the score if the rule "skip" were fixed.
	scoreWithout := func(skip string) int {
		total, passed, critical := 0, 0, false
		for _, r := range applicable {
			w := weight[r.Severity]
			total += w
			sev, bad := failing[r.ID]
			if !bad || r.ID == skip {
				passed += w
			} else if sev == "critical" {
				critical = true
			}
		}
		if total == 0 {
			return 100
		}
		s := (passed*100 + total/2) / total
		if critical && s > 69 {
			s = 69
		}
		return s
	}
	score = scoreWithout("")
	gain = map[string]int{}
	for id := range failing {
		if g := scoreWithout(id) - score; g > 0 {
			gain[id] = g
		}
	}
	return score, gain
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
