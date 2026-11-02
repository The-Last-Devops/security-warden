// Package engine loads declarative rules and matches them against the items
// collected by the sources. Rules can only read items through CEL; they can
// never run commands or touch files.
package engine

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

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
	Explain    Text     `yaml:"explain"`
	Fix        Text     `yaml:"fix"`
	References []string `yaml:"references"`
	Author     string   `yaml:"author"`
	Tests      []Test   `yaml:"tests"`

	file string
	prg  cel.Program
}

// File is where the rule was loaded from.
func (r *Rule) File() string { return r.file }

// Severities in report order, with the points each finding costs.
var Severities = []string{"critical", "high", "medium", "low", "info"}

var penalty = map[string]int{"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}

var tiers = map[string]bool{"stable": true, "community": true, "experimental": true}

var idPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

func newEnv() (*cel.Env, error) {
	return cel.NewEnv(cel.Variable("item", cel.MapType(cel.StringType, cel.DynType)))
}

// Load parses and compiles every *.yaml rule in fsys. knownSources lists the
// source names a rule may refer to.
func Load(fsys fs.FS, knownSources []string) ([]*Rule, error) {
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
		if r.prg, err = env.Program(ast); err != nil {
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
	for name, t := range map[string]Text{"title": r.Title, "explain": r.Explain, "fix": r.Fix} {
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
			return fmt.Sprint(v)
		}
		return m
	})
}

// Finding is one rule matching one item, rendered in one language.
type Finding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Title    string `json:"title"`
	Explain  string `json:"explain"`
	Fix      string `json:"fix"`
	Item     Item   `json:"item"`
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

// Score is 100 minus a penalty per finding, never below 0.
func Score(fs []Finding) int {
	s := 100
	for _, f := range fs {
		s -= penalty[f.Severity]
	}
	return max(s, 0)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
