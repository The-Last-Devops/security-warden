// Package rulecheck checks one rule file the way a reviewer would: the
// engine's own validation, its tests, the fields it uses against the source
// schema, the text markup, and the safety lint on its fix commands. The CLI
// (`security-warden rules check`), the MCP server (check_rule) and the Go
// tests of the bundled rules all use it, so they agree.
package rulecheck

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/fixlint"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/rules"
)

// Issue is one problem, at a field of the rule ("fix.en", "tests[2]").
type Issue struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Tests counts the rule's samples that behave as declared.
type Tests struct {
	Passed int `json:"passed"`
	Total  int `json:"total"`
}

// Result is what one check found.
type Result struct {
	File     string  `json:"file"`
	RuleID   string  `json:"rule_id,omitempty"`
	Source   string  `json:"source,omitempty"`
	Tier     string  `json:"tier,omitempty"`
	New      bool    `json:"new,omitempty"`
	Tests    Tests   `json:"tests"`
	Errors   []Issue `json:"errors"`
	Warnings []Issue `json:"warnings"`
}

// OK reports whether the rule passes: no errors, and with strict no
// warnings either.
func (r Result) OK(strict bool) bool {
	return len(r.Errors) == 0 && (!strict || len(r.Warnings) == 0)
}

// Flagged reports whether the safety lint flagged a fix command.
func (r Result) Flagged() bool {
	for _, w := range r.Warnings {
		if strings.HasPrefix(w.Code, "lint.") {
			return true
		}
	}
	return false
}

// Options tune a check.
type Options struct {
	Lang string // language of the messages; default en
	// New marks a newly added rule: it must start as experimental.
	New bool
}

var (
	itemRef     = regexp.MustCompile(`\bitem\s*\.\s*([A-Za-z0-9_]+)|\bitem\s*\[\s*["']([^"']+)["']\s*\]`)
	placeholder = regexp.MustCompile(`\{([a-z0-9_]+)(\|sh)?\}`)
	todo        = regexp.MustCompile(`\bTODO\b`)
)

// SourceNames lists every source a rule may read.
func SourceNames() []string {
	var ns []string
	for _, c := range source.All() {
		ns = append(ns, c.Name)
	}
	return ns
}

// Check checks one rule file. name is the file name ("" when the rule has
// no file, as with check_rule over MCP); data is its YAML.
func Check(name string, data []byte, o Options) Result {
	l := o.Lang
	if l == "" {
		l = i18n.Default
	}
	res := Result{File: name, New: o.New, Errors: []Issue{}, Warnings: []Issue{}}
	msg := func(code string, a ...any) string { return fmt.Sprintf(i18n.T(l, "check."+code), a...) }
	errf := func(field, code string, a ...any) {
		res.Errors = append(res.Errors, Issue{field, code, msg(code, a...)})
	}
	warnf := func(field, code string, a ...any) {
		res.Warnings = append(res.Warnings, Issue{field, code, msg(code, a...)})
	}

	label := name
	if label == "" {
		label = "rule.yaml"
	}
	r, err := engine.Parse(label, data, SourceNames(), fix.CheckRemedy)
	if err != nil {
		errf("", "invalid", strings.TrimPrefix(err.Error(), label+": "))
		return res
	}
	res.RuleID, res.Source, res.Tier = r.ID, r.Source, r.Tier

	if name != "" && path.Base(name) != r.ID+".yaml" {
		errf("id", "file_name", r.ID+".yaml")
	}
	if name != "" {
		for _, b := range builtinRules() {
			if b.ID == r.ID && path.Base(name) != b.File() {
				errf("id", "duplicate_id", b.File())
			}
		}
	}
	if o.New && r.Tier != "experimental" {
		warnf("tier", "not_experimental")
	}

	info := source.Schema[r.Source]
	for _, p := range r.Platforms {
		if !contains(info.Platforms, p) {
			errf("platforms", "platform", r.Source, p)
		}
	}

	// Fields the rule reads must exist in the source.
	for _, m := range itemRef.FindAllStringSubmatch(r.Match, -1) {
		f := m[1] + m[2]
		if _, ok := source.FieldOf(r.Source, f); !ok {
			errf("match", "unknown_field", f, r.Source)
		}
	}
	texts := []struct {
		field string
		t     engine.Text
	}{{"title", r.Title}, {"check", r.Check}, {"explain", r.Explain}, {"fix", r.Fix}}
	for _, tx := range texts {
		for _, lang := range i18n.Supported {
			s, field := tx.t[lang], tx.field+"."+lang
			for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
				if tx.field == "check" {
					errf(field, "check_placeholder", m[0])
				} else if _, ok := source.FieldOf(r.Source, m[1]); !ok {
					errf(field, "unknown_placeholder", m[1], r.Source)
				}
			}
			if strings.Count(s, "`")%2 != 0 {
				errf(field, "backticks")
			}
			if strings.Count(s, "{") != strings.Count(s, "}") {
				errf(field, "braces")
			}
			if todo.MatchString(s) {
				errf(field, "todo")
			}
		}
		if en, vi := strings.TrimSpace(tx.t["en"]), strings.TrimSpace(tx.t["vi"]); en == vi && !todo.MatchString(en) && placeholder.ReplaceAllString(en, "") != "" {
			warnf(tx.field+".vi", "untranslated")
		}
	}
	for i, ref := range r.References {
		if todo.MatchString(ref) {
			errf(fmt.Sprintf("references[%d]", i+1), "todo")
		}
	}
	if todo.MatchString(r.Author) {
		errf("author", "todo")
	}
	// A TODO left in a comment (the skeleton's hints) also counts.
	if todo.Match(data) && !hasCode(res.Errors, "todo") {
		errf("", "todo")
	}
	if r.Remedy != nil {
		for k, v := range r.Remedy.Params {
			for _, m := range placeholder.FindAllStringSubmatch(v, -1) {
				if _, ok := source.FieldOf(r.Source, m[1]); !ok {
					errf("remedy.params."+k, "unknown_placeholder", m[1], r.Source)
				}
			}
		}
	}

	// Tests: every sample behaves as declared, uses real fields with the
	// declared types, and the reported ones fill every placeholder.
	res.Tests.Total = len(r.Tests)
	for i, tc := range r.Tests {
		field := fmt.Sprintf("tests[%d]", i+1)
		keys := make([]string, 0, len(tc.Item))
		for k := range tc.Item {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			f, ok := source.FieldOf(r.Source, k)
			if !ok {
				errf(field, "test_unknown_field", k, r.Source)
				continue
			}
			if t := typeOf(tc.Item[k]); t != f.Type {
				errf(field, "field_type", k, t, r.Source, f.Type)
			}
		}
		got, err := r.Matches(tc.Item)
		switch {
		case err != nil:
			errf(field, "test_error", err.Error())
			continue
		case got != tc.Expect:
			errf(field, "test_failed", got, tc.Expect, tc.Note)
			continue
		}
		res.Tests.Passed++
		if !tc.Expect {
			continue
		}
		for _, tx := range texts {
			if tx.field == "check" {
				continue
			}
			for _, lang := range i18n.Supported {
				out := engine.Render(tx.t[lang], tc.Item)
				if tx.field == "fix" {
					out = engine.RenderFix(tx.t[lang], tc.Item)
				}
				for _, m := range placeholder.FindAllStringSubmatch(out, -1) {
					errf(tx.field+"."+lang, "unfilled", m[1], i+1)
				}
			}
		}
	}

	// Safety lint on the commands people will paste.
	for _, field := range []string{"fix", "explain"} {
		t := r.Fix
		if field == "explain" {
			t = r.Explain
		}
		for _, lang := range i18n.Supported {
			for _, w := range fixlint.Lint(t[lang]) {
				if _, ok := fixlint.Allow(r.ID, w.Code); ok {
					continue
				}
				warnf(field+"."+lang, "lint."+w.Code, w.Command)
			}
		}
	}
	return res
}

var (
	builtinOnce sync.Once
	builtin     []*engine.Rule
)

// builtinRules are the rules embedded in this binary.
func builtinRules() []*engine.Rule {
	builtinOnce.Do(func() { builtin, _ = engine.Load(rules.FS, SourceNames(), fix.CheckRemedy) })
	return builtin
}

func hasCode(is []Issue, code string) bool {
	for _, i := range is {
		if i.Code == code {
			return true
		}
	}
	return false
}

func typeOf(v any) string {
	switch v.(type) {
	case bool:
		return "bool"
	case string:
		return "string"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return "number"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", v)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
