package engine_test

import (
	"testing"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/rules"
)

func sourceNames() []string {
	var ns []string
	for _, c := range source.All() {
		ns = append(ns, c.Name)
	}
	return ns
}

// Every bundled rule must load and pass its own sample items. This is the
// check CI runs on every contributed rule.
func TestBundledRules(t *testing.T) {
	rs, err := engine.Load(rules.FS, sourceNames(), fix.IDs())
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("no rules loaded")
	}
	for _, r := range rs {
		for i, tc := range r.Tests {
			got, err := r.Matches(tc.Item)
			if err != nil {
				t.Errorf("%s test %d: %v", r.File(), i+1, err)
				continue
			}
			if got != tc.Expect {
				t.Errorf("%s test %d (%s): got %v, want %v", r.File(), i+1, tc.Note, got, tc.Expect)
			}
		}
		// Placeholders must refer to fields the positive samples have.
		for _, tc := range r.Tests {
			if !tc.Expect {
				continue
			}
			for _, lang := range []string{"en", "vi"} {
				for _, s := range []string{r.Title.Get(lang), r.Explain.Get(lang), r.Fix.Get(lang)} {
					if out := engine.Render(s, tc.Item); containsPlaceholder(out) {
						t.Errorf("%s: unfilled placeholder in %q", r.File(), out)
					}
				}
			}
		}
	}
}

func containsPlaceholder(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '{' {
			for j := i + 1; j < len(s) && j < i+40; j++ {
				if s[j] == '}' {
					return true
				}
				c := s[j]
				if !(c == '_' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
					break
				}
			}
		}
	}
	return false
}

func TestScore(t *testing.T) {
	fs := []engine.Finding{{RuleID: "a", Severity: "high"}, {RuleID: "b", Severity: "medium"}, {RuleID: "c", Severity: "info"}}
	if got := engine.Score(fs); got != 86 {
		t.Errorf("score = %d, want 86", got)
	}
	// The same rule five times costs its penalty plus at most half again.
	many := []engine.Finding{{RuleID: "a", Severity: "high"}, {RuleID: "a", Severity: "high"}, {RuleID: "a", Severity: "high"}, {RuleID: "a", Severity: "high"}, {RuleID: "a", Severity: "high"}}
	if got := engine.Score(many); got != 100-10-5 {
		t.Errorf("repeated score = %d, want %d", got, 100-10-5)
	}
}
