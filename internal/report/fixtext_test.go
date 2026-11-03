package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/The-Last-Devops/security-warden/internal/engine"
)

func TestIsBlock(t *testing.T) {
	for code, want := range map[string]bool{
		".gitignore": false, "git rm --cached x": true,
		"~/Library/Application Support/x":         true,
		"averyveryverylongnamewithoutspacesatall": true,
	} {
		if IsBlock(code) != want {
			t.Errorf("IsBlock(%q) = %v", code, !want)
		}
	}
}

func TestParseSteps(t *testing.T) {
	s := ParseSteps("1. Run `brew update` first. 2. Then `brew upgrade x` · `brew cleanup x` 10. Done with `.env`.")
	if len(s) != 3 {
		t.Fatalf("steps = %d: %+v", len(s), s)
	}
	if s[0][0].Text != "Run " || !s[0][1].IsCode || s[0][1].Code != "brew update" {
		t.Errorf("step 1 = %+v", s[0])
	}
	// The " · " between two commands is dropped.
	for _, p := range s[1] {
		if !p.IsCode && strings.TrimSpace(p.Text) == "·" {
			t.Errorf("separator kept: %+v", s[1])
		}
	}
	if s[2][1].Code != ".env" {
		t.Errorf("step 10 = %+v", s[2])
	}
	// Not a list unless it starts with "1. "; "123. " never splits.
	if n := len(ParseSteps("Update to 2. something")); n != 1 {
		t.Errorf("plain text split into %d", n)
	}
	if n := len(ParseSteps("1. a 123. b")); n != 1 {
		t.Errorf("three digits split: %d", n)
	}
	if got := Commands("Use `a b`, `short` and `c d`"); len(got) != 2 || got[1] != "c d" {
		t.Errorf("Commands = %v", got)
	}
}

func fnd(rule, sev, src, title, fix string, item engine.Item) engine.Finding {
	return engine.Finding{RuleID: rule, Severity: sev, Source: src, Title: title, Fix: fix, Explain: "Why.", Item: item}
}

func TestPerPlace(t *testing.T) {
	a := fnd("r", "high", "dev_files", "Secret: a/.env", "1. Run `git rm --cached a/.env`. 2. Rotate with `vault rotate all`.", engine.Item{"file": ".env"})
	b := fnd("r", "high", "dev_files", "Secret: b/.env", "1. Run `git rm --cached b/.env`. 2. Rotate with `vault rotate all`.", engine.Item{"file": ".env"})
	pp := PerPlaceOf([]engine.Finding{a, b}, nil)
	if pp == nil || pp.Plan || !pp.Hide["git rm --cached a/.env"] || pp.Hide["vault rotate all"] {
		t.Fatalf("pp = %+v", pp)
	}
	if pp.Places[1].Place != "b/.env" || len(pp.Places[1].Cmds) != 1 || pp.Places[1].Cmds[0] != "git rm --cached b/.env" {
		t.Errorf("places = %+v", pp.Places)
	}
	// Same commands everywhere, or one place: nothing per place.
	if PerPlaceOf([]engine.Finding{a, a}, nil) != nil || PerPlaceOf([]engine.Finding{a}, nil) != nil {
		t.Error("per-place for shared commands")
	}
	// Auto-fix plans: each place lists its plan.
	pp = PerPlaceOf([]engine.Finding{a, b}, [][]string{{"chmod 600 a"}, {"chmod 600 b"}})
	if pp == nil || !pp.Plan || pp.Places[1].Cmds[0] != "chmod 600 b" {
		t.Errorf("plan pp = %+v", pp)
	}
}

func TestGroupsWorstFirst(t *testing.T) {
	gs := Groups([]engine.Finding{
		fnd("low1", "low", "posture", "L", "", nil),
		fnd("hi", "high", "posture", "H: 1", "", nil),
		fnd("crit", "critical", "posture", "C", "", nil),
		fnd("hi", "high", "posture", "H: 2", "", nil),
	})
	if len(gs) != 3 || gs[0].RuleID != "crit" || gs[1].RuleID != "hi" || len(gs[1].All) != 2 {
		t.Fatalf("groups = %+v", gs)
	}
}

func testScan() Scan {
	return Scan{
		Lang: "en", Score: 60, ScoreMachine: 80, ScoreCode: 30, Checked: 3, Passed: []string{"ok-rule"},
		Findings: []engine.Finding{
			fnd("secret", "critical", "dev_files", "Secret file: api/.env", "1. Remove it: `git -C /r/api rm --cached .env`. 2. Rotate the keys.", engine.Item{"file": ".env", "repo_name": "api"}),
			fnd("secret", "critical", "dev_files", "Secret file: web/.env", "1. Remove it: `git -C /r/web rm --cached .env`. 2. Rotate the keys.", engine.Item{"file": ".env", "repo_name": "web"}),
			fnd("fw", "high", "posture", "Firewall is off", "Turn it on: `sudo fw on`.", nil),
		},
	}
}

func TestTextReport(t *testing.T) {
	var b bytes.Buffer
	Text(&b, testScan(), Options{})
	out := b.String()
	for _, want := range []string{
		"This machine", " 80/100", "Your code", " 30/100", "[CRITICAL] · 1", "[HIGH] · 1",
		"(command for each place below)", "Command for each place (2):", "api/.env",
		"$ git -C /r/web rm --cached .env", "2. Rotate the keys.", "$ sudo fw on",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "`") {
		t.Error("backticks left in the report")
	}
	if strings.Contains(out, "$ git -C /r/api rm --cached .env\n  |   2.") {
		t.Error("per-place command printed in the shared steps")
	}
}

func TestTextFilters(t *testing.T) {
	var b bytes.Buffer
	Text(&b, testScan(), Options{Scope: "machine"})
	if out := b.String(); strings.Contains(out, "Secret file") || !strings.Contains(out, "Firewall") || !strings.Contains(out, "Showing only: This machine") {
		t.Errorf("--scope machine:\n%s", out)
	}
	b.Reset()
	Text(&b, testScan(), Options{Category: "code_secrets"})
	if out := b.String(); strings.Contains(out, "Firewall") || !strings.Contains(out, "Secret file") {
		t.Errorf("--category code_secrets:\n%s", out)
	}
	b.Reset()
	Text(&b, testScan(), Options{ByRepo: true})
	out := b.String()
	m, api, web := strings.Index(out, "■ This machine"), strings.Index(out, "■ api"), strings.Index(out, "■ web")
	if m < 0 || api < 0 || web < 0 || m > api {
		t.Errorf("--by-repo sections (machine first):\n%s", out)
	}
	b.Reset()
	rules := []*engine.Rule{{ID: "ok-rule", Source: "posture", Check: engine.Text{"en": "The disk is encrypted"}}}
	Text(&b, testScan(), Options{Safe: true, Rules: rules})
	if out := b.String(); !strings.Contains(out, "System settings") || !strings.Contains(out, "✓ The disk is encrypted") || strings.Contains(out, "Firewall") {
		t.Errorf("--safe:\n%s", out)
	}
}

func TestTextVerboseKeys(t *testing.T) {
	var b bytes.Buffer
	s := testScan()
	Text(&b, s, Options{Verbose: true})
	if k := ShortKey(s.Findings[1]); !strings.Contains(b.String(), "["+k+"]") {
		t.Errorf("verbose report lacks key %s", k)
	}
}
