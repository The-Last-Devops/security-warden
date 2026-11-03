package main

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/rules"
)

func loadRules(t *testing.T) []*engine.Rule {
	t.Helper()
	var names []string
	for _, c := range source.All() {
		names = append(names, c.Name)
	}
	rs, err := engine.Load(rules.FS, names, fix.CheckRemedy)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestFeedbackFinding(t *testing.T) {
	home, _ := os.UserHomeDir()
	rs := loadRules(t)
	f := engine.Finding{RuleID: "credential-file-readable-by-others", Severity: "high", Source: "credential_files",
		Title: "Credential file readable by other users: " + home + "/.aws/credentials", Explain: "Others can read it.",
		Fix: "Run `chmod 600 " + home + "/.aws/credentials`", Item: engine.Item{"path": home + "/.aws/credentials", "mode": "0644"}}
	scan := func() []engine.Finding { return []engine.Finding{f} }
	var opened string
	old := openURL
	openURL = func(u string) error { opened = u; return nil }
	defer func() { openURL = old }()

	var out strings.Builder
	key := engine.FindingID(f)[:8]
	if code := runFeedback(&out, "en", rs, []string{key}, "", false, false, scan); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "https://github.com/The-Last-Devops/security-warden/issues/new?") || !strings.Contains(s, "~/.aws/credentials") ||
		!strings.Contains(s, "Nothing has been sent") || opened != "" {
		t.Fatalf("output:\n%s", s)
	}
	if len(home) > 1 && strings.Contains(s, home) {
		t.Fatalf("home folder in output:\n%s", s)
	}

	out.Reset()
	runFeedback(&out, "vi", rs, []string{"credential-file-readable-by-others"}, "", false, true, scan)
	if u, err := url.Parse(opened); err != nil || u.Host != "github.com" || !strings.Contains(out.String(), "Đã mở") {
		t.Fatalf("--open: %q, %s", opened, out.String())
	}
}

func TestFeedbackRuleNotFailing(t *testing.T) {
	var out strings.Builder
	none := func() []engine.Finding { return nil }
	if code := runFeedback(&out, "en", loadRules(t), []string{"backup-none"}, "", false, false, none); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "does not fail on this machine") || !strings.Contains(out.String(), "False+positive%3A+backup-none") {
		t.Fatalf("output:\n%s", out.String())
	}
	if code := runFeedback(&out, "en", loadRules(t), []string{"no-such-thing"}, "", false, false, none); code != 2 {
		t.Fatalf("unknown target: exit %d", code)
	}
}

func TestFeedbackIdea(t *testing.T) {
	var out strings.Builder
	rs := loadRules(t)
	if code := runFeedback(&out, "en", rs, nil, "Check ~/.npmrc for tokens", true, false, nil); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "template=rule-request.yml") || !strings.Contains(out.String(), "Rule: Check ~/.npmrc for tokens") {
		t.Fatalf("output:\n%s", out.String())
	}
	if code := runFeedback(&out, "en", rs, nil, "  ", true, false, nil); code != 2 {
		t.Fatal("empty idea accepted")
	}
	if code := runFeedback(&out, "en", rs, nil, "", false, false, nil); code != 2 {
		t.Fatal("no target accepted")
	}
}
