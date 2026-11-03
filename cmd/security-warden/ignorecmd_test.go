package main

import (
	"testing"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/report"
)

func TestIgnoreAddRestore(t *testing.T) {
	a := engine.Finding{RuleID: "dev-secret", Severity: "high", Title: "Secret: a/.env", Item: engine.Item{"file": "a/.env"}}
	b := engine.Finding{RuleID: "dev-secret", Severity: "high", Title: "Secret: b/.env", Item: engine.Item{"file": "b/.env"}}
	c := engine.Finding{RuleID: "fw-off", Severity: "medium", Title: "Firewall off", Item: engine.Item{"x": 1}}
	all := []engine.Finding{a, b, c}

	// A rule id hides every place; a key one place; too short or unknown: nothing.
	if got, err := pickFindings(all, "dev-secret"); err != nil || len(got) != 2 {
		t.Fatalf("rule: %v %v", got, err)
	}
	key := engine.FindingID(b)
	if got, err := pickFindings(all, key[:8]); err != nil || len(got) != 1 || got[0].Title != b.Title {
		t.Fatalf("key: %v %v", got, err)
	}
	if _, err := pickFindings(all, key[:3]); err == nil || err.Error() != "ignore.no_match" {
		t.Errorf("short key: %v", err)
	}
	if _, err := pickFindings(all, "nope-rule"); err == nil {
		t.Error("unknown target accepted")
	}

	st := &ignore.Store{Path: t.TempDir() + "/ignores.json"}
	now := time.Now()
	pick, _ := pickFindings(all, "dev-secret")
	if err := st.Add(pick, 7*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	pick, _ = pickFindings(all, engine.FindingID(c)[:10])
	_ = st.Add(pick, 24*time.Hour, now)
	es, _ := st.List(now)
	if len(es) != 3 {
		t.Fatalf("entries = %d", len(es))
	}
	if ids := restoreIDs(es, "dev-secret"); len(ids) != 2 {
		t.Errorf("restore rule = %v", ids)
	}
	if ids := restoreIDs(es, key[:6]); len(ids) != 1 || ids[0] != key {
		t.Errorf("restore key = %v", ids)
	}
	if ids := restoreIDs(es, "all"); len(ids) != 3 {
		t.Errorf("restore all = %v", ids)
	}
	if ids := restoreIDs(es, "zzzzzz"); len(ids) != 0 {
		t.Errorf("restore unknown = %v", ids)
	}
	_ = st.Remove(restoreIDs(es, "dev-secret"))
	es, _ = st.List(now)
	if len(es) != 1 || es[0].RuleID != "fw-off" {
		t.Errorf("after restore: %+v", es)
	}
	if end(es[0]).Sub(now) > 25*time.Hour {
		t.Errorf("1 day became %s", end(es[0]).Sub(now))
	}
	if !hideDaysOK(1) || !hideDaysOK(30) || hideDaysOK(0) || hideDaysOK(31) {
		t.Error("days limits")
	}
}

func TestCheckFilters(t *testing.T) {
	for _, o := range []report.Options{{}, {Scope: "machine"}, {Scope: "code", Category: "code_deps"}, {Category: "ai"}} {
		if e := checkFilters("en", o); e != "" {
			t.Errorf("%+v refused: %s", o, e)
		}
	}
	for _, o := range []report.Options{{Scope: "laptop"}, {Category: "nope"}} {
		if e := checkFilters("en", o); e == "" {
			t.Errorf("%+v accepted", o)
		}
	}
}
