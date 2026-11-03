package ignore

import (
	"testing"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
)

func TestPickAndRestore(t *testing.T) {
	a := engine.Finding{RuleID: "dev-secret", Severity: "high", Title: "Secret: a/.env", Item: engine.Item{"file": "a/.env"}}
	b := engine.Finding{RuleID: "dev-secret", Severity: "high", Title: "Secret: b/.env", Item: engine.Item{"file": "b/.env"}}
	c := engine.Finding{RuleID: "fw-off", Severity: "medium", Title: "Firewall off", Item: engine.Item{"x": 1}}
	all := []engine.Finding{a, b, c}

	// A rule id hides every place; a key one place; too short or unknown: nothing.
	if got, err := Pick(all, "dev-secret"); err != nil || len(got) != 2 {
		t.Fatalf("rule: %v %v", got, err)
	}
	key := engine.FindingID(b)
	if got, err := Pick(all, key[:8]); err != nil || len(got) != 1 || got[0].Title != b.Title {
		t.Fatalf("key: %v %v", got, err)
	}
	if _, err := Pick(all, key[:3]); err == nil || err.Error() != "ignore.no_match" {
		t.Errorf("short key: %v", err)
	}
	if _, err := Pick(all, "nope-rule"); err == nil {
		t.Error("unknown target accepted")
	}

	st := &Store{Path: t.TempDir() + "/ignores.json"}
	now := time.Now()
	pick, _ := Pick(all, "dev-secret")
	if err := st.Add(pick, 7*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	pick, _ = Pick(all, engine.FindingID(c)[:10])
	_ = st.Add(pick, 24*time.Hour, now)
	es, _ := st.List(now)
	if len(es) != 3 {
		t.Fatalf("entries = %d", len(es))
	}
	if ids := RestoreIDs(es, "dev-secret"); len(ids) != 2 {
		t.Errorf("restore rule = %v", ids)
	}
	if ids := RestoreIDs(es, key[:6]); len(ids) != 1 || ids[0] != key {
		t.Errorf("restore key = %v", ids)
	}
	if ids := RestoreIDs(es, "all"); len(ids) != 3 {
		t.Errorf("restore all = %v", ids)
	}
	if ids := RestoreIDs(es, "zzzzzz"); len(ids) != 0 {
		t.Errorf("restore unknown = %v", ids)
	}
	_ = st.Remove(RestoreIDs(es, "dev-secret"))
	es, _ = st.List(now)
	if len(es) != 1 || es[0].RuleID != "fw-off" {
		t.Errorf("after restore: %+v", es)
	}
	if End(es[0]).Sub(now) > 25*time.Hour {
		t.Errorf("1 day became %s", End(es[0]).Sub(now))
	}
	if !DaysOK(1) || !DaysOK(30) || DaysOK(0) || DaysOK(31) {
		t.Error("days limits")
	}
}
