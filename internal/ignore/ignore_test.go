package ignore

import (
	"testing"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
)

func TestSnoozeAndExpire(t *testing.T) {
	s := &Store{Path: t.TempDir() + "/ignores.json"}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	port := engine.Finding{RuleID: "port", Title: "node 3000", Severity: "medium", Item: engine.Item{"port": 3000}}
	key := engine.Finding{RuleID: "key", Title: "k.pem", Severity: "critical", Item: engine.Item{"path": "/k.pem"}}
	other := engine.Finding{RuleID: "port", Title: "node 4000", Severity: "medium", Item: engine.Item{"port": 4000}}

	if err := s.Add([]engine.Finding{port}, 7*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Add([]engine.Finding{key}, 0, now); err != nil { // 0 never means for good
		t.Fatal(err)
	}
	es, _ := s.List(now)
	shown, ignored := Split([]engine.Finding{port, key, other}, es, now)
	if len(ignored) != 2 || len(shown) != 1 || shown[0].Title != "node 4000" {
		t.Fatalf("shown=%v ignored=%v", shown, ignored)
	}
	for _, e := range es {
		if e.Until.IsZero() || e.Until.Sub(now) > MaxHide {
			t.Errorf("%s hidden for longer than 30 days", e.RuleID)
		}
	}
	later := now.Add(8 * 24 * time.Hour)
	es, _ = s.List(later)
	shown, _ = Split([]engine.Finding{port, key, other}, es, later)
	if len(shown) != 2 {
		t.Errorf("port finding should be back after 7 days, shown=%v", shown)
	}
	s.Remove(nil)
	if es, _ := s.List(now); len(es) != 0 {
		t.Error("clear left entries")
	}
}

func TestHideNeverLongerThan30Days(t *testing.T) {
	s := &Store{Path: t.TempDir() + "/ignores.json"}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	f := engine.Finding{RuleID: "port", Title: "node 3000", Severity: "low", Item: engine.Item{"port": 3000}}
	if err := s.Add([]engine.Finding{f}, 365*24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if es, _ := s.List(now.Add(31 * 24 * time.Hour)); len(es) != 0 {
		t.Errorf("a year-long hide must end after 30 days: %v", es)
	}
}

// Entries written by older versions with no end date expire 30 days after
// they were made.
func TestOldForeverEntryExpires(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	e := Entry{ID: "x", RuleID: "port", Created: now}
	if !e.Active(now.Add(29*24*time.Hour)) || e.Active(now.Add(31*24*time.Hour)) {
		t.Error("old for-good entry should last exactly 30 days")
	}
}
