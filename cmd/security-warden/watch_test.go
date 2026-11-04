package main

import (
	"testing"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
)

func TestDiff(t *testing.T) {
	a := engine.Finding{RuleID: "port", Title: "node on 3000", Severity: "medium"}
	b := engine.Finding{RuleID: "port", Title: "node on 4000", Severity: "medium"}
	c := engine.Finding{RuleID: "tunnel", Title: "ngrok", Severity: "high"}
	before := map[string]engine.Finding{findingKey(a): a, findingKey(b): b}
	added, gone := diff(before, []engine.Finding{a, c})
	if len(added) != 1 || added[0].Title != "ngrok" {
		t.Errorf("added = %v", added)
	}
	if len(gone) != 1 || gone[0].Title != "node on 4000" {
		t.Errorf("gone = %v", gone)
	}
	if countAlerts([]engine.Finding{a, c, {Severity: "low"}}) != 2 {
		t.Error("countAlerts")
	}
}

func TestNewFindingsIgnoresFlappingAndPids(t *testing.T) {
	t0 := time.Now()
	a := engine.Finding{RuleID: "tunnel", Title: "ngrok", Severity: "high", Item: engine.Item{"pid": 1}}
	low := engine.Finding{RuleID: "x", Title: "y", Severity: "low"}
	seen := map[string]time.Time{}
	if got := newFindings(seen, []engine.Finding{a, low}, t0); len(got) != 1 {
		t.Fatalf("first: %v", got)
	}
	// Gone for one scan (a source timed out), back with a new pid: not new.
	newFindings(seen, nil, t0.Add(30*time.Minute))
	a.Item = engine.Item{"pid": 2}
	if got := newFindings(seen, []engine.Finding{a}, t0.Add(time.Hour)); len(got) != 0 {
		t.Errorf("flapping finding notified again: %v", got)
	}
	// Gone for more than a week: new again.
	if got := newFindings(seen, []engine.Finding{a}, t0.Add(9*24*time.Hour)); len(got) != 1 {
		t.Errorf("after a week: %v", got)
	}
}
