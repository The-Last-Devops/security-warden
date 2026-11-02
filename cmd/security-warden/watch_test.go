package main

import (
	"testing"

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
