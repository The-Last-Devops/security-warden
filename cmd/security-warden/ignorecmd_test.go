package main

import (
	"testing"

	"github.com/The-Last-Devops/security-warden/internal/report"
)

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
