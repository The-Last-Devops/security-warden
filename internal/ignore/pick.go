package ignore

import (
	"errors"
	"strings"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
)

// MinKey is the shortest key prefix accepted to name one finding.
const MinKey = 6

// Errors of Pick. Their texts are i18n keys that take the target.
var (
	ErrNoMatch   = errors.New("ignore.no_match")
	ErrAmbiguous = errors.New("ignore.ambiguous")
)

// DaysOK: a problem is hidden for 1 to 30 days, never for good.
func DaysOK(days int) bool { return days >= 1 && days <= int(MaxHide/(24*time.Hour)) }

// End is when an entry stops hiding its finding.
func End(e Entry) time.Time {
	if e.Until.IsZero() { // written by an older version: ends MaxHide after
		return e.Created.Add(MaxHide)
	}
	return e.Until
}

// Pick resolves a rule id (every place of that rule) or a finding key (one
// place; any unique prefix of at least MinKey characters).
func Pick(fs []engine.Finding, target string) ([]engine.Finding, error) {
	var byRule, byKey []engine.Finding
	seen := map[string]bool{}
	for _, f := range fs {
		id := engine.FindingID(f)
		if seen[id] {
			continue
		}
		seen[id] = true
		if f.RuleID == target {
			byRule = append(byRule, f)
		}
		if len(target) >= MinKey && strings.HasPrefix(id, strings.ToLower(target)) {
			byKey = append(byKey, f)
		}
	}
	switch {
	case len(byRule) > 0:
		return byRule, nil
	case len(byKey) == 1:
		return byKey, nil
	case len(byKey) > 1:
		return nil, ErrAmbiguous
	}
	return nil, ErrNoMatch
}

// RestoreIDs picks the hidden entries to show again: all, every entry of a
// rule, or the entry whose key starts with target.
func RestoreIDs(es []Entry, target string) []string {
	var byRule, byKey []string
	for _, e := range es {
		switch {
		case target == "all":
			byRule = append(byRule, e.ID)
		case e.RuleID == target:
			byRule = append(byRule, e.ID)
		case len(target) >= MinKey && strings.HasPrefix(e.ID, strings.ToLower(target)):
			byKey = append(byKey, e.ID)
		}
	}
	if len(byRule) > 0 {
		return byRule
	}
	if len(byKey) == 1 {
		return byKey
	}
	return nil
}
