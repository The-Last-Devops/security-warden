package main

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/report"
)

// minKey is the shortest key prefix accepted to name one finding.
const minKey = 6

// runIgnore hides problems for a while, shows them again, and lists what
// is hidden (the web UI's Hide button and Hidden view).
func runIgnore(l string, rs []*engine.Rule, args []string, days int) int {
	t := func(k string) string { return i18n.T(l, k) }
	st := ignore.Default()
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "add", "hide":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, t("ignore.usage"))
			return 2
		}
		if !hideDaysOK(days) {
			fmt.Fprintln(os.Stderr, t("ignore.days"))
			return 2
		}
		s := scanNow(rs, l, true)
		pick, err := pickFindings(append(append([]engine.Finding(nil), s.Findings...), s.Ignored...), args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, t(err.Error())+"\n", args[1])
			return 2
		}
		now := time.Now()
		if err := st.Add(pick, time.Duration(days)*24*time.Hour, now); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		title := report.Tilde(engine.Clean(pick[0].Title))
		if len(pick) > 1 {
			title = report.Headline(title)
		}
		fmt.Printf(t("ignore.hidden")+"\n", len(pick), title)
		fmt.Printf(t("ignore.back")+"\n", now.Add(time.Duration(days)*24*time.Hour).Format("2006-01-02 15:04"), args[1])
		return 0
	case "restore", "show", "unhide":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, t("ignore.usage"))
			return 2
		}
		es, err := st.List(time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		ids := restoreIDs(es, args[1])
		if len(ids) == 0 {
			fmt.Printf(t("ignore.restore_none")+"\n", args[1])
			return 1
		}
		if err := st.Remove(ids); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Printf(t("ignore.restored")+"\n", len(ids))
		return 0
	case "clear":
		if err := st.Remove(nil); err != nil {
			fmt.Println(err)
			return 2
		}
		fmt.Println(t("ignore.cleared"))
		return 0
	case "list":
	default:
		fmt.Fprintln(os.Stderr, t("ignore.usage"))
		return 2
	}
	es, err := st.List(time.Now())
	if err != nil {
		fmt.Println(err)
		return 2
	}
	if len(es) == 0 {
		fmt.Println(t("ignore.none"))
		return 0
	}
	sort.SliceStable(es, func(i, j int) bool { return end(es[i]).Before(end(es[j])) })
	fmt.Printf("\n  "+t("ignore.header")+"\n\n", len(es))
	for _, e := range es {
		title := report.Tilde(engine.Clean(e.Title))
		head, place := title, ""
		if i := strings.Index(title, ": "); i > 0 {
			head, place = title[:i], title[i+2:]
		}
		fmt.Printf("  [%s] %s\n", i18n.T(l, "severity."+e.Severity), head)
		if place != "" {
			fmt.Printf("      %s\n", place)
		}
		fmt.Printf("      "+t("ignore.until")+" · "+t("report.key")+" · %s\n\n", end(e).Local().Format("2006-01-02 15:04"), shortID(e.ID), e.RuleID)
	}
	fmt.Println("  " + t("ignore.list_hint") + "\n")
	return 0
}

// hideDaysOK: a problem is hidden for 1 to 30 days, never for good.
func hideDaysOK(days int) bool { return days >= 1 && days <= int(ignore.MaxHide/(24*time.Hour)) }

// end is when an entry stops hiding its finding.
func end(e ignore.Entry) time.Time {
	if e.Until.IsZero() { // written by an older version: ends MaxHide after
		return e.Created.Add(ignore.MaxHide)
	}
	return e.Until
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// pickFindings resolves a rule id (every place of that rule) or a finding
// key (one place; any unique prefix of at least minKey characters). The
// error is an i18n key that takes the target.
func pickFindings(fs []engine.Finding, target string) ([]engine.Finding, error) {
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
		if len(target) >= minKey && strings.HasPrefix(id, strings.ToLower(target)) {
			byKey = append(byKey, f)
		}
	}
	switch {
	case len(byRule) > 0:
		return byRule, nil
	case len(byKey) == 1:
		return byKey, nil
	case len(byKey) > 1:
		return nil, errors.New("ignore.ambiguous")
	}
	return nil, errors.New("ignore.no_match")
}

// restoreIDs picks the hidden entries to show again: all, every entry of a
// rule, or the entry whose key starts with target.
func restoreIDs(es []ignore.Entry, target string) []string {
	var byRule, byKey []string
	for _, e := range es {
		switch {
		case target == "all":
			byRule = append(byRule, e.ID)
		case e.RuleID == target:
			byRule = append(byRule, e.ID)
		case len(target) >= minKey && strings.HasPrefix(e.ID, strings.ToLower(target)):
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
