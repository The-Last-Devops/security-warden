package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/feedback"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/internal/web"
)

// openURL opens a link in the browser; tests replace it.
var openURL = web.OpenBrowser

// runFeedback prints a GitHub issue link for a wrong finding (RULE or KEY)
// or a new idea, and exactly what it fills in. It never sends anything.
// ideaSet: --idea was given (maybe empty); scan returns the current
// findings, in English, the issue tracker's language.
func runFeedback(w io.Writer, l string, rs []*engine.Rule, args []string, idea string, ideaSet, open bool,
	scan func() []engine.Finding) int {
	t := func(k string) string { return i18n.T(l, k) }
	info := feedback.Info{Version: version, Platform: platform(), Via: "cli"}
	sc := feedback.NewScrubber(feedback.DefaultEnv())
	var d feedback.Draft
	switch {
	case ideaSet && len(args) == 0:
		var err error
		if d, err = feedback.Idea(idea, info, sc); err != nil {
			fmt.Fprintln(os.Stderr, t("feedback.empty_idea"))
			return 2
		}
	case len(args) == 1:
		target := args[0]
		var rule *engine.Rule
		for _, r := range rs {
			if r.ID == target {
				rule = r
			}
		}
		pick, err := ignore.Pick(scan(), target)
		switch {
		case err == nil:
			d = feedback.FalsePositive(pick[0], ruleOf(rs, pick[0].RuleID), info, sc)
		case rule != nil:
			fmt.Fprintf(w, t("feedback.not_failing")+"\n\n", rule.ID)
			d = feedback.ForRule(rule, info, sc)
		default:
			fmt.Fprintf(os.Stderr, t(err.Error())+"\n", target)
			return 2
		}
	default:
		fmt.Fprintln(os.Stderr, t("feedback.usage"))
		return 2
	}
	return showDraft(w, l, d, open)
}

// runBugReport prints a GitHub bug report link with the user's words and
// the newest lines of the scan log, scrubbed. It never sends anything.
func runBugReport(w io.Writer, l, text string, open bool) int {
	if strings.TrimSpace(text) == "" {
		fmt.Fprintln(os.Stderr, i18n.T(l, "feedback.empty_bug"))
		return 2
	}
	log, _ := source.ReadLog()
	d := feedback.Bug(text, log, feedback.Info{Version: version, Platform: platform(), Via: "cli"}, feedback.NewScrubber(feedback.DefaultEnv()))
	return showDraft(w, l, d, open)
}

// showDraft prints what an issue link fills in, then the link (and opens it
// with open).
func showDraft(w io.Writer, l string, d feedback.Draft, open bool) int {
	t := func(k string) string { return i18n.T(l, k) }
	fmt.Fprintln(w, t("feedback.preview"))
	fmt.Fprintln(w)
	for _, line := range strings.Split(d.Preview, "\n") {
		fmt.Fprintln(w, "  "+line)
	}
	fmt.Fprintln(w)
	if d.Shortened {
		fmt.Fprintln(w, t("feedback.shortened"))
	}
	fmt.Fprintln(w, t("feedback.link"))
	fmt.Fprintln(w, d.URL)
	fmt.Fprintln(w)
	if !open {
		fmt.Fprintln(w, t("feedback.nothing_sent")+" "+t("feedback.open_hint"))
		return 0
	}
	if err := openURL(d.URL); err != nil {
		fmt.Fprintf(w, t("feedback.open_failed")+"\n", err)
		return 0
	}
	fmt.Fprintln(w, t("feedback.opened"))
	return 0
}

func ruleOf(rs []*engine.Rule, id string) *engine.Rule {
	for _, r := range rs {
		if r.ID == id {
			return r
		}
	}
	return nil
}
