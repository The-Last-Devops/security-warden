package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/fix"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
)

func tilde(s string) string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return strings.ReplaceAll(s, h, "~")
	}
	return s
}

// runFix offers the built-in remedy of each finding, one by one, and
// applies the ones the user accepts (all of them with --yes).
func runFix(lang string, findings []engine.Finding, yes, dryRun bool) int {
	t := func(k string) string { return i18n.T(lang, k) }
	var fixable, manual []engine.Finding
	for _, f := range findings {
		if f.Remedy != nil {
			fixable = append(fixable, f)
		} else {
			manual = append(manual, f)
		}
	}
	if len(fixable) == 0 {
		fmt.Println("\n  " + t("fix.none") + "\n")
		return 0
	}
	fmt.Printf("\n  "+t("fix.header")+"\n\n", len(fixable), len(findings))

	// Ask for the admin password once, up front, if any fix needs it.
	if !dryRun && os.Geteuid() != 0 {
		for _, f := range fixable {
			if a, _ := fix.Get(f.Remedy.Action); a.NeedsRoot {
				fmt.Println("  " + t("fix.sudo"))
				if err := exec.Command("sudo", "-v").Run(); err != nil {
					fmt.Printf("  "+t("fix.failed")+"\n", err)
					return 2
				}
				fmt.Println()
				break
			}
		}
	}

	in := bufio.NewReader(os.Stdin)
	batch := fix.NewBatch()
	applied, failed := 0, 0
	for i, f := range fixable {
		a, _ := fix.Get(f.Remedy.Action)
		var notes []string
		if a.NeedsRoot {
			notes = append(notes, t("fix.needs_admin"))
		}
		if !a.Undoable {
			notes = append(notes, t("fix.no_undo"))
		}
		fmt.Printf("  %d. %s\n", i+1, tilde(f.Title))
		for _, c := range a.Plan(f.Remedy.Params) {
			fmt.Printf("     $ %s\n", tilde(c))
		}
		if len(notes) > 0 {
			fmt.Printf("     (%s)\n", strings.Join(notes, ", "))
		}
		if dryRun {
			fmt.Println()
			continue
		}
		if !yes {
			fmt.Print("     " + t("fix.ask"))
			line, _ := in.ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" && a != "c" && a != "có" {
				fmt.Printf("     %s\n\n", t("fix.skipped"))
				continue
			}
		}
		if err := fix.Apply(batch, f.RuleID, f.Remedy.Action, f.Remedy.Params); err != nil {
			fmt.Printf("     ✗ "+t("fix.failed")+"\n\n", err)
			failed++
			continue
		}
		fmt.Printf("     ✓ %s\n\n", t("fix.applied"))
		applied++
	}

	if dryRun {
		fmt.Println("  " + t("fix.dry_run"))
	}
	if len(manual) > 0 {
		fmt.Println("\n  " + t("fix.manual"))
		for _, f := range manual {
			fmt.Printf("    • %s\n      → %s\n", tilde(f.Title), tilde(f.Fix))
		}
	}
	if applied > 0 {
		fmt.Println("\n  " + t("fix.undo_hint"))
	}
	fmt.Println()
	if failed > 0 {
		return 1
	}
	return 0
}

func runUndo(lang string) int {
	t := func(k string) string { return i18n.T(lang, k) }
	done, err := fix.UndoLast()
	if len(done) == 0 && err == nil {
		fmt.Println(t("fix.nothing"))
		return 0
	}
	for _, e := range done {
		fmt.Printf("  ↩ %s (%s)\n", e.RuleID, e.Action)
	}
	fmt.Printf(t("fix.undone")+"\n", len(done))
	if err != nil {
		fmt.Printf(t("fix.failed")+"\n", err)
		return 1
	}
	return 0
}
