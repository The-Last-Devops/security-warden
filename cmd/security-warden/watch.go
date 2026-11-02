package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/agent"
	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/ignore"
	"github.com/The-Last-Devops/security-warden/internal/notify"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/internal/web"
)

// findingKey identifies one problem across scans: the rule plus what it
// is about (the rendered title names the port, file or app).
func findingKey(f engine.Finding) string { return f.RuleID + "\x00" + f.Title }

// diff returns findings present now but not before, and keys that went away.
func diff(before map[string]engine.Finding, now []engine.Finding) (added []engine.Finding, gone []engine.Finding) {
	cur := map[string]bool{}
	for _, f := range now {
		k := findingKey(f)
		cur[k] = true
		if _, ok := before[k]; !ok {
			added = append(added, f)
		}
	}
	for k, f := range before {
		if !cur[k] {
			gone = append(gone, f)
		}
	}
	return added, gone
}

var alertLevels = map[string]bool{"critical": true, "high": true, "medium": true}

// runWatch scans on a timer and notifies about new problems. Fast sources
// run every interval; slow ones (file walks, package managers) every full.
func runWatch(lang string, rs []*engine.Rule, interval, full time.Duration) int {
	t := func(k string) string { return i18n.T(lang, k) }
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	items := map[string][]engine.Item{}
	scan := func(all bool) []engine.Finding {
		source.ResetCaches()
		var cs []source.Collector
		for _, c := range source.All() {
			if all || !source.Slow[c.Name] {
				cs = append(cs, c)
			}
		}
		for _, r := range source.Run(ctx, cs, nil) {
			if r.Err == nil {
				items[r.Name] = r.Items
			}
		}
		found := engine.Evaluate(rs, items, platform(), lang)
		entries, _ := ignore.Default().List(time.Now())
		shown, _ := ignore.Split(found, entries, time.Now())
		return shown
	}
	logf := func(format string, a ...any) {
		fmt.Printf("%s  %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, a...))
	}

	known := map[string]engine.Finding{}
	for _, f := range scan(true) {
		known[findingKey(f)] = f
	}
	logf(t("watch.start"), len(known), interval, full)
	lastFull := time.Now()

	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			logf("%s", t("watch.stop"))
			return 0
		case <-tick.C:
		}
		all := time.Since(lastFull) >= full
		if all {
			lastFull = time.Now()
		}
		now := scan(all)
		added, gone := diff(known, now)
		sent := 0
		for _, f := range added {
			logf("+ [%s] %s", i18n.T(lang, "severity."+f.Severity), tilde(f.Title))
			if alertLevels[f.Severity] && sent < 3 {
				notify.Send("security-warden", i18n.T(lang, "severity."+f.Severity), tilde(f.Title))
				sent++
			}
		}
		if extra := countAlerts(added) - sent; extra > 0 {
			notify.Send("security-warden", t("watch.more_title"), fmt.Sprintf(t("watch.more"), extra))
		}
		for _, f := range gone {
			logf("- [%s] %s", i18n.T(lang, "severity."+f.Severity), tilde(f.Title))
		}
		known = map[string]engine.Finding{}
		for _, f := range now {
			known[findingKey(f)] = f
		}
	}
}

func countAlerts(fs []engine.Finding) int {
	n := 0
	for _, f := range fs {
		if alertLevels[f.Severity] {
			n++
		}
	}
	return n
}

func runAgent(lang string, args []string) int {
	t := func(k string) string { return i18n.T(lang, k) }
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	unit, logPath := agent.Paths()
	switch sub {
	case "install":
		p, err := agent.Install(lang)
		if err != nil {
			fmt.Printf(t("fix.failed")+"\n", err)
			return 2
		}
		fmt.Printf(t("agent.installed")+"\n", p, logPath)
	case "uninstall":
		if err := agent.Uninstall(); err != nil {
			fmt.Printf(t("fix.failed")+"\n", err)
			return 2
		}
		fmt.Println(t("agent.removed"))
	default:
		if agent.Installed() {
			fmt.Printf(t("agent.on")+"\n", unit, logPath)
		} else {
			fmt.Println(t("agent.off"))
		}
	}
	return 0
}

// runStart runs Security Warden as a background service (restarted at
// login) and opens its window. If it already runs, it just opens it.
func runStart(lang string) int {
	t := func(k string) string { return i18n.T(lang, k) }
	if !web.RunningHere(web.DefaultPort) {
		if _, err := agent.Install(lang); err != nil {
			fmt.Printf(t("fix.failed")+"\n", err)
			return 2
		}
		for i := 0; i < 50 && !web.RunningHere(web.DefaultPort); i++ {
			time.Sleep(200 * time.Millisecond)
		}
		if !web.RunningHere(web.DefaultPort) {
			_, logPath := agent.Paths()
			fmt.Printf(t("start.slow")+"\n", logPath)
			return 1
		}
	}
	url := web.StoredLoginURL()
	if url == "" {
		url = fmt.Sprintf("http://localhost:%d/", web.DefaultPort)
	}
	fmt.Printf(t("start.ok")+"\n", web.DefaultPort)
	_ = web.OpenApp(url)
	return 0
}

func runStop(lang string) int {
	t := func(k string) string { return i18n.T(lang, k) }
	if err := agent.Uninstall(); err != nil {
		fmt.Printf(t("fix.failed")+"\n", err)
		return 2
	}
	for i := 0; i < 25 && web.RunningHere(web.DefaultPort); i++ {
		time.Sleep(200 * time.Millisecond)
	}
	if web.RunningHere(web.DefaultPort) {
		fmt.Println(t("stop.foreground"))
		return 1
	}
	fmt.Println(t("stop.ok"))
	return 0
}

func runStatus(lang string) int {
	t := func(k string) string { return i18n.T(lang, k) }
	switch {
	case web.RunningHere(web.DefaultPort):
		fmt.Printf(t("status.running")+"\n", web.DefaultPort)
		if agent.Installed() {
			fmt.Println(t("status.atlogin"))
		}
	default:
		fmt.Println(t("status.stopped"))
	}
	return 0
}
