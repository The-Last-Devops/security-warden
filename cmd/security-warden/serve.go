package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/The-Last-Devops/security-warden/internal/agent"
	"github.com/The-Last-Devops/security-warden/internal/update"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/notify"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/internal/web"
	ui "github.com/The-Last-Devops/security-warden/web"
)

func runServe(lang string, rs []*engine.Rule, listen string, allowLAN, open, tab, background bool, popup string) int {
	if background {
		open = false
	}
	t := func(k string) string { return i18n.T(lang, k) }
	if os.Geteuid() == 0 {
		fmt.Println(t("serve.root"))
		return 2
	}
	if listen == "" {
		listen = fmt.Sprintf("127.0.0.1:%d", web.DefaultPort)
	}
	addr, kind, err := web.ValidateListen(listen, allowLAN, web.LocalIPs())
	if err != nil {
		fmt.Println(err)
		return 2
	}
	if !web.HasUI(ui.UI()) {
		fmt.Println(t("serve.no_ui"))
		return 2
	}
	ln, err := web.Listen(addr)
	if errors.Is(err, web.ErrInUse) {
		// Opened twice: show the one that is already running.
		if kind == web.KindLoopback && web.RunningHere(web.DefaultPort) && strings.HasSuffix(addr, fmt.Sprintf(":%d", web.DefaultPort)) {
			fmt.Printf("  %s\n  http://localhost:%d/\n", t("serve.already"), web.DefaultPort)
			if open || background {
				_ = web.OpenBrowser(web.SignedInURL(web.DefaultPort))
			}
			return 0
		}
		fmt.Printf(t("serve.in_use")+"\n", addr)
		return 2
	}
	if err != nil {
		fmt.Println(err)
		return 2
	}
	srv := web.New(addr, kind, version, lang, ui.UI(), web.Scanner{
		Rules: rs,
		Collect: func(ctx context.Context, done func(string)) []source.Result {
			return source.Run(ctx, source.All(), done)
		},
		Evaluate: func(results []source.Result, l string) report.Scan {
			return buildScan(rs, results, l)
		},
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := web.SaveToken(srv.Token()); err == nil {
		defer web.ForgetToken()
	}
	if background {
		// Running as a service: no secret in the log; watch and notify.
		fmt.Printf("%s  %s %s\n", time.Now().Format("2006-01-02 15:04:05"), t("serve.background"), addr)
		srv.Watching = true
		go watchInBackground(ctx, srv, lang, popup)
		go autoUpdate(ctx, lang, stop)
		if err := srv.Run(ctx, ln); err != nil {
			fmt.Println(err)
			return 2
		}
		return 0
	}
	fmt.Printf("\n  security-warden %s\n\n  %s\n  %s\n\n", version, t("serve.open"), srv.LoginURL())
	if kind == web.KindLAN {
		fmt.Println("  " + t("serve.lan_warning") + "\n")
	}
	fmt.Println("  " + t("serve.secret") + "\n")
	// Open the browser for the person at this machine; a Tailscale address is
	// for another device, so only print the link then.
	if open && kind == web.KindLoopback {
		openFn := web.OpenBrowser
		if !tab {
			openFn = web.OpenBrowser
		}
		if err := openFn(srv.LoginURL()); err == nil {
			fmt.Println("  " + t("serve.opened") + "\n")
		}
	}
	if err := srv.Run(ctx, ln); err != nil {
		fmt.Println(err)
		return 2
	}
	return 0
}

// watchInBackground rescans every 30 minutes and notifies about problems
// that were not there before (medium and worse; snoozed ones are skipped
// because they are not in the findings).
func watchInBackground(ctx context.Context, srv *web.Server, lang, popup string) {
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	limit, popupOn := rank[popup]
	var lastPopup time.Time
	known := map[string]bool{}
	for _, f := range srv.ScanNow(ctx) {
		known[engine.FindingID(f)] = true
	}
	tick := time.NewTicker(30 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := srv.ScanNow(ctx)
		var added []engine.Finding
		next := map[string]bool{}
		for _, f := range now {
			id := engine.FindingID(f)
			next[id] = true
			if !known[id] && alertLevels[f.Severity] {
				added = append(added, f)
			}
		}
		known = next
		for i, f := range added {
			fmt.Printf("%s  + [%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), f.Severity, engine.Clean(tilde(f.Title)))
			if i < 3 {
				notify.Send("Security Warden", i18n.T(lang, "severity."+f.Severity), tilde(f.Title))
			}
		}
		if len(added) > 3 {
			notify.Send("Security Warden", i18n.T(lang, "watch.more_title"), fmt.Sprintf(i18n.T(lang, "watch.more"), len(added)-3))
		}
		// Serious new problems also bring the window up, at most once an
		// hour so it never turns into nagging.
		serious := false
		for _, f := range added {
			if r, ok := rank[f.Severity]; ok && popupOn && r <= limit {
				serious = true
			}
		}
		if serious && time.Since(lastPopup) >= time.Hour {
			if web.OpenBrowser(web.SignedInURL(web.DefaultPort)) == nil {
				lastPopup = time.Now()
			}
		}
	}
}

// runOpen opens the running Security Warden, signed in; starts it if needed.
func runOpen(lang string, rs []*engine.Rule) int {
	if web.RunningHere(web.DefaultPort) {
		if err := web.OpenBrowser(web.SignedInURL(web.DefaultPort)); err != nil {
			fmt.Println(err)
			return 2
		}
		return 0
	}
	return runServe(lang, rs, "", false, true, false, false, "off")
}

// autoUpdate checks for a new release two minutes after start and then
// daily. Homebrew installs upgrade themselves and restart (the service
// manager starts the new version); others get a notification once.
func autoUpdate(ctx context.Context, lang string, stop context.CancelFunc) {
	if version == "dev" {
		return
	}
	wait := 2 * time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = 24 * time.Hour
		if checkAndUpdate(ctx, lang) {
			// New version installed: exit so launchd/systemd restarts us.
			stop()
			os.Exit(3)
		}
	}
}

// checkAndUpdate returns true when a new version was installed.
func checkAndUpdate(ctx context.Context, lang string) bool {
	t := func(k string) string { return i18n.T(lang, k) }
	st := update.Load()
	latest, err := update.Latest(ctx)
	st.Checked = time.Now()
	if err != nil {
		st.LastError = err.Error()
		_ = update.Save(st)
		return false
	}
	st.Latest, st.LastError = latest, ""
	if !update.Newer(latest, version) {
		_ = update.Save(st)
		return false
	}
	if st.Auto && update.Method() == "brew" {
		// Restart only when a newer binary is really in place.
		if _, err := update.UpgradeBrew(ctx, version); err != nil {
			st.LastError = err.Error()
			_ = update.Save(st)
			return false
		}
		st.Applied = latest
		_ = update.Save(st)
		fmt.Printf("%s  %s %s\n", time.Now().Format("2006-01-02 15:04:05"), t("update.applied"), latest)
		notify.Send("Security Warden", t("update.applied"), latest)
		return true
	}
	if st.Notified != latest {
		notify.Send("Security Warden", t("update.available"), fmt.Sprintf(t("update.how"), latest))
		st.Notified = latest
	}
	_ = update.Save(st)
	return false
}

// runUpdate updates now (CLI).
func runUpdate(lang string) int {
	t := func(k string) string { return i18n.T(lang, k) }
	latest, err := update.Latest(context.Background())
	if err != nil {
		fmt.Printf(t("fix.failed")+"\n", err)
		return 2
	}
	if !update.Newer(latest, version) {
		fmt.Printf(t("update.current")+"\n", version)
		return 0
	}
	if update.Method() != "brew" {
		fmt.Printf(t("update.how")+"\n", latest)
		return 1
	}
	fmt.Printf(t("update.installing")+"\n", latest)
	if got, err := update.UpgradeBrew(context.Background(), version); errors.Is(err, update.ErrNotUpdated) {
		fmt.Printf(t("update.notYet")+"\n", got, latest)
		return 1
	} else if err != nil {
		fmt.Printf(t("fix.failed")+"\n", err)
		return 2
	}
	if web.RunningHere(web.DefaultPort) && agent.Installed() {
		// Restart the background service on the new version.
		_ = agent.Uninstall()
		time.Sleep(time.Second)
		_, _ = agent.Install(lang)
	}
	fmt.Printf(t("update.done")+"\n", latest)
	return 0
}
