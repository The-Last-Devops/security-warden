package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/internal/vulndb"
)

// runVulnDB manages the local copy of the OSV vulnerability data:
// "vulndb" shows it, "vulndb update" refreshes it now, "on"/"off" turn the
// daily refresh of the background service on or off.
func runVulnDB(lang string, args []string) int {
	t := func(k string) string { return i18n.T(lang, k) }
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "on", "off":
		s := vulndb.LoadSettings()
		s.Off = sub == "off"
		if err := vulndb.SaveSettings(s); err != nil {
			fmt.Println(err)
			return 2
		}
		fmt.Println(t("vulndb.auto_" + sub))
		return 0
	case "update":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		fmt.Println(t("vulndb.updating"))
		failed := false
		for _, r := range vulndb.UpdateAll(ctx) {
			if r.Err != nil {
				failed = true
				fmt.Printf("  %-10s %v\n", r.Ecosystem, r.Err)
				continue
			}
			how := t("vulndb.incremental")
			if r.Full {
				how = t("vulndb.full")
			}
			fmt.Printf("  %-10s %6d  %8s  %s, %d\n", r.Ecosystem, r.Vulns, size(r.Bytes), how, r.Changed)
		}
		if failed {
			return 2
		}
		return 0
	case "status":
		s := vulndb.LoadSettings()
		state := t("vulndb.auto_on")
		if s.Off {
			state = t("vulndb.auto_off")
		}
		fmt.Println(state)
		sts := vulndb.Statuses()
		if len(sts) == 0 {
			fmt.Println(t("vulndb.none"))
			return 0
		}
		var total int64
		for _, st := range sts {
			total += st.Bytes
			fmt.Printf("  %-10s %6d  %6d  %8s  %s\n", st.Ecosystem, st.Vulns, st.Packages, size(st.Bytes), st.Updated.Local().Format("2006-01-02 15:04"))
		}
		fmt.Printf("  %-10s %22s\n  %s\n", "", size(total), vulndb.Dir())
		if s.LastError != "" {
			fmt.Println("  " + s.LastError)
		}
		return 0
	}
	fmt.Println(t("vulndb.usage"))
	return 2
}

func size(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// vulnDBLoop refreshes the vulnerability data once a day while the
// background service runs, unless turned off. The first refresh waits a
// few minutes so login stays quiet; a scan never downloads anything.
func vulnDBLoop(ctx context.Context) {
	wait := 5 * time.Minute
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = time.Hour
		s := vulndb.LoadSettings()
		due := 23 * time.Hour
		if s.LastError != "" {
			due = 3 * time.Hour
		}
		// No lock file in the code folders: nothing to match, so nothing to
		// download. Every machine that downloads fetches the same files.
		if s.Off || time.Since(s.Checked) < due || !source.HasLockFiles() {
			continue
		}
		for _, r := range vulndb.UpdateAll(ctx) {
			if r.Err != nil {
				fmt.Printf("%s  vulndb %s: %v\n", time.Now().Format("2006-01-02 15:04:05"), r.Ecosystem, r.Err)
			}
		}
	}
}
