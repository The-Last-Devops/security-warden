package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/The-Last-Devops/security-warden/internal/engine"
	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/report"
	"github.com/The-Last-Devops/security-warden/internal/source"
	"github.com/The-Last-Devops/security-warden/internal/web"
	ui "github.com/The-Last-Devops/security-warden/web"
)

func runServe(lang string, rs []*engine.Rule, listen string, allowLAN, open bool) int {
	t := func(k string) string { return i18n.T(lang, k) }
	if os.Geteuid() == 0 {
		fmt.Println(t("serve.root"))
		return 2
	}
	fallback := listen == ""
	if fallback {
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
	ln, addr, err := web.Listen(addr, fallback)
	if err != nil {
		fmt.Println(err)
		return 2
	}
	srv := web.New(addr, kind, version, lang, ui.UI(), web.Scanner{
		Collect: func(ctx context.Context, done func(string)) []source.Result {
			return source.Run(ctx, source.All(), done)
		},
		Evaluate: func(results []source.Result, l string) report.Scan {
			return buildScan(rs, results, l)
		},
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("\n  security-warden %s\n\n  %s\n  %s\n\n", version, t("serve.open"), srv.LoginURL())
	if kind == web.KindLAN {
		fmt.Println("  " + t("serve.lan_warning") + "\n")
	}
	fmt.Println("  " + t("serve.secret") + "\n")
	// Open the browser for the person at this machine; a Tailscale address is
	// for another device, so only print the link then.
	if open && kind == web.KindLoopback {
		if err := web.OpenBrowser(srv.LoginURL()); err == nil {
			fmt.Println("  " + t("serve.opened") + "\n")
		}
	}
	if err := srv.Run(ctx, ln); err != nil {
		fmt.Println(err)
		return 2
	}
	return 0
}
