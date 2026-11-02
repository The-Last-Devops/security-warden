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

func runServe(lang string, rs []*engine.Rule, listen string, allowLAN bool) int {
	t := func(k string) string { return i18n.T(lang, k) }
	if os.Geteuid() == 0 {
		fmt.Println(t("serve.root"))
		return 2
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
	srv := web.New(addr, kind, version, lang, ui.UI(), web.Scanner{
		Collect: func(ctx context.Context) []source.Result { return source.Run(ctx, source.All(), nil) },
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
	if err := srv.Run(ctx); err != nil {
		fmt.Println(err)
		return 2
	}
	return 0
}
