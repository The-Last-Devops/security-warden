package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/The-Last-Devops/security-warden/internal/i18n"
	"github.com/The-Last-Devops/security-warden/internal/web"
)

// runPasskey lists or removes the passkeys that sign in to the web UI (the
// web Settings dialog has the same buttons).
func runPasskey(l string, args []string, yes bool) int {
	t := func(k string) string { return i18n.T(l, k) }
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		ps, err := web.LocalPasskeys(web.DefaultPort)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if len(ps) == 0 {
			fmt.Println(t("passkey.none"))
			return 0
		}
		fmt.Printf(t("passkey.count")+"\n", len(ps))
		for i, p := range ps {
			added := t("passkey.unknown")
			if !p.Added.IsZero() {
				added = fmt.Sprintf(t("passkey.added"), p.Added.Local().Format("2006-01-02 15:04"))
			}
			via := ""
			if len(p.Transports) > 0 {
				via = " · " + strings.Join(p.Transports, ", ")
			}
			fmt.Printf("  %d. %s%s\n", i+1, added, via)
		}
		fmt.Println(t("passkey.clear_hint"))
		return 0
	case "clear", "remove":
		ps, err := web.LocalPasskeys(web.DefaultPort)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		if len(ps) == 0 {
			fmt.Println(t("passkey.none"))
			return 0
		}
		if !yes {
			fmt.Printf(t("passkey.confirm"), len(ps))
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" && a != "c" && a != "có" {
				fmt.Println(t("passkey.kept"))
				return 0
			}
		}
		n, err := web.LocalClearPasskeys(web.DefaultPort)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		fmt.Printf(t("passkey.cleared")+"\n", n)
		return 0
	}
	fmt.Fprintln(os.Stderr, t("passkey.usage"))
	return 2
}

// runLogout ends every signed-in web session (each browser signs in again
// with a passkey or the link from security-warden open).
func runLogout(l string) int {
	n, err := web.LocalLogout(web.DefaultPort)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Printf(i18n.T(l, "logout.done")+"\n", n)
	return 0
}
