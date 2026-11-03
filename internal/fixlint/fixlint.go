// Package fixlint flags commands in fix texts that are risky to paste: a
// rule cannot run code, but people copy the commands its fix text shows.
// The checks are heuristics for reviewers, so they warn, they do not block:
// a flagged command may be right, and then the text should say why.
package fixlint

import (
	"regexp"
	"strings"
)

// Warning is one flagged command.
type Warning struct {
	Code    string `json:"code"`    // pipe_to_shell, rm_rf, chmod_777, …
	Command string `json:"command"` // the code span, as written in the rule
}

// Codes lists every warning code, in the order the docs explain them.
var Codes = []string{"pipe_to_shell", "rm_rf", "chmod_777", "disable_security", "sudo_unannounced", "etc_no_backup", "force_push", "history_rewrite_no_warning"}

func re(s string) *regexp.Regexp { return regexp.MustCompile(s) }

var (
	pipeToShell = []*regexp.Regexp{
		re(`(?i)\b(curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|]*\|\s*(sudo\s+(-\S+\s+)*)?(sh|bash|zsh|dash|ksh|fish|python3?|perl|ruby|node|iex|invoke-expression)\b`),
		re(`(?i)\b(sh|bash|zsh|dash|ksh)\s+(-c\s+)?["']?\$\(\s*(curl|wget)\b`),
		re(`(?i)\b(sh|bash|zsh|dash|ksh|source|\.)\s+<\(\s*(curl|wget)\b`),
		re(`(?i)\biex\b.*\b(downloadstring|iwr|irm|invoke-webrequest|invoke-restmethod)\b`),
	}
	rmRF = []*regexp.Regexp{
		re(`\brm\s+(-\S+\s+)*-(\w*[rR]\w*f\w*|\w*f\w*[rR]\w*)\b`),
		re(`\brm\s+(-\S+\s+)*-[rR]\s+(-\S+\s+)*-f\b`),
		re(`\brm\s+(-\S+\s+)*-f\s+(-\S+\s+)*-[rR]\b`),
		re(`\brm\s+.*--recursive\b.*--force\b|\brm\s+.*--force\b.*--recursive\b`),
		re(`(?i)\bremove-item\b.*-recurse\b.*-force\b|\bremove-item\b.*-force\b.*-recurse\b`),
		re(`(?i)\b(rd|rmdir)\s+/s\s+/q\b|\b(rd|rmdir)\s+/q\s+/s\b`),
	}
	chmod777 = re(`(?i)\bchmod\s+(-\S+\s+)*(0?777|0?666|a\+rwx|ugo\+rwx|[ao]\+w|[ao]\+rw|o\+rwx)\b`)
	disable  = []*regexp.Regexp{
		re(`(?i)\bspctl\s+--(master|global)-disable\b`),
		re(`(?i)\bcsrutil\s+disable\b`),
		re(`(?i)\bsetenforce\s+(0|permissive)\b`),
		re(`(?i)\bufw\s+disable\b`),
		re(`(?i)\bsocketfilterfw\s+--setglobalstate\s+off\b`),
		re(`(?i)\bfdesetup\s+disable\b`),
		re(`(?i)\bmanage-bde\s+-off\b`),
		re(`(?i)\bsystemctl\s+(--now\s+)?(stop|disable|mask)\b.*\b(firewalld|ufw|nftables|apparmor|auditd|fail2ban)\b`),
		re(`(?i)\bset-mppreference\b.*-disable\w+(\s+(\$true|1|true))?\s*$`),
		re(`(?i)\bset-mppreference\b.*-disable\w+\s+(\$true|1|true)\b`),
		re(`(?i)\bnetsh\s+advfirewall\s+set\s+\S+\s+state\s+off\b`),
		re(`(?i)\bset-netfirewallprofile\b.*-enabled\s+(\$false|false|0)\b`),
		re(`(?i)\bhttp\.sslverify\s+false\b`),
		re(`(?i)\bstrict-ssl\s+false\b`),
	}
	sudo       = re(`(?i)\b(sudo|doas|pkexec|runas)\b|-verb\s+runas\b`)
	adminWords = re(`(?i)admin|root|sudo|password|quản trị|mật khẩu`)
	etcWrite   = []*regexp.Regexp{
		re(`(>>?|\btee\b(\s+-a)?)\s*/etc/`),
		re(`\bsed\s+(-\S+\s+)*-i(\s|$)[^|]*/etc/`),
		re(`\b(cp|mv|install|ln)\b(\s+\S+)+\s+/etc/\S*$`),
		re(`\b(nano|vi|vim|nvim|emacs|gedit|pico|ed|code)\s+(-\S+\s+)*/etc/`),
	}
	backupWords = re(`(?i)\.bak\b|\.orig\b|\.backup\b|back ?up|sao lưu|bản sao|\bvisudo\b`)
	forcePush   = re(`\bgit\b.*\bpush\b.*(--force\b|--force-with-lease\b|\s-f\b|\s\+\S)`)
	rewrite     = re(`(?i)\bgit\s+(filter-repo|filter-branch)\b|\bbfg\b`)
	rewriteWarn = re(`(?i)rewrit|re-?clone|clone again|everyone|force-push|viết lại|clone lại|mọi người`)
)

// Spans splits a fix text into its `code` spans and the prose around them.
func Spans(text string) (code []string, prose string) {
	parts := strings.Split(text, "`")
	var p strings.Builder
	for i, s := range parts {
		if i%2 == 1 {
			code = append(code, s)
		} else {
			p.WriteString(s)
			p.WriteString(" ")
		}
	}
	return code, p.String()
}

// Lint checks the commands of one fix text (in one language).
func Lint(text string) []Warning {
	code, prose := Spans(text)
	var out []Warning
	add := func(c, cmd string) {
		for _, w := range out {
			if w.Code == c && w.Command == cmd {
				return
			}
		}
		out = append(out, Warning{c, cmd})
	}
	backup := backupWords.MatchString(text)
	for _, c := range code {
		if matchAny(pipeToShell, c) {
			add("pipe_to_shell", c)
		}
		if matchAny(rmRF, c) {
			add("rm_rf", c)
		}
		if chmod777.MatchString(c) {
			add("chmod_777", c)
		}
		if matchAny(disable, c) {
			add("disable_security", c)
		}
		if sudo.MatchString(c) && !adminWords.MatchString(prose) {
			add("sudo_unannounced", c)
		}
		if !backup && matchAny(etcWrite, c) {
			add("etc_no_backup", c)
		}
		if forcePush.MatchString(c) {
			add("force_push", c)
		}
		if rewrite.MatchString(c) && !rewriteWarn.MatchString(prose) {
			add("history_rewrite_no_warning", c)
		}
	}
	return out
}

func matchAny(rs []*regexp.Regexp, s string) bool {
	for _, r := range rs {
		if r.MatchString(s) {
			return true
		}
	}
	return false
}

// Allowed are warnings on built-in rules that a maintainer reviewed and
// kept, keyed "rule-id:code", with the reason.
var Allowed = map[string]string{
	// The text turns ufw on; `sudo ufw disable` is offered only as the undo,
	// for someone who cut off their own access.
	"linux-firewall-off:disable_security": "ufw disable is the undo of the step that turns the firewall on",
}

// Allow reports whether a warning on a rule was reviewed and kept.
func Allow(ruleID, code string) (reason string, ok bool) {
	reason, ok = Allowed[ruleID+":"+code]
	return reason, ok
}
