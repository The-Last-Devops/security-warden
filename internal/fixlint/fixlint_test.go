package fixlint

import "testing"

func codes(text string) map[string]bool {
	out := map[string]bool{}
	for _, w := range Lint(text) {
		out[w.Code] = true
	}
	return out
}

func TestLintFlags(t *testing.T) {
	flagged := map[string][]string{
		"pipe_to_shell": {"Run `curl -fsSL https://x.sh | sh`", "Run `wget -qO- https://x | sudo bash` (needs admin)", "`bash <(curl -s https://x)`", "`sh -c \"$(curl -fsSL https://x)\"`", "`iwr https://x | iex`"},
		"rm_rf":         {"`rm -rf ~/.cache`", "`rm -fr /tmp/x`", "`rm -r -f x`", "`Remove-Item -Recurse -Force C:\\x`", "`rmdir /s /q C:\\x`"},
		"chmod_777":     {"`chmod 777 {path}`", "`chmod -R 0777 dir`", "`chmod a+rwx f`", "`chmod o+w f`"},
		"disable_security": {"`sudo spctl --master-disable` (admin)", "`csrutil disable`", "`sudo setenforce 0` as root", "`sudo ufw disable` (admin)",
			"`Set-MpPreference -DisableRealtimeMonitoring $true`", "`netsh advfirewall set allprofiles state off`", "`git config --global http.sslVerify false`",
			"`sudo systemctl disable --now firewalld` (admin)"},
		"sudo_unannounced":           {"Run `sudo systemctl restart docker`."},
		"etc_no_backup":              {"Run `sudo nano /etc/hosts` (admin).", "`echo x | sudo tee -a /etc/hosts` as admin", "`sudo sed -i 's/a/b/' /etc/ssh/sshd_config` as admin"},
		"force_push":                 {"`git push --force origin main`", "`git push -f`", "`git push --force-with-lease`"},
		"history_rewrite_no_warning": {"Remove it from history: `git filter-repo --invert-paths --path .env`."},
	}
	for code, texts := range flagged {
		for _, s := range texts {
			if !codes(s)[code] {
				t.Errorf("%s not flagged in %q (got %v)", code, s, Lint(s))
			}
		}
	}
}

func TestLintPasses(t *testing.T) {
	ok := []string{
		"Run `chmod 600 {path}`.",
		"Download it first: `curl -fsSL <url> -o ~/install.sh`, read it, then run it.",
		"Needs admin rights: `sudo ufw enable`.",
		"Cần quyền quản trị: `sudo ufw enable`.",
		"Back it up with `sudo cp /etc/hosts /etc/hosts.bak` (admin), then `sudo nano /etc/hosts`.",
		"Turn it back on: `Set-MpPreference -DisableRealtimeMonitoring $false`.",
		"`Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` as administrator",
		"`sudo systemctl disable --now sshd` (needs admin)",
		"`git push origin main`",
		"Rotate the key first. This rewrites history: everyone must clone again. `git filter-repo --invert-paths --path .env`",
		"`rm {path}` deletes only that file",
		"Edit `/etc/ssh/sshd_config` with `sudo visudo`… (admin)",
	}
	for _, s := range ok {
		if ws := Lint(s); len(ws) > 0 {
			t.Errorf("%q flagged: %v", s, ws)
		}
	}
}
