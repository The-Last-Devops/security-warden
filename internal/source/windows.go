package source

// Windows checks. The collectors run PowerShell's Get-* cmdlets and read the
// registry as the signed-in user: no administrator rights, no UAC prompt,
// nothing is changed. Everything that parses their output lives here, in
// pure functions, so the tests run on any OS with captured samples.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// psPrelude keeps PowerShell quiet and makes it print UTF-8, so paths with
// non-ASCII letters survive.
const psPrelude = `$ErrorActionPreference='SilentlyContinue';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;`

// The scripts below use single quotes only: a double quote would have to
// survive Windows command-line quoting on its way to powershell.exe. Only
// Get-* cmdlets, CIM reads and registry reads are allowed (see
// TestWindowsScriptsReadOnly).

// winPostureScript reads the firewall, BitLocker and registry settings.
const winPostureScript = `$o=[ordered]@{};
function GetReg($p,$n){ try { (Get-ItemProperty -LiteralPath $p -Name $n -ErrorAction Stop).$n } catch { $null } };
$fw=Get-NetFirewallProfile -PolicyStore ActiveStore; if(-not $fw){ $fw=Get-NetFirewallProfile };
if($fw){ $o.fw=@($fw | ForEach-Object { [ordered]@{n=[string]$_.Name; e=[string]$_.Enabled} }) };
$d=$env:SystemDrive;
try { $v=Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter ('DriveLetter='''+$d+'''') -ErrorAction Stop; if($v){ $o.bl_cim=[int]$v.ProtectionStatus } } catch {};
try { $s=(New-Object -ComObject Shell.Application).NameSpace($d+'\').Self.ExtendedProperty('System.Volume.BitLockerProtection'); if($s -ne $null){ $o.bl_shell=[int]$s } } catch {};
$ts='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server';
$tp='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services';
$o.rdp_deny=GetReg $ts 'fDenyTSConnections'; $o.rdp_deny_pol=GetReg $tp 'fDenyTSConnections';
$o.rdp_nla=GetReg ($ts+'\WinStations\RDP-Tcp') 'UserAuthentication'; $o.rdp_nla_pol=GetReg $tp 'UserAuthentication';
$sys='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';
$o.lua=GetReg $sys 'EnableLUA'; $o.cpba=GetReg $sys 'ConsentPromptBehaviorAdmin';
$o.noau=GetReg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate';
$o.smb1_cli=GetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start';
$o.smb1_srv=GetReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1';
try { $o.smb1_cfg=[string](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {};
$g=$null; try { $g=Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1 } catch {};
if($g){ $o.guest=[bool]$g.Enabled; $o.guest_name=[string]$g.Name } else {
 $c=Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Where-Object { $_.SID -like '*-501' } | Select-Object -First 1;
 if($c){ $o.guest=-not [bool]$c.Disabled; $o.guest_name=[string]$c.Name } };
$o.ndta_m=GetReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun';
$o.ndta_u=GetReg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun';
$o.noap=GetReg 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' 'DisableAutoplay';
ConvertTo-Json -Compress -Depth 5 -InputObject $o`

// winDefenderScript reads Microsoft Defender's state and exclusions. Since
// 2021 Defender hides exclusions from non-administrators ("N/A: Must be an
// administrator to view exclusions"); those are dropped, not reported.
const winDefenderScript = `$o=[ordered]@{};
$s=Get-MpComputerStatus;
if($s){ $o.status=[ordered]@{mode=[string]$s.AMRunningMode; svc=[bool]$s.AMServiceEnabled; av=[bool]$s.AntivirusEnabled; rtp=[bool]$s.RealTimeProtectionEnabled; age=[int]$s.AntivirusSignatureAge; tamper=[string]$s.IsTamperProtected} };
$p=Get-MpPreference;
if($p){ $o.paths=@($p.ExclusionPath | Where-Object { $_ }); $o.ext=@($p.ExclusionExtension | Where-Object { $_ }); $o.proc=@($p.ExclusionProcess | Where-Object { $_ }) };
$o.products=@(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct | ForEach-Object { [string]$_.displayName });
ConvertTo-Json -Compress -Depth 5 -InputObject $o`

// winAutostartScript lists Run and RunOnce values, the Startup folders
// (shortcut targets are read, never saved) and scheduled tasks outside
// \Microsoft\. Disabled tasks are left out.
const winAutostartScript = `$r=New-Object System.Collections.ArrayList;
$skip=@('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider');
foreach($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')){
 $p=Get-ItemProperty -LiteralPath $k;
 if($p){ foreach($v in $p.PSObject.Properties){ if($skip -notcontains $v.Name){ [void]$r.Add([ordered]@{w='run_key'; l=$k; n=[string]$v.Name; c=[string]$v.Value}) } } } };
$ws=New-Object -ComObject WScript.Shell;
foreach($d in @([Environment]::GetFolderPath('Startup'),[Environment]::GetFolderPath('CommonStartup'))){
 if($d){ Get-ChildItem -LiteralPath $d -File -Force | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
  $c=$_.FullName; if($_.Extension -eq '.lnk' -and $ws){ $l=$ws.CreateShortcut($_.FullName); $c=([string]$l.TargetPath+' '+[string]$l.Arguments).Trim() };
  [void]$r.Add([ordered]@{w='startup_folder'; l=$d; n=$_.Name; c=$c}) } } };
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and [string]$_.State -ne 'Disabled' } | ForEach-Object {
 $t=$_; foreach($a in @($t.Actions)){ if($a.Execute){ [void]$r.Add([ordered]@{w='scheduled_task'; l=[string]$t.TaskPath; n=[string]$t.TaskName; c=([string]$a.Execute+' '+[string]$a.Arguments).Trim()}) } } };
ConvertTo-Json -Compress -Depth 4 -InputObject @($r)`

// winProcessScript maps process ids to executables. Other accounts'
// processes (services, SYSTEM) have no path for a standard user: their
// name is kept instead.
const winProcessScript = `ConvertTo-Json -Compress -InputObject @(Get-CimInstance Win32_Process | ForEach-Object { [ordered]@{p=[int]$_.ProcessId; n=[string]$_.Name; x=[string]$_.ExecutablePath} })`

// ---- posture ----

// envLookup reads environment variables (case-insensitive on Windows).
var envLookup = os.Getenv

// systemExe is the full path of a Windows tool in System32, so a program
// of the same name earlier in PATH is never run instead.
func systemExe(rel string) string {
	if root := envLookup("SystemRoot"); root != "" {
		p := filepath.Join(root, "System32", rel)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Base(rel)
}

// regInt is a registry number that may be missing (null), or stored as a
// string by a sloppy installer.
type regInt struct {
	v  int
	ok bool
}

func (r *regInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" || s == "" {
		return nil
	}
	n, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return nil // not a number: treat as missing
	}
	r.v, r.ok = int(n), true
	return nil
}

func (r regInt) is(v int) bool { return r.ok && r.v == v }

type winPostureRaw struct {
	FW []struct {
		N string `json:"n"`
		E string `json:"e"`
	} `json:"fw"`
	BLCim      regInt  `json:"bl_cim"`
	BLShell    regInt  `json:"bl_shell"`
	RDPDeny    regInt  `json:"rdp_deny"`
	RDPDenyPol regInt  `json:"rdp_deny_pol"`
	RDPNLA     regInt  `json:"rdp_nla"`
	RDPNLAPol  regInt  `json:"rdp_nla_pol"`
	LUA        regInt  `json:"lua"`
	CPBA       regInt  `json:"cpba"`
	NoAU       regInt  `json:"noau"`
	SMB1Cli    regInt  `json:"smb1_cli"`
	SMB1Srv    regInt  `json:"smb1_srv"`
	SMB1Cfg    *string `json:"smb1_cfg"`
	Guest      *bool   `json:"guest"`
	GuestName  string  `json:"guest_name"`
	NDTAM      regInt  `json:"ndta_m"`
	NDTAU      regInt  `json:"ndta_u"`
	NoAP       regInt  `json:"noap"`
}

// parseWinPosture turns the posture script's JSON into one item. A field
// is left out when Windows would not tell a standard user.
func parseWinPosture(out string) (Item, error) {
	var r winPostureRaw
	if err := json.Unmarshal([]byte(strings.TrimSpace(trimBOM(out))), &r); err != nil {
		return nil, err
	}
	it := Item{"os": "windows"}

	var profiles []string
	for _, p := range r.FW {
		if p.N != "" {
			profiles = append(profiles, p.N)
		}
	}
	if len(profiles) > 0 {
		var off []string
		for _, p := range r.FW {
			// GpoBoolean: True, False or NotConfigured (which means on).
			if strings.EqualFold(p.E, "False") || p.E == "0" {
				off = append(off, p.N)
			}
		}
		it["firewall_off_profiles"] = strings.Join(off, ", ")
	}

	// Win32_EncryptableVolume needs an administrator, so most scans fall
	// back to the Explorer property: 1, 3 and 6 mean protected, 2 off.
	// Any other value (suspended, not encryptable, unknown) is not judged.
	switch {
	case r.BLCim.is(1):
		it["bitlocker"] = "on"
	case r.BLCim.is(0):
		it["bitlocker"] = "off"
	case r.BLShell.is(1) || r.BLShell.is(3) || r.BLShell.is(6):
		it["bitlocker"] = "on"
	case r.BLShell.is(2):
		it["bitlocker"] = "off"
	}

	// Remote Desktop: a policy value wins over the local setting.
	if deny := firstInt(r.RDPDenyPol, r.RDPDeny); deny.ok {
		it["rdp_enabled"] = deny.v == 0
		nla := firstInt(r.RDPNLAPol, r.RDPNLA)
		it["rdp_nla"] = !nla.ok || nla.v != 0 // NLA is on by default
	}

	it["uac_enabled"] = !r.LUA.is(0) // on when the value is absent
	it["uac_never_notify"] = r.CPBA.is(0)
	it["updates_disabled_by_policy"] = r.NoAU.is(1)

	// SMBv1: the server setting (when Windows lets us read it), the SMBv1
	// client driver (start type 4 = disabled), or the server switch.
	smb1 := r.SMB1Cfg != nil && strings.EqualFold(*r.SMB1Cfg, "True")
	if r.SMB1Cli.ok && r.SMB1Cli.v != 4 {
		smb1 = true
	}
	if r.SMB1Cfg == nil && r.SMB1Srv.ok && r.SMB1Srv.v != 0 {
		smb1 = true
	}
	it["smb1"] = smb1

	if r.Guest != nil {
		it["guest_enabled"] = *r.Guest
		name := r.GuestName
		if name == "" {
			name = "Guest"
		}
		it["guest_name"] = name
	}

	// AutoPlay is off for every drive type (0xFF), or turned off in
	// Settings for this user.
	it["autoplay_off"] = r.NDTAM.is(0xFF) || r.NDTAU.is(0xFF) || r.NoAP.is(1)
	return it, nil
}

func firstInt(vs ...regInt) regInt {
	for _, v := range vs {
		if v.ok {
			return v
		}
	}
	return regInt{}
}

func trimBOM(s string) string { return strings.TrimPrefix(s, "\ufeff") }

// ---- Microsoft Defender ----

type winDefenderRaw struct {
	Status *struct {
		Mode   string `json:"mode"`
		Svc    bool   `json:"svc"`
		AV     bool   `json:"av"`
		RTP    bool   `json:"rtp"`
		Age    int    `json:"age"`
		Tamper string `json:"tamper"`
	} `json:"status"`
	Paths    []string `json:"paths"`
	Ext      []string `json:"ext"`
	Proc     []string `json:"proc"`
	Products []string `json:"products"`
}

// defender reads Microsoft Defender's status and exclusions.
func defender(ctx context.Context) ([]Item, error) {
	if runtime.GOOS != "windows" {
		return nil, Skip{"skip.platform"}
	}
	out, err := runPS(ctx, winDefenderScript)
	if err != nil && out == "" {
		return nil, err
	}
	items, err := parseDefender(out, envLookup)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, Skip{"skip.defender"}
	}
	return items, nil
}

// parseDefender returns one status item and one item per exclusion.
func parseDefender(out string, env func(string) string) ([]Item, error) {
	var r winDefenderRaw
	if err := json.Unmarshal([]byte(strings.TrimSpace(trimBOM(out))), &r); err != nil {
		return nil, err
	}
	if r.Status == nil {
		return nil, nil
	}
	s := r.Status
	// With another antivirus registered, Defender steps back to passive
	// mode on purpose: its real-time protection is then off by design.
	active := s.Mode == "Normal" || (s.Mode == "" && s.AV && s.Svc)
	var others []string
	for _, p := range r.Products {
		if p != "" && !strings.Contains(strings.ToLower(p), "defender") {
			others = append(others, p)
		}
	}
	items := []Item{{
		"kind":               "status",
		"active":             active,
		"mode":               s.Mode,
		"realtime":           s.RTP,
		"signature_age_days": s.Age,
		"tamper_known":       s.Tamper != "",
		"tamper_protected":   strings.EqualFold(s.Tamper, "True"),
		"other_antivirus":    strings.Join(others, ", "),
	}}
	add := func(typ string, vals []string) {
		for _, v := range vals {
			v = strings.TrimSpace(v)
			if v == "" || strings.HasPrefix(v, "N/A") {
				continue // hidden from non-administrators
			}
			reason := riskyExclusion(typ, v, env)
			items = append(items, Item{"kind": "exclusion", "type": typ, "value": v, "risky": reason != "", "reason": reason})
		}
	}
	add("path", r.Paths)
	add("extension", r.Ext)
	add("process", r.Proc)
	return items, nil
}

var (
	driveRoot     = regexp.MustCompile(`^[a-z]:\\?$`)
	riskyExts     = map[string]bool{"exe": true, "dll": true, "ps1": true, "bat": true, "cmd": true, "vbs": true, "js": true, "jse": true, "hta": true, "scr": true, "msi": true, "lnk": true, "wsf": true, "com": true, "pif": true}
	scriptEngines = map[string]bool{"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true, "wscript.exe": true, "cscript.exe": true, "mshta.exe": true, "rundll32.exe": true, "regsvr32.exe": true, "python.exe": true, "node.exe": true}
)

// riskyExclusion says why an exclusion leaves a big hole: a whole drive,
// the user profile, a temp or downloads folder, a wildcard, an executable
// file type, or a script engine. "" means it looks targeted.
func riskyExclusion(typ, v string, env func(string) string) string {
	l := strings.ToLower(strings.TrimRight(expandWinEnv(v, env), `\`))
	switch typ {
	case "extension":
		if riskyExts[strings.TrimPrefix(l, ".")] {
			return "executable_type"
		}
		return ""
	case "process":
		if scriptEngines[winBase(l)] {
			return "script_engine"
		}
		if l == "*" || strings.HasPrefix(l, "*.") {
			return "wildcard"
		}
		return ""
	}
	switch {
	case l == "" || l == "*" || driveRoot.MatchString(l) || strings.HasPrefix(l, `*\`):
		return "drive"
	case l == `c:\users` || l == strings.ToLower(strings.TrimRight(env("USERPROFILE"), `\`)) || userProfileRoot.MatchString(l):
		return "profile"
	case l == `c:\windows` || l == `c:\program files` || l == `c:\program files (x86)` || l == `c:\programdata`:
		return "system_folder"
	}
	f := winPathFlags(l+`\`, env)
	switch {
	case f.temp:
		return "temp"
	case f.downloads:
		return "downloads"
	case userAppData.MatchString(l):
		return "profile"
	}
	return ""
}

var (
	userProfileRoot = regexp.MustCompile(`^[a-z]:\\users\\[^\\]+$`)
	userAppData     = regexp.MustCompile(`^[a-z]:\\users\\[^\\]+\\appdata(\\(roaming|local|locallow))?$`)
)

// ---- paths and command lines ----

type winFlags struct{ temp, downloads, appdataRoot bool }

var (
	winDownloads   = regexp.MustCompile(`^[a-z]:\\users\\[^\\]+\\downloads\\`)
	winAppDataRoot = regexp.MustCompile(`^[a-z]:\\users\\[^\\]+\\appdata\\(roaming|local|locallow)\\[^\\]+$|^[a-z]:\\programdata\\[^\\]+$`)
)

// winPathFlags classifies a Windows path (any case): inside a temp folder
// or the public profile, inside Downloads, or a file lying loose at the
// top of AppData or ProgramData, where installers never put programs.
func winPathFlags(p string, env func(string) string) winFlags {
	l := strings.ToLower(strings.ReplaceAll(p, "/", `\`))
	var f winFlags
	for _, t := range []string{`\appdata\local\temp\`, `:\windows\temp\`, `:\users\public\`, `:\temp\`, `:\tmp\`, `\$recycle.bin\`} {
		if strings.Contains(l, t) {
			f.temp = true
		}
	}
	if t := strings.ToLower(strings.TrimRight(env("TEMP"), `\`)); t != "" && strings.HasPrefix(l, t+`\`) {
		f.temp = true
	}
	f.downloads = winDownloads.MatchString(l)
	f.appdataRoot = winAppDataRoot.MatchString(l)
	return f
}

var winEnvVar = regexp.MustCompile(`%([A-Za-z0-9_()]+)%`)

// expandWinEnv replaces %VAR% with its value; unknown variables stay.
func expandWinEnv(s string, env func(string) string) string {
	return winEnvVar.ReplaceAllStringFunc(s, func(m string) string {
		if v := env(m[1 : len(m)-1]); v != "" {
			return v
		}
		return m
	})
}

func winBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

var exeEnd = regexp.MustCompile(`(?i)\.(exe|com|bat|cmd|vbs|js|ps1|scr|hta|lnk)(\s|$)`)

// winProgram extracts the program from a command line: the quoted part,
// else everything up to the first ".exe" (unquoted paths with spaces),
// else the first word.
func winProgram(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			return cmd[1 : end+1]
		}
		return strings.Trim(cmd, `"`)
	}
	if loc := exeEnd.FindStringIndex(cmd); loc != nil {
		return strings.TrimSpace(cmd[:loc[1]])
	}
	if f := strings.Fields(cmd); len(f) > 0 {
		return f[0]
	}
	return ""
}

var (
	psLoader     = regexp.MustCompile(`(?i)(\s-(e|ec|enc|enco|encodedcommand)\s|frombase64string|downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|invoke-expression|\biex\b|start-bitstransfer)`)
	mshtaLoader  = regexp.MustCompile(`(?i)(https?://|javascript:|vbscript:)`)
	regsvrLoader = regexp.MustCompile(`(?i)(/i:\s*https?://|scrobj)`)
	rundllLoader = regexp.MustCompile(`(?i)(javascript:|https?://|url\.dll)`)
	certLoader   = regexp.MustCompile(`(?i)(-urlcache|-decode|-decodehex)`)
	fetchAny     = regexp.MustCompile(`(?i)\b(curl|wget|bitsadmin)\b.*https?://`)
)

// scriptLoader tells whether a command downloads or decodes code and runs
// it through a built-in Windows tool (PowerShell -enc, mshta, regsvr32
// /i:http, certutil -urlcache…), the usual shape of fileless malware.
func scriptLoader(cmd, prog string) bool {
	b := strings.TrimSuffix(strings.ToLower(winBase(prog)), ".exe")
	args := cmd
	switch b {
	case "powershell", "pwsh":
		return psLoader.MatchString(args + " ")
	case "mshta":
		return mshtaLoader.MatchString(args)
	case "regsvr32":
		return regsvrLoader.MatchString(args)
	case "rundll32":
		return rundllLoader.MatchString(args)
	case "certutil":
		return certLoader.MatchString(args)
	}
	return fetchAny.MatchString(args)
}

type winAutostartRaw struct {
	W string `json:"w"`
	L string `json:"l"`
	N string `json:"n"`
	C string `json:"c"`
}

// windowsAutostarts lists Run keys, Startup folder entries and scheduled
// tasks. Command lines are not kept (they can hold tokens): only the
// program and what it looks like.
func windowsAutostarts(ctx context.Context) []Item {
	out, err := runPS(ctx, winAutostartScript)
	if err != nil && out == "" {
		return nil
	}
	return parseAutostarts(out, envLookup)
}

func parseAutostarts(out string, env func(string) string) []Item {
	var raw []winAutostartRaw
	if err := json.Unmarshal([]byte(strings.TrimSpace(trimBOM(out))), &raw); err != nil {
		var one winAutostartRaw // PowerShell may print a lone object
		if json.Unmarshal([]byte(strings.TrimSpace(trimBOM(out))), &one) != nil || one.W == "" {
			return nil
		}
		raw = []winAutostartRaw{one}
	}
	var items []Item
	for _, a := range raw {
		cmd := expandWinEnv(a.C, env)
		prog := winProgram(cmd)
		f := winPathFlags(prog, env)
		location := a.L
		if a.W == "scheduled_task" {
			location = "Task Scheduler Library" + strings.TrimRight(a.L, `\`)
		}
		items = append(items, Item{
			"kind":          "autostart",
			"where":         a.W,
			"name":          a.N,
			"location":      location,
			"program":       prog,
			"in_temp":       f.temp,
			"in_downloads":  f.downloads,
			"appdata_root":  f.appdataRoot,
			"script_loader": scriptLoader(cmd, prog),
		})
	}
	return items
}

// ---- processes and listeners ----

type winProc struct {
	P int    `json:"p"`
	N string `json:"n"`
	X string `json:"x"`
}

// parseWinProcesses maps pid to executable path, or to the bare name when
// the path is hidden (other accounts' processes).
func parseWinProcesses(out string) map[int]string {
	m := map[int]string{}
	var ps []winProc
	if json.Unmarshal([]byte(strings.TrimSpace(trimBOM(out))), &ps) != nil {
		return m
	}
	for _, p := range ps {
		if p.P <= 0 {
			continue
		}
		if p.X != "" {
			m[p.P] = p.X
		} else {
			m[p.P] = p.N
		}
	}
	return m
}

// winListener is one listening TCP socket from netstat.
type winListener struct {
	host string
	port int
	pid  int
}

// parseNetstat reads `netstat -ano`. Headers and the state column are
// translated on non-English Windows, so a listener is recognised by its
// foreign address instead: 0.0.0.0:0 or [::]:0.
func parseNetstat(out string) []winListener {
	var ls []winListener
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.EqualFold(f[0], "TCP") || (f[2] != "0.0.0.0:0" && f[2] != "[::]:0") {
			continue
		}
		host, port, ok := splitHostPort(f[1])
		pid, err := strconv.Atoi(f[len(f)-1])
		if !ok || err != nil {
			continue
		}
		if i := strings.Index(host, "%"); i >= 0 {
			host = host[:i] // IPv6 zone
		}
		key := host + "|" + strconv.Itoa(port) + "|" + strconv.Itoa(pid)
		if seen[key] {
			continue
		}
		seen[key] = true
		ls = append(ls, winListener{host, port, pid})
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].port < ls[j].port })
	return ls
}

// winSystemProcess: a listener whose program path is hidden from us runs
// under another account (a Windows service or SYSTEM), and anything under
// the Windows folder ships with Windows.
func winSystemProcess(path, systemRoot string) bool {
	l := strings.ToLower(path)
	if !strings.Contains(l, `\`) {
		return true
	}
	root := strings.ToLower(strings.TrimRight(systemRoot, `\`))
	if root == "" {
		root = `c:\windows`
	}
	return strings.HasPrefix(l, root+`\`)
}

func windowsListeners(ctx context.Context) ([]Item, error) {
	out, err := run(ctx, systemExe("netstat.exe"), "-ano")
	if err != nil && out == "" {
		return nil, err
	}
	paths := processPaths()
	var items []Item
	seen := map[string]bool{}
	for _, l := range parseNetstat(out) {
		loopback := isLoopback(l.host)
		key := strconv.Itoa(l.pid) + "|" + strconv.Itoa(l.port) + "|" + strconv.FormatBool(loopback)
		if seen[key] {
			continue // same port on IPv4 and IPv6
		}
		seen[key] = true
		path := paths[l.pid]
		if l.pid == 4 {
			path = "System"
		}
		service := ""
		if s, ok := identify(path); ok {
			service = s.product
		}
		items = append(items, Item{
			"service":        service,
			"process":        strings.TrimSuffix(winBase(path), ".exe"),
			"pid":            l.pid,
			"user":           "",
			"path":           path,
			"address":        l.host,
			"port":           l.port,
			"loopback":       loopback,
			"all_interfaces": l.host == "0.0.0.0" || l.host == "::",
			"reachable":      !loopback,
			"system_binary":  winSystemProcess(path, envLookup("SystemRoot")),
		})
	}
	return items, nil
}
