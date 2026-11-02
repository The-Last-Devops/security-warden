package power

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOnBatteryLinuxSysfs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sysfs layout is Linux only")
	}
	mk := func(dir, typ, file, val string) {
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "type"), []byte(typ+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(dir, file), []byte(val+"\n"), 0o644)
	}
	root := t.TempDir()
	mk(filepath.Join(root, "BAT0"), "Battery", "status", "Discharging")
	mk(filepath.Join(root, "AC"), "Mains", "online", "0")
	if !onBatteryIn(root) {
		t.Error("unplugged laptop should be on battery")
	}
	mk(filepath.Join(root, "AC"), "Mains", "online", "1")
	if onBatteryIn(root) {
		t.Error("plugged in laptop is not on battery")
	}
	if onBatteryIn(t.TempDir()) {
		t.Error("a desktop without power supplies is not on battery")
	}
}
