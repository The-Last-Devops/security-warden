package power

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

func onBattery(ctx context.Context) bool { return onBatteryIn("/sys/class/power_supply") }

// onBatteryIn: on battery when no mains supply is online and a battery is
// discharging.
func onBatteryIn(dir string) bool {
	supplies, _ := filepath.Glob(filepath.Join(dir, "*"))
	mains, discharging := false, false
	for _, d := range supplies {
		typ := read(filepath.Join(d, "type"))
		switch typ {
		case "Mains", "USB":
			if read(filepath.Join(d, "online")) == "1" {
				mains = true
			}
		case "Battery":
			if read(filepath.Join(d, "status")) == "Discharging" {
				discharging = true
			}
		}
	}
	return discharging && !mains
}

func read(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}
