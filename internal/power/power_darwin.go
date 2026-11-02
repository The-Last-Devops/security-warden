package power

import (
	"context"
	"os/exec"
	"strings"
)

func onBattery(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "pmset", "-g", "batt").Output()
	return err == nil && parsePmset(string(out))
}

// parsePmset reads the first line of `pmset -g batt`:
// "Now drawing from 'Battery Power'" or "... 'AC Power'".
func parsePmset(s string) bool {
	return strings.Contains(s, "'Battery Power'")
}
