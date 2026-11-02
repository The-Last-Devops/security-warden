package source

import (
	"context"
	"strings"
)

// backup reports whether Time Machine has a destination and whether every
// destination is encrypted. Other backup tools are not detected, so the
// rule says so.
func backup(ctx context.Context) ([]Item, error) {
	out, _ := run(ctx, "defaults", "read", "/Library/Preferences/com.apple.TimeMachine")
	configured := strings.Contains(out, "DestinationID")
	encrypted := configured && !strings.Contains(out, "NotEncrypted")
	return []Item{{"tool": "Time Machine", "configured": configured, "encrypted": encrypted}}, nil
}
