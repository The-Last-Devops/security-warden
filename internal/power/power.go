// Package power tells whether the computer runs on battery, so background
// work can slow down to save it.
package power

import (
	"context"
	"time"
)

// OnBattery reports true only when the machine is known to run on battery;
// desktops, unknown states and errors count as plugged in.
func OnBattery() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return onBattery(ctx)
}
