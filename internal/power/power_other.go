//go:build !darwin && !linux

package power

import "context"

func onBattery(ctx context.Context) bool { return false }
