//go:build !darwin && !linux && !windows

package source

import "context"

func posture(ctx context.Context) ([]Item, error) {
	return nil, Skip{"skip.platform"}
}
