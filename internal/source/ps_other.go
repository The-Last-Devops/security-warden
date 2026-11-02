//go:build !windows

package source

import (
	"context"
	"errors"
)

func runPS(ctx context.Context, script string) (string, error) {
	return "", errors.New("PowerShell checks run on Windows only")
}
