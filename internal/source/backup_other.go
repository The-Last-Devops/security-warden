//go:build !darwin

package source

import "context"

func backup(ctx context.Context) ([]Item, error) { return nil, Skip{"skip.platform"} }
