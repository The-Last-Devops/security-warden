//go:build !darwin

package source

import "context"

func apps(ctx context.Context) ([]Item, error) { return nil, Skip{"skip.platform"} }
