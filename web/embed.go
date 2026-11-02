// Package web holds the built UI (Vue + Tailwind, see web/src). The Go
// binary embeds web/dist; build it with: docker compose run --rm web
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// UI is the built single-page app.
func UI() fs.FS {
	sub, _ := fs.Sub(dist, "dist")
	return sub
}
