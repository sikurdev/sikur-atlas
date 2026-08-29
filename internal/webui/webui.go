// Package webui embeds the built web interface. The dist directory is a
// build artifact (make web); only a .gitkeep is committed so the embed
// pattern always resolves.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var distFS embed.FS

// Dist returns the built UI as a filesystem rooted at the asset
// directory, or ok=false when the UI has not been built into this
// binary.
func Dist() (fs.FS, bool) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, false
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil, false
	}
	return sub, true
}
