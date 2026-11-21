// Package ui holds the web interface: three static files, no build step,
// nothing fetched from anywhere else.
package ui

import "embed"

//go:embed static
var Files embed.FS
