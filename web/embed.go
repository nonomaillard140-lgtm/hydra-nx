// Package web embarque la compilation React pour le binaire statique.
package web

import "embed"

//go:embed all:dist
var Assets embed.FS
