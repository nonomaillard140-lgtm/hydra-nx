package fuzz

import (
	"net/url"
	"strings"
)

const CorpusVersion = "2026.11-defensive"

type Variant struct {
	Path  string `json:"path"`
	Label string `json:"label"`
}

type CorpusEntry struct {
	Raw  string
	Tags string
}

// Corpus contient des sondes d'exposition défensives, sans contournement de WAF.
func Corpus() []CorpusEntry {
	return []CorpusEntry{
		{Raw: "/.env", Tags: "configuration,secrets"},
		{Raw: "/wp-config.php.bak", Tags: "wordpress,sauvegarde"},
		{Raw: "/.git/HEAD", Tags: "git,code_source"},
		{Raw: "/phpinfo.php", Tags: "debug,configuration"},
		{Raw: "/.DS_Store", Tags: "metadata"},
		{Raw: "/config.json.bak", Tags: "configuration,sauvegarde"},
		{Raw: "/assets/index.js.map", Tags: "sourcemap,code_source"},
		{Raw: "/server-status", Tags: "debug,apache"},
	}
}

// Variants produit uniquement des formes canoniques; les contournements sont exclus.
func Variants(raw string) []Variant {
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	seen := make(map[string]struct{})
	out := make([]Variant, 0, 3)
	add := func(path, label string) {
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		out = append(out, Variant{Path: path, Label: label})
	}
	add(raw, "canonique")
	parts := strings.Split(raw, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	add(strings.Join(parts, "/"), "echappement_url")
	if raw != "/" {
		add(strings.TrimSuffix(raw, "/")+"/", "slash_final")
	}
	return out
}

func VariantPaths(raw string) []string {
	variants := Variants(raw)
	out := make([]string, len(variants))
	for i, variant := range variants {
		out[i] = variant.Path
	}
	return out
}
