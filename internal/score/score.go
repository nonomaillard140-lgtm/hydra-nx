package score

import "strings"

type Result struct {
	Points   int
	Priority int
}

// Score mesure la gravité et la priorité de remédiation, jamais une valeur monétaire.
func Score(vuln, service string, findings int) Result {
	points := 10
	switch strings.ToLower(vuln) {
	case "env_exposure", "wp_config_exposure", "git_exposed":
		points = 80
	case "sourcemap_exposure", "backup_exposure":
		points = 45
	case "debug_exposure", "metadata_exposure":
		points = 25
	}
	if findings > 0 {
		points += min(findings*3, 30)
	}
	priority := points
	if service != "generic" && service != "unknown" {
		priority += 10
	}
	return Result{Points: points, Priority: min(priority, 100)}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
