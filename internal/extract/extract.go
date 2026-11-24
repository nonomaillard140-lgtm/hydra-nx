package extract

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed services.json
var serviceData []byte

type servicePattern struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	re      *regexp.Regexp
}

var (
	servicesOnce sync.Once
	services     []servicePattern
	servicesErr  error
)

func loadServices() {
	var raw []servicePattern
	if err := json.Unmarshal(serviceData, &raw); err != nil {
		servicesErr = err
		return
	}
	for _, item := range raw {
		re, err := regexp.Compile(item.Pattern)
		if err != nil {
			servicesErr = err
			return
		}
		item.re = re
		services = append(services, item)
	}
}

func Classify(value string) string {
	servicesOnce.Do(loadServices)
	if servicesErr != nil {
		return "generic"
	}
	for _, service := range services {
		if service.re.MatchString(value) {
			return service.Name
		}
	}
	return "generic"
}

type Finding struct {
	Service   string `json:"service"`
	Variable  string `json:"variable"`
	Redacted  string `json:"redacted"`
	ValueHash string `json:"value_hash"`
	Entropy   bool   `json:"entropy"`
}

type Exposure struct {
	Vuln       string    `json:"vuln"`
	Findings   []Finding `json:"findings"`
	Confidence int       `json:"confidence"`
	Summary    string    `json:"summary"`
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newFinding(variable, value string) Finding {
	return Finding{Service: Classify(variable + " " + valuePrefix(value)), Variable: variable,
		Redacted: variable + "=<redacted>", ValueHash: fingerprint(value)}
}

func valuePrefix(value string) string {
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

func cleanEnvValue(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 && ((raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'')) {
		return raw[1 : len(raw)-1]
	}
	if index := strings.Index(raw, " #"); index >= 0 {
		raw = raw[:index]
	}
	return strings.TrimSpace(raw)
}

// ParseEnv ne conserve jamais les valeurs: seules des preuves rédigées et des empreintes sortent.
func ParseEnv(body []byte) []Finding {
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	findings := make([]Finding, 0)
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`).MatchString(key) {
			continue
		}
		value := cleanEnvValue(parts[1])
		if value == "" || IsPublicExample(value) {
			continue
		}
		upper := strings.ToUpper(key)
		if !(strings.Contains(upper, "KEY") || strings.Contains(upper, "SECRET") || strings.Contains(upper, "TOKEN") ||
			strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "PASSWD") || strings.Contains(upper, "USERNAME") ||
			strings.Contains(upper, "DATABASE_URL") || strings.HasPrefix(upper, "MAIL_") || strings.HasPrefix(upper, "AWS_")) {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		findings = append(findings, newFinding(key, value))
		if len(findings) >= 100 {
			break
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Variable < findings[j].Variable })
	return findings
}

var wpDefine = regexp.MustCompile(`(?m)define\s*\(\s*['"]([A-Z0-9_]+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)`)

func ParseWPConfig(body []byte) []Finding {
	matches := wpDefine.FindAllSubmatch(body, 100)
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		key, value := string(match[1]), string(match[2])
		if value == "" || IsPublicExample(value) {
			continue
		}
		if strings.Contains(key, "DB_") || strings.Contains(key, "KEY") || strings.Contains(key, "SALT") || strings.Contains(key, "PASSWORD") {
			findings = append(findings, newFinding(key, value))
		}
	}
	return findings
}

func ParseSourceMap(body []byte) ([]string, bool) {
	var document struct {
		Version int      `json:"version"`
		Sources []string `json:"sources"`
	}
	if json.Unmarshal(body, &document) != nil || document.Version == 0 || len(document.Sources) == 0 {
		return nil, false
	}
	sources := append([]string(nil), document.Sources...)
	if len(sources) > 200 {
		sources = sources[:200]
	}
	return sources, true
}

func ParseGitHEAD(body []byte) (string, bool) {
	line := strings.TrimSpace(string(body))
	if strings.HasPrefix(line, "ref: refs/heads/") && len(line) < 200 {
		return strings.TrimPrefix(line, "ref: "), true
	}
	if regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(line) {
		return "detached:" + line, true
	}
	return "", false
}

func ShannonEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	frequency := make(map[rune]float64)
	for _, r := range value {
		frequency[r]++
	}
	length := float64(len([]rune(value)))
	var entropy float64
	for _, count := range frequency {
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

var entropyCandidate = regexp.MustCompile(`[A-Za-z0-9_+/=-]{32,}`)

func HighEntropyFindings(body []byte) []Finding {
	matches := entropyCandidate.FindAll(body, 1000)
	findings := make([]Finding, 0)
	seen := make(map[string]struct{})
	for _, match := range matches {
		value := string(match)
		if ShannonEntropy(value) < 4.2 || IsPublicExample(value) {
			continue
		}
		hash := fingerprint(value)
		if _, ok := seen[hash]; ok {
			continue
		}
		seen[hash] = struct{}{}
		findings = append(findings, Finding{Service: Classify(value), Variable: "unknown_high_entropy", Redacted: "unknown_high_entropy=<redacted>", ValueHash: hash, Entropy: true})
		if len(findings) >= 20 {
			break
		}
	}
	return findings
}

func IsPublicExample(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return true
	}
	exact := map[string]bool{"example": true, "changeme": true, "change-me": true, "password": true, "secret": true, "placeholder": true, "dummy": true, "test": true, "testtest": true, "xxxxxxxx": true}
	if exact[lower] || strings.HasPrefix(lower, "your_") || strings.HasPrefix(lower, "your-") || strings.Contains(lower, "example") || strings.Contains(lower, "xxxx") {
		return true
	}
	return value == "AKIAIOSFODNN7EXAMPLE"
}

func Detect(requestPath string, body []byte) (Exposure, bool) {
	base := strings.ToLower(path.Base(requestPath))
	switch {
	case base == ".env" || strings.HasPrefix(base, ".env."):
		findings := ParseEnv(body)
		return Exposure{Vuln: "env_exposure", Findings: findings, Confidence: 95, Summary: "Fichier d'environnement lisible; révoquer les secrets exposés"}, true
	case strings.HasPrefix(base, "wp-config.php"):
		findings := ParseWPConfig(body)
		return Exposure{Vuln: "wp_config_exposure", Findings: findings, Confidence: 95, Summary: "Configuration WordPress lisible; rotation des accès requise"}, true
	case strings.HasSuffix(strings.ToLower(requestPath), "/.git/head"):
		ref, ok := ParseGitHEAD(body)
		if !ok {
			return Exposure{}, false
		}
		return Exposure{Vuln: "git_exposed", Confidence: 90, Summary: "Métadonnées Git exposées: " + ref}, true
	case strings.HasSuffix(base, ".map"):
		sources, ok := ParseSourceMap(body)
		if !ok {
			return Exposure{}, false
		}
		return Exposure{Vuln: "sourcemap_exposure", Confidence: 80, Summary: "Source map exposée", Findings: HighEntropyFindings(body)}, len(sources) > 0
	case base == "phpinfo.php" || base == "info.php":
		if !strings.Contains(strings.ToLower(string(body)), "php version") {
			return Exposure{}, false
		}
		return Exposure{Vuln: "debug_exposure", Confidence: 85, Summary: "Page phpinfo publique"}, true
	case base == ".ds_store" || strings.HasSuffix(base, ".bak"):
		findings := ParseEnv(body)
		findings = append(findings, HighEntropyFindings(body)...)
		return Exposure{Vuln: "backup_exposure", Confidence: 65, Summary: "Sauvegarde ou métadonnées accessibles", Findings: findings}, len(body) > 24
	default:
		findings := HighEntropyFindings(body)
		return Exposure{Vuln: "secret_pattern", Confidence: 55, Summary: "Motif à forte entropie détecté, revue manuelle requise", Findings: findings}, len(findings) > 0
	}
}
