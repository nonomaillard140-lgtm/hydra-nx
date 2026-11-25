package fuzz

import "strings"

var highValue = []string{
	"/.env", "/.env.local", "/.env.prod", "/.env.production", "/.env.bak",
	"/wp-config.php", "/wp-config.php.bak", "/.git/config", "/.git/HEAD",
	"/config.php.bak", "/docker-compose.yml", "/.aws/credentials",
	"/.htpasswd", "/.svn/entries", "/backup.sql", "/app.js.map", "/main.js.map",
}

func IsHighValue(p string) bool {
	for _, s := range highValue {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

func pct(s, hex string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' || c == '.' {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// VariantsExtended n'est utilisée que si le réglage variants_extended est actif.
func VariantsExtended(raw string) []string {
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	out := []string{raw}
	if !IsHighValue(raw) {
		return out
	}
	seen := map[string]bool{raw: true}
	add := func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	low := pct(raw, "0123456789abcdef")
	add(low)
	add(strings.ReplaceAll(low, "%", "%25"))
	add(pct(raw, "0123456789ABCDEF"))
	add(raw + "/")
	add("/./" + strings.TrimPrefix(raw, "/"))
	if i := strings.LastIndex(raw, "."); i > strings.LastIndex(raw, "/") {
		add(raw[:i] + "%00" + raw[i:])
	}
	return out
}
