package validate

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Verdict string

const (
	Plausible Verdict = "plausible"
	Doubtful  Verdict = "doubtful"
	Invalid   Verdict = "invalid"
)

type Result struct {
	Verdict Verdict           `json:"verdict"`
	Reason  string            `json:"reason"`
	Meta    map[string]string `json:"meta,omitempty"`
}

type rule struct {
	re   *regexp.Regexp
	note string
}

var rules = map[string]rule{
	"aws":       {regexp.MustCompile(`^(AKIA|ASIA)[0-9A-Z]{16}$`), "identifiant AWS"},
	"stripe":    {regexp.MustCompile(`^(sk|rk|pk)_(live|test)_[0-9a-zA-Z]{16,}$`), "clé Stripe"},
	"sendgrid":  {regexp.MustCompile(`^SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}$`), "clé SendGrid"},
	"mailgun":   {regexp.MustCompile(`^key-[0-9a-zA-Z]{32}$`), "clé Mailgun"},
	"postmark":  {regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`), "jeton Postmark"},
	"brevo":     {regexp.MustCompile(`^xkeysib-[0-9a-f]{64}-[0-9A-Za-z]{16}$`), "clé Brevo"},
	"github":    {regexp.MustCompile(`^gh[pousr]_[0-9A-Za-z]{36,}$`), "jeton GitHub"},
	"gitlab":    {regexp.MustCompile(`^glpat-[0-9A-Za-z_\-]{20,}$`), "jeton GitLab"},
	"slack":     {regexp.MustCompile(`^https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+$`), "webhook Slack"},
	"discord":   {regexp.MustCompile(`^https://(discord\.com|discordapp\.com)/api/webhooks/[0-9]+/[0-9A-Za-z_\-]+$`), "webhook Discord"},
	"twilio":    {regexp.MustCompile(`^AC[0-9a-f]{32}$`), "SID Twilio"},
	"npm":       {regexp.MustCompile(`^npm_[0-9A-Za-z]{36}$`), "jeton npm"},
	"openai":    {regexp.MustCompile(`^sk-[0-9A-Za-z_\-]{20,}$`), "clé OpenAI"},
	"anthropic": {regexp.MustCompile(`^sk-ant-[0-9A-Za-z_\-]{20,}$`), "clé Anthropic"},
	"gemini":    {regexp.MustCompile(`^AIza[0-9A-Za-z_\-]{35}$`), "clé Google API"},
	"xai":       {regexp.MustCompile(`^xai-[0-9A-Za-z]{20,}$`), "clé xAI"},
	"groq":      {regexp.MustCompile(`^gsk_[0-9A-Za-z]{40,}$`), "clé Groq"},
	"database":  {regexp.MustCompile(`^(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^\s]{8,}$`), "chaîne de connexion"},
	"smtp":      {regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`), "identifiant SMTP"},
}

var placeholders = []string{"example", "exemple", "changeme", "your_", "your-", "xxxx", "<", ">", "todo", "placeholder", "dummy", "sample", "localhost"}

func isPlaceholder(s string) bool {
	if s == "AKIAIOSFODNN7EXAMPLE" {
		return true
	}
	l := strings.ToLower(s)
	for _, p := range placeholders {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func Check(service, secret string) Result {
	s := strings.TrimSpace(secret)
	if s == "" {
		return Result{Verdict: Invalid, Reason: "valeur absente"}
	}
	if isPlaceholder(s) {
		return Result{Verdict: Invalid, Reason: "valeur d'exemple"}
	}
	r, ok := rules[strings.ToLower(service)]
	if !ok {
		return generic(s)
	}
	if !r.re.MatchString(s) {
		return Result{Verdict: Invalid, Reason: "format non conforme"}
	}
	res := Result{Verdict: Plausible, Reason: r.note, Meta: map[string]string{"longueur": strconv.Itoa(len(s))}}
	if strings.HasPrefix(s, "eyJ") && strings.Count(s, ".") == 2 {
		enrichJWT(&res, s)
	}
	if entropy(s) < 3.0 {
		res.Verdict = Doubtful
		res.Reason = "entropie faible"
	}
	return res
}

func generic(s string) Result {
	h := entropy(s)
	switch {
	case len(s) < 16:
		return Result{Verdict: Invalid, Reason: "trop court"}
	case h < 3.2:
		return Result{Verdict: Doubtful, Reason: "entropie faible, format inconnu"}
	default:
		return Result{Verdict: Doubtful, Reason: "format inconnu, entropie élevée"}
	}
}

func enrichJWT(res *Result, s string) {
	parts := strings.Split(s, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		res.Verdict = Doubtful
		res.Reason = "payload JWT non décodable"
		return
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		res.Verdict = Doubtful
		res.Reason = "payload JWT non JSON"
		return
	}
	if exp, ok := claims["exp"].(float64); ok {
		t := time.Unix(int64(exp), 0).UTC()
		if res.Meta == nil {
			res.Meta = map[string]string{}
		}
		res.Meta["exp"] = t.Format(time.RFC3339)
		if time.Now().After(t) {
			res.Verdict = Doubtful
			res.Reason = "JWT expiré"
		}
	}
}
