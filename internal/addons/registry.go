package addons

import (
	"context"
	"strings"
	"time"

	"hydra/internal/validate"
)

type Status string

const (
	StatusDetected  Status = "detected_unvalidated"
	StatusReview    Status = "manual_review"
	StatusPlausible Status = "plausible_local"
	StatusInvalid   Status = "invalid_local"
)

type Addon struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

type Evidence struct {
	Service  string `json:"service"`
	Redacted string `json:"redacted"`
	Hash     string `json:"hash"`
	Value    string `json:"-"`
}

type Result struct {
	Status    Status    `json:"status"`
	Quota     string    `json:"quota"`
	Scope     string    `json:"scope"`
	Action    string    `json:"suggested_action"`
	Reason    string    `json:"reason"`
	CheckedAt time.Time `json:"checked_at"`
}

// Registry effectue une analyse locale: aucune requête vers un compte tiers avec un secret trouvé.
type Registry struct {
	addons map[string]Addon
}

func NewRegistry() *Registry {
	catalog := []Addon{
		{Name: "aws", Category: "cloud", Description: "Exposition de variables AWS"},
		{Name: "stripe", Category: "payment", Description: "Configuration Stripe exposée"},
		{Name: "sendgrid", Category: "mail", Description: "Configuration SendGrid exposée"},
		{Name: "mailgun", Category: "mail", Description: "Configuration Mailgun exposée"},
		{Name: "sparkpost", Category: "mail", Description: "Configuration SparkPost exposée"},
		{Name: "mandrill", Category: "mail", Description: "Configuration Mandrill exposée"},
		{Name: "postmark", Category: "mail", Description: "Configuration Postmark exposée"},
		{Name: "mailchimp", Category: "mail", Description: "Configuration Mailchimp exposée"},
		{Name: "mailjet", Category: "mail", Description: "Configuration Mailjet exposée"},
		{Name: "brevo", Category: "mail", Description: "Configuration Brevo exposée"},
		{Name: "smtp", Category: "mail", Description: "Paramètres SMTP exposés"},
		{Name: "o365", Category: "mail", Description: "Paramètres Microsoft 365 exposés"},
		{Name: "github", Category: "code", Description: "Jeton GitHub exposé"},
		{Name: "gitlab", Category: "code", Description: "Jeton GitLab exposé"},
		{Name: "slack", Category: "collaboration", Description: "Jeton Slack exposé"},
		{Name: "discord", Category: "collaboration", Description: "Configuration Discord exposée"},
		{Name: "twilio", Category: "communication", Description: "Configuration Twilio exposée"},
		{Name: "firebase", Category: "cloud", Description: "Configuration Firebase exposée"},
		{Name: "supabase", Category: "cloud", Description: "Configuration Supabase exposée"},
		{Name: "cloudflare", Category: "cloud", Description: "Configuration Cloudflare exposée"},
		{Name: "digitalocean", Category: "cloud", Description: "Configuration DigitalOcean exposée"},
		{Name: "vercel", Category: "cloud", Description: "Configuration Vercel exposée"},
		{Name: "netlify", Category: "cloud", Description: "Configuration Netlify exposée"},
		{Name: "npm", Category: "code", Description: "Jeton npm exposé"},
		{Name: "dockerhub", Category: "code", Description: "Configuration Docker Hub exposée"},
		{Name: "database", Category: "database", Description: "Accès de base de données exposé"},
		{Name: "openai", Category: "ai", Description: "Configuration OpenAI exposée"},
		{Name: "anthropic", Category: "ai", Description: "Configuration Anthropic exposée"},
		{Name: "gemini", Category: "ai", Description: "Configuration Gemini exposée"},
		{Name: "xai", Category: "ai", Description: "Configuration xAI exposée"},
		{Name: "mistral", Category: "ai", Description: "Configuration Mistral exposée"},
		{Name: "groq", Category: "ai", Description: "Configuration Groq exposée"},
		{Name: "generic", Category: "unknown", Description: "Secret non classé à examiner"},
	}
	registry := &Registry{addons: make(map[string]Addon, len(catalog))}
	for _, addon := range catalog {
		registry.addons[addon.Name] = addon
	}
	return registry
}

func (r *Registry) List() []Addon {
	out := make([]Addon, 0, len(r.addons))
	for _, addon := range r.addons {
		out = append(out, addon)
	}
	return out
}

func (r *Registry) Validate(_ context.Context, evidence Evidence) Result {
	service := strings.ToLower(evidence.Service)
	action := "Révoquer le secret exposé, le régénérer et vérifier les journaux d'accès"
	if _, ok := r.addons[service]; !ok {
		service = "generic"
	}
	verdict := validate.Check(service, evidence.Value)
	result := Result{Quota: "non interrogé", Scope: service + ", preuve locale uniquement", Reason: verdict.Reason, Action: action, CheckedAt: time.Now().UTC()}
	switch verdict.Verdict {
	case validate.Plausible:
		result.Status = StatusPlausible
	case validate.Doubtful:
		result.Status = StatusReview
	default:
		result.Status = StatusInvalid
	}
	return result
}
