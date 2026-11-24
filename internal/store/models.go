package store

import "time"

type User struct {
	ID           int64     `json:"id"`
	Email        string    `json:"email"`
	Username     string    `json:"username"`
	PassHash     string    `json:"-"`
	Role         string    `json:"role"`
	TOTPSecret   string    `json:"-"`
	RecoveryJSON string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	Banned       bool      `json:"banned"`
	TelegramID   string    `json:"telegram_id"`
}

type Session struct {
	ID        string
	UserID    int64
	TokenHash string
	UA        string
	IP        string
	ExpiresAt time.Time
}

type Plan struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	PriceCents    int64  `json:"price_cents"`
	DurationHours int    `json:"duration_hours"`
	MaxDevices    int    `json:"max_devices"`
	DailyCredits  int    `json:"daily_credits"`
	FeaturesJSON  string `json:"features_json"`
}

type License struct {
	ID         int64     `json:"id"`
	Key        string    `json:"key"`
	PlanID     int64     `json:"plan_id"`
	PlanName   string    `json:"plan_name,omitempty"`
	UserID     int64     `json:"user_id"`
	MaxDevices int       `json:"max_devices"`
	ExpiresAt  time.Time `json:"expires_at"`
	Signature  string    `json:"signature"`
	Revoked    bool      `json:"revoked"`
}

type List struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"user_id"`
	Name       string    `json:"name"`
	Kind       string    `json:"kind"`
	Size       int       `json:"size"`
	Authorized bool      `json:"authorized"`
	CreatedAt  time.Time `json:"created_at"`
	Items      []string  `json:"items,omitempty"`
}

type Path struct {
	ID       int64    `json:"id"`
	UserID   int64    `json:"user_id"`
	Raw      string   `json:"raw"`
	Variants []string `json:"variants"`
	Tags     string   `json:"tags"`
}

type Crack struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	ListID     int64      `json:"list_id"`
	PathID     int64      `json:"path_id"`
	Status     string     `json:"status"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	StatsJSON  string     `json:"stats_json"`
	Confirmed  bool       `json:"authorization_confirmed"`
	CreatedAt  time.Time  `json:"created_at"`
	ListName   string     `json:"list_name,omitempty"`
	PathRaw    string     `json:"path_raw,omitempty"`
}

type Hit struct {
	ID             int64     `json:"id"`
	CrackID        int64     `json:"crack_id"`
	UserID         int64     `json:"user_id"`
	Host           string    `json:"host"`
	Path           string    `json:"path"`
	Vuln           string    `json:"vuln"`
	Service        string    `json:"service"`
	SecretRedacted string    `json:"secret_redacted"`
	SecretHash     string    `json:"-"`
	Status         string    `json:"status"`
	Points         int       `json:"points"`
	CashScore      int       `json:"cash_score"`
	SMTPUsable     bool      `json:"smtp_usable"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

type PublicList struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Filename    string    `json:"filename"`
	SizeBytes   int64     `json:"size_bytes"`
	Lines       int       `json:"lines"`
	SHA256      string    `json:"sha256"`
	Format      string    `json:"format"`
	PublishedAt time.Time `json:"published_at"`
	PublishedBy int64     `json:"published_by"`
	Downloads   int64     `json:"downloads"`
	Hidden      bool      `json:"hidden"`
}

type Notification struct {
	ID         int64  `json:"id"`
	UserID     int64  `json:"user_id"`
	Addon      string `json:"addon"`
	Channel    string `json:"channel"`
	Target     string `json:"target"`
	SecretJSON string `json:"-"`
	Enabled    bool   `json:"enabled"`
}

type Send struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Transport string    `json:"transport"`
	From      string    `json:"from_addr"`
	To        string    `json:"to_addr"`
	Subject   string    `json:"subject"`
	Status    string    `json:"status"`
	Error     string    `json:"error"`
	SentAt    time.Time `json:"sent_at"`
}

type AuditEntry struct {
	ID        int64     `json:"id"`
	ActorID   int64     `json:"actor_id"`
	ActorName string    `json:"actor_name"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	MetaJSON  string    `json:"meta_json"`
	CreatedAt time.Time `json:"created_at"`
}
