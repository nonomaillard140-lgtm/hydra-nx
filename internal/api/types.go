package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"hydra/internal/auth"
	"hydra/internal/license"
	"hydra/internal/notify"
	"hydra/internal/publiclists"
	"hydra/internal/scan"
	"hydra/internal/send"
	"hydra/internal/store"
)

type contextKey string

const userContextKey contextKey = "user"

type Server struct {
	store        *store.Store
	auth         *auth.Service
	scheduler    *scan.Scheduler
	licenses     *license.Manager
	lists        *publiclists.Service
	sender       *send.Manager
	notifier     *notify.Dispatcher
	secureCookie bool
	started      time.Time
	limiter      *rateLimiter
}

func NewServer(st *store.Store, authService *auth.Service, scheduler *scan.Scheduler, secureCookie bool) *Server {
	return &Server{store: st, auth: authService, scheduler: scheduler, licenses: license.NewManager(st),
		lists: publiclists.NewService(st), sender: send.NewManager(st), notifier: notify.NewDispatcher(st), secureCookie: secureCookie,
		started: time.Now().UTC(), limiter: newRateLimiter()}
}

func currentUser(ctx context.Context) store.User {
	user, _ := ctx.Value(userContextKey).(store.User)
	return user
}

func ownerID(user store.User) int64 {
	if user.Role == "admin" {
		return 0
	}
	return user.ID
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "JSON invalide ou champ inconnu")
		return false
	}
	return true
}

func cleanMessage(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, store.ErrNotFound) {
		return "élément introuvable"
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 300 {
		message = message[:300]
	}
	return message
}
