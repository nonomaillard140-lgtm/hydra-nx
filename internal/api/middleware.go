package api

import (
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[string]*bucket)}
}

func (l *rateLimiter) allow(key string, rate float64, burst float64) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	item, ok := l.buckets[key]
	if !ok {
		item = &bucket{tokens: burst, last: now}
		l.buckets[key] = item
	}
	item.tokens += now.Sub(item.last).Seconds() * rate
	if item.tokens > burst {
		item.tokens = burst
	}
	item.last = now
	if item.tokens < 1 {
		return false
	}
	item.tokens--
	if len(l.buckets) > 10000 {
		for key, value := range l.buckets {
			if now.Sub(value.last) > time.Hour {
				delete(l.buckets, key)
			}
		}
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func requestID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "unknown"
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func (s *Server) commonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-Id", requestID())
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		if !s.limiter.allow("global:"+clientIP(r), 20, 60) {
			writeError(w, http.StatusTooManyRequests, "limite de débit atteinte")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
			writeError(w, http.StatusForbidden, "en-tête de protection CSRF requis")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("nx_session")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentification requise")
			return
		}
		parts := strings.Split(cookie.Value, ".")
		if len(parts) != 2 || !s.store.VerifySignature(parts[0], parts[1]) {
			writeError(w, http.StatusUnauthorized, "session invalide")
			return
		}
		_, user, err := s.store.SessionByToken(r.Context(), parts[0])
		if err != nil {
			writeError(w, http.StatusUnauthorized, "session expirée")
			return
		}
		next.ServeHTTP(w, r.WithContext(contextWithUser(r, user)))
	})
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r.Context()).Role != "admin" {
			writeError(w, http.StatusForbidden, "rôle administrateur requis")
			return
		}
		next.ServeHTTP(w, r)
	})
}
