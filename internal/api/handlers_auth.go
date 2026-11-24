package api

import (
	"errors"
	"net/http"
	"time"

	"hydra/internal/auth"
)

type loginRequest struct {
	Identity          string `json:"identity"`
	Password          string `json:"password"`
	Code              string `json:"code"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow("login:"+clientIP(r), 0.2, 5) {
		writeError(w, http.StatusTooManyRequests, "trop de tentatives de connexion")
		return
	}
	var request loginRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	user, err := s.auth.Authenticate(r.Context(), request.Identity, request.Password, request.Code)
	if err != nil {
		writeError(w, http.StatusUnauthorized, cleanMessage(err))
		return
	}
	maxDevices := 1
	if user.Role == "admin" {
		maxDevices = 0
	} else if _, _, err := s.store.ActiveLicense(r.Context(), user.ID); err == nil {
		_, plan, _ := s.store.ActiveLicense(r.Context(), user.ID)
		maxDevices = plan.MaxDevices
	}
	if request.DeviceFingerprint == "" {
		writeError(w, http.StatusBadRequest, "empreinte d'appareil requise")
		return
	}
	if err := s.store.SetDevice(r.Context(), user.ID, request.DeviceFingerprint, maxDevices); err != nil {
		writeError(w, http.StatusForbidden, cleanMessage(err))
		return
	}
	token, session, err := s.store.CreateSession(r.Context(), user.ID, r.UserAgent(), clientIP(r), 24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "création de session impossible")
		return
	}
	value := token + "." + s.store.Sign(token)
	http.SetCookie(w, &http.Cookie{Name: "nx_session", Value: value, Path: "/", HttpOnly: true, Secure: s.secureCookie, SameSite: http.SameSiteLaxMode, Expires: session.ExpiresAt, MaxAge: int(time.Until(session.ExpiresAt).Seconds())})
	_ = s.store.Audit(r.Context(), user.ID, "auth.login", user.Username, "{}")
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "expires_at": session.ExpiresAt})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("nx_session"); err == nil {
		parts := splitCookie(cookie.Value)
		if len(parts) == 2 {
			_ = s.store.DeleteSession(r.Context(), parts[0])
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "nx_session", Value: "", Path: "/", HttpOnly: true, Secure: s.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func splitCookie(value string) []string {
	for i := range value {
		if value[i] == '.' {
			return []string{value[:i], value[i+1:]}
		}
	}
	return nil
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("nx_session")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	parts := splitCookie(cookie.Value)
	if len(parts) != 2 || !s.store.VerifySignature(parts[0], parts[1]) {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	_, user, err := s.store.SessionByToken(r.Context(), parts[0])
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	remaining, limit, _ := s.store.CreditStatus(r.Context(), user.ID)
	session := map[string]any{"user": user, "credits_remaining": remaining, "daily_limit": limit, "totp_enabled": user.TOTPSecret != ""}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "session": session})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r.Context())
	remaining, limit, _ := s.store.CreditStatus(r.Context(), user.ID)
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "credits_remaining": remaining, "daily_limit": limit, "totp_enabled": user.TOTPSecret != ""})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := s.auth.ChangePassword(r.Context(), currentUser(r.Context()).ID, request.Current, request.Next); err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "mot de passe modifié; reconnectez-vous"})
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r.Context())
	if user.TOTPSecret != "" {
		writeError(w, http.StatusConflict, "TOTP est déjà activé")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "génération TOTP impossible")
		return
	}
	encrypted, err := s.store.Encrypt(secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "chiffrement TOTP impossible")
		return
	}
	if err := s.store.SetSetting(r.Context(), "totp_pending_"+idString(user.ID), "enc:"+encrypted); err != nil {
		writeError(w, http.StatusInternalServerError, "enregistrement TOTP impossible")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": auth.TOTPURI(secret, user.Username, "HYDRA")})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	user := currentUser(r.Context())
	pending, err := s.store.Setting(r.Context(), "totp_pending_"+idString(user.ID))
	if err != nil || len(pending) < 4 {
		writeError(w, http.StatusBadRequest, "aucune configuration TOTP en attente")
		return
	}
	secret, err := s.store.Decrypt(pending[4:])
	if err != nil || !auth.VerifyTOTP(secret, request.Code, time.Now()) {
		writeError(w, http.StatusBadRequest, "code TOTP invalide")
		return
	}
	codes, hashes, err := auth.NewRecoveryCodes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "génération des récupérations impossible")
		return
	}
	if err := s.store.EnableTOTP(r.Context(), user.ID, secret, hashes); err != nil {
		writeError(w, http.StatusInternalServerError, "activation TOTP impossible")
		return
	}
	_ = s.store.SetSetting(r.Context(), "totp_pending_"+idString(user.ID), "")
	writeJSON(w, http.StatusOK, map[string]any{"status": "TOTP activé", "recovery_codes": codes})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	user := currentUser(r.Context())
	if user.TOTPSecret == "" || !auth.VerifyTOTP(user.TOTPSecret, request.Code, time.Now()) {
		writeError(w, http.StatusBadRequest, "code TOTP invalide")
		return
	}
	if err := s.store.DisableTOTP(r.Context(), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "désactivation impossible")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "TOTP désactivé"})
}

func idString(id int64) string {
	return fmtInt(id)
}

func fmtInt(id int64) string {
	if id == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for id > 0 {
		i--
		buf[i] = byte('0' + id%10)
		id /= 10
	}
	return string(buf[i:])
}

var errInvalidID = errors.New("identifiant invalide")
