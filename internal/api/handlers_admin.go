package api

import (
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"hydra/internal/auth"
	"hydra/internal/store"
)

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.Users(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	hash, err := auth.HashPassword(request.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	user, err := s.store.CreateUser(r.Context(), request.Email, request.Username, hash, request.Role)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	_ = s.store.Audit(r.Context(), currentUser(r.Context()).ID, "admin.user.create", user.Username, "{}")
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) handleAdminBan(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	var request struct {
		Banned bool `json:"banned"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if id == currentUser(r.Context()).ID && request.Banned {
		writeError(w, http.StatusBadRequest, "auto-bannissement interdit")
		return
	}
	if err := s.store.SetUserBanned(r.Context(), id, request.Banned); err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAdminPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := s.store.Plans(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, plans)
}

func (s *Server) handleAdminUpdatePlan(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	plan, err := s.store.PlanByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, cleanMessage(err))
		return
	}
	var request struct {
		PriceCents    int64  `json:"price_cents"`
		DurationHours int    `json:"duration_hours"`
		MaxDevices    int    `json:"max_devices"`
		DailyCredits  int    `json:"daily_credits"`
		FeaturesJSON  string `json:"features_json"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	plan.PriceCents, plan.DurationHours, plan.MaxDevices, plan.DailyCredits, plan.FeaturesJSON = request.PriceCents, request.DurationHours, request.MaxDevices, request.DailyCredits, request.FeaturesJSON
	if err := s.store.UpdatePlan(r.Context(), plan); err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handleAdminIssueLicense(w http.ResponseWriter, r *http.Request) {
	var request struct {
		UserID int64 `json:"user_id"`
		PlanID int64 `json:"plan_id"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	license, err := s.licenses.Issue(r.Context(), request.UserID, request.PlanID)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	_ = s.store.Audit(r.Context(), currentUser(r.Context()).ID, "admin.license.issue", strconv.FormatInt(license.ID, 10), "{}")
	writeJSON(w, http.StatusCreated, license)
}

func (s *Server) handleAdminRevokeLicense(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	if err := s.store.RevokeLicense(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.AuditLog(r.Context(), 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.store.Settings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	delete(settings, "smtp_control_config")
	for key := range settings {
		if len(key) >= 12 && key[:12] == "totp_pending" {
			delete(settings, key)
		}
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleAdminUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var request map[string]string
	if !decodeJSON(w, r, &request) {
		return
	}
	allowed := map[string]bool{"concurrency": true, "timeout_seconds": true, "host_limit": true, "maintenance": true, "public_hits": true, "grace_hours": true}
	for key, value := range request {
		if !allowed[key] {
			writeError(w, http.StatusBadRequest, "réglage non modifiable: "+key)
			return
		}
		if err := s.store.SetSetting(r.Context(), key, value); err != nil {
			writeError(w, http.StatusBadRequest, cleanMessage(err))
			return
		}
	}
	_ = s.store.Audit(r.Context(), currentUser(r.Context()).ID, "admin.settings", "global", store.MarshalJSON(request))
	writeJSON(w, http.StatusOK, map[string]string{"status": "réglages enregistrés; redémarrage requis pour la concurrence"})
}

func (s *Server) handleAdminClearQueue(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteAllCracks(r.Context(), 0); err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "files marquées annulées; les requêtes courantes se terminent"})
}

func (s *Server) handleAdminImpersonate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "user_id requis")
		return
	}
	user, err := s.store.UserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, cleanMessage(err))
		return
	}
	metrics, err := s.store.Dashboard(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	lists, err := s.store.Lists(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	hits, err := s.store.Hits(r.Context(), id, "", "", "", 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	_ = s.store.Audit(r.Context(), currentUser(r.Context()).ID, "admin.impersonate.read", user.Username, "{}")
	writeJSON(w, http.StatusOK, map[string]any{"mode": "lecture_seule", "user": user, "metrics": metrics, "lists": lists, "hits": hits})
}

func (s *Server) handleAdminPublishList(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(100 * 1024 * 1024); err != nil {
		writeError(w, http.StatusBadRequest, "multipart invalide")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "fichier requis")
		return
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, 100*1024*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "lecture du fichier impossible")
		return
	}
	format := r.FormValue("format")
	if format == "" {
		format = strings.TrimPrefix(strings.ToLower(filepath.Ext(header.Filename)), ".")
	}
	item, err := s.lists.ImportBytes(r.Context(), content, r.FormValue("name"), r.FormValue("kind"), format, currentUser(r.Context()).ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) handleAdminHideList(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	var request struct {
		Hidden bool `json:"hidden"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if err := s.store.HidePublicList(r.Context(), id, request.Hidden); err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
