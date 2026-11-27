package api

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"hydra/internal/addons"
	"hydra/internal/discover"
	"hydra/internal/fuzz"
	"hydra/internal/store"
)

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(chiURLParam(r, "id"), 10, 64)
}

func chiURLParam(r *http.Request, key string) string {
	return chi.URLParam(r, key)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "uptime_seconds": int64(time.Since(s.started).Seconds()), "queue_depth": s.scheduler.Depth()})
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r.Context())
	metrics, err := s.store.Dashboard(r.Context(), ownerID(user))
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	remaining, limit, _ := s.store.CreditStatus(r.Context(), user.ID)
	writeJSON(w, http.StatusOK, map[string]any{"metrics": metrics, "credits_remaining": remaining, "daily_limit": limit, "queue_depth": s.scheduler.Depth(), "scope": "cibles explicitement autorisées"})
}

func (s *Server) ensureDefaultPaths(r *http.Request, userID int64) error {
	for _, entry := range fuzz.Corpus() {
		if _, err := s.store.EnsurePath(r.Context(), userID, entry.Raw, fuzz.VariantPaths(entry.Raw), entry.Tags); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleLists(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.Lists(r.Context(), ownerID(currentUser(r.Context())))
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleCreateList(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name       string   `json:"name"`
		Kind       string   `json:"kind"`
		Items      []string `json:"items"`
		Authorized bool     `json:"authorized"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	items, err := discover.MergeAndNormalize(request.Kind, request.Items)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	user := currentUser(r.Context())
	item, err := s.store.CreateList(r.Context(), user.ID, request.Name, request.Kind, items, request.Authorized)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	item.Items = nil
	_ = s.store.Audit(r.Context(), user.ID, "list.create", strconv.FormatInt(item.ID, 10), store.MarshalJSON(map[string]any{"kind": item.Kind, "size": item.Size}))
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) handleDeleteList(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	if err := s.store.DeleteList(r.Context(), id, ownerID(currentUser(r.Context()))); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, cleanMessage(err))
			return
		}
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handlePaths(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r.Context())
	if err := s.ensureDefaultPaths(r, user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	items, err := s.store.Paths(r.Context(), ownerID(user))
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleCreatePath(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Raw  string `json:"raw"`
		Tags string `json:"tags"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	user := currentUser(r.Context())
	item, err := s.store.CreatePath(r.Context(), user.ID, request.Raw, fuzz.VariantPaths(request.Raw), request.Tags)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) handleDeletePath(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	if err := s.store.DeletePath(r.Context(), id, ownerID(currentUser(r.Context()))); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, cleanMessage(err))
			return
		}
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.Cracks(r.Context(), ownerID(currentUser(r.Context())), 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleClearScans(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r.Context())
	deleted, err := s.store.ClearScans(r.Context(), ownerID(user))
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	_ = s.store.Audit(r.Context(), user.ID, "scan.purge", "", store.MarshalJSON(map[string]int64{"deleted": deleted}))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted})
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if s.store.StringSetting(r.Context(), "maintenance", "false") == "true" {
		writeError(w, http.StatusServiceUnavailable, "nouveaux scans suspendus pendant la maintenance")
		return
	}
	var request struct {
		ListID    int64 `json:"list_id"`
		PathID    int64 `json:"path_id"`
		Confirmed bool  `json:"authorization_confirmed"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	user := currentUser(r.Context())
	crack, err := s.store.CreateCrack(r.Context(), user.ID, request.ListID, request.PathID, request.Confirmed)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	list, err := s.store.ListByID(r.Context(), request.ListID, user.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, cleanMessage(err))
		return
	}
	if err := s.store.ConsumeCredits(r.Context(), user.ID, list.Size, "scan "+strconv.FormatInt(crack.ID, 10)); err != nil {
		_ = s.store.SetCrackStatus(r.Context(), crack.ID, "failed", store.MarshalJSON(map[string]string{"error": "crédits insuffisants"}))
		writeError(w, http.StatusPaymentRequired, cleanMessage(err))
		return
	}
	if err := s.scheduler.Submit(crack.ID); err != nil {
		writeError(w, http.StatusServiceUnavailable, cleanMessage(err))
		return
	}
	_ = s.store.Audit(r.Context(), user.ID, "scan.start", strconv.FormatInt(crack.ID, 10), store.MarshalJSON(map[string]int{"targets": list.Size}))
	writeJSON(w, http.StatusCreated, crack)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	item, err := s.store.CrackByID(r.Context(), id, ownerID(currentUser(r.Context())))
	if err != nil {
		writeError(w, http.StatusNotFound, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleHits(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	items, err := s.store.Hits(r.Context(), ownerID(currentUser(r.Context())), query.Get("service"), query.Get("status"), query.Get("q"), 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleHitsExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="hydra-hits-redacted.csv"`)
	if err := s.store.ExportHitsCSV(r.Context(), ownerID(currentUser(r.Context())), w); err != nil {
		return
	}
}

func (s *Server) handleAddons(w http.ResponseWriter, r *http.Request) {
	items := addons.NewRegistry().List()
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"addons": items, "validation": "analyse locale rédigée; aucun secret n'est utilisé contre un service tiers"})
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.NotificationConfigs(r.Context(), currentUser(r.Context()).ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, items)
}

type notificationRequest struct {
	Addon   string            `json:"addon"`
	Channel string            `json:"channel"`
	Target  string            `json:"target"`
	Secrets map[string]string `json:"secrets"`
	Enabled bool              `json:"enabled"`
}

func (s *Server) notificationFromRequest(r *http.Request, request notificationRequest) (store.Notification, error) {
	secretJSON := store.MarshalJSON(request.Secrets)
	encrypted, err := s.store.Encrypt(secretJSON)
	if err != nil {
		return store.Notification{}, err
	}
	addon := strings.TrimSpace(request.Addon)
	if addon == "" {
		addon = "*"
	}
	return store.Notification{UserID: currentUser(r.Context()).ID, Addon: addon, Channel: request.Channel, Target: strings.TrimSpace(request.Target), SecretJSON: "enc:" + encrypted, Enabled: request.Enabled}, nil
}

func (s *Server) handleSaveNotification(w http.ResponseWriter, r *http.Request) {
	var request notificationRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	config, err := s.notificationFromRequest(r, request)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	saved, err := s.store.SaveNotification(r.Context(), config)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	var request notificationRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	config, err := s.notificationFromRequest(r, request)
	if err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	if err := s.notifier.Test(r.Context(), config); err != nil {
		writeError(w, http.StatusBadGateway, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "notification envoyée"})
}

func (s *Server) handleDeleteNotification(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	if err := s.store.DeleteNotification(r.Context(), id, currentUser(r.Context()).ID); err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
