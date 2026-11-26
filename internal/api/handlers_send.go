package api

import (
	"net/http"
	"strconv"

	"hydra/internal/send"
)

func (s *Server) handleSendConfig(w http.ResponseWriter, r *http.Request) {
	if currentUser(r.Context()).Role != "admin" {
		writeError(w, http.StatusForbidden, "seul l'administrateur configure le transport global")
		return
	}
	var config send.SMTPConfig
	if !decodeJSON(w, r, &config) {
		return
	}
	if err := s.sender.Configure(r.Context(), config); err != nil {
		writeError(w, http.StatusBadRequest, cleanMessage(err))
		return
	}
	_ = s.store.Audit(r.Context(), currentUser(r.Context()).ID, "send.config", "smtp_control", "{}")
	writeJSON(w, http.StatusOK, map[string]string{"status": "transport de contrôle configuré", "control_address": config.ControlAddress})
}

func (s *Server) handleSendControl(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Subject == "" || request.Body == "" {
		writeError(w, http.StatusBadRequest, "sujet et corps requis")
		return
	}
	if err := s.sender.SendControl(r.Context(), currentUser(r.Context()).ID, request.Subject, request.Body); err != nil {
		writeError(w, http.StatusBadGateway, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "message de contrôle envoyé"})
}

func (s *Server) handleHitSend(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	var request send.SendRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	user := currentUser(r.Context())
	if err := s.sender.SendHit(r.Context(), user.ID, id, request); err != nil {
		writeError(w, http.StatusBadGateway, cleanMessage(err))
		return
	}
	_ = s.store.Audit(r.Context(), user.ID, "send.hit", strconv.FormatInt(id, 10), "{}")
	writeJSON(w, http.StatusOK, map[string]string{"status": "message envoyé"})
}

func (s *Server) handleSendHistory(w http.ResponseWriter, r *http.Request) {
	items, err := s.store.Sends(r.Context(), ownerID(currentUser(r.Context())))
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleLicense(w http.ResponseWriter, r *http.Request) {
	summary, err := s.licenses.Summary(r.Context(), currentUser(r.Context()).ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, summary)
}
