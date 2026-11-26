package send

import (
	"context"
	"errors"
	"net/mail"
	"strconv"
	"strings"

	"hydra/internal/store"
)

type SendRequest struct {
	To       string `json:"to"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	From     string `json:"from"`
	Subject  string `json:"subject"`
	Body     string `json:"body"`
}

// DeriveTransport deduit l'hote et l'utilisateur de la valeur trouvee, la surcharge manuelle gagne.
func DeriveTransport(ctx context.Context, resolver MXResolver, secret string, request SendRequest) (SMTPConfig, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return SMTPConfig{}, errors.New("valeur du secret absente: relancer le scan")
	}
	to := strings.TrimSpace(request.To)
	if _, err := mail.ParseAddress(to); err != nil {
		return SMTPConfig{}, errors.New("destinataire invalide")
	}
	subject := strings.TrimSpace(request.Subject)
	if subject == "" || len(subject) > 200 {
		return SMTPConfig{}, errors.New("sujet requis, 200 caracteres maximum")
	}
	if strings.TrimSpace(request.Body) == "" || len(request.Body) > 100000 {
		return SMTPConfig{}, errors.New("corps requis, 100000 octets maximum")
	}
	username := strings.TrimSpace(request.Username)
	if username == "" {
		if address, err := mail.ParseAddress(secret); err == nil {
			username = address.Address
		}
	}
	if username == "" {
		return SMTPConfig{}, errors.New("utilisateur SMTP requis")
	}
	host, port, err := ResolveHost(ctx, resolver, username, request.Host)
	if err != nil {
		return SMTPConfig{}, err
	}
	from := strings.TrimSpace(request.From)
	if from == "" {
		from = username
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return SMTPConfig{}, errors.New("expediteur invalide")
	}
	if request.Port != 0 {
		port = request.Port
	}
	if port < 1 || port > 65535 {
		return SMTPConfig{}, errors.New("port SMTP invalide")
	}
	return SMTPConfig{Host: host, Port: port, Username: username, Password: secret, From: from, ControlAddress: to}, nil
}

// SendHit envoie depuis un hit SMTP utilisable, la valeur etant dechiffree a la volee.
func (m *Manager) SendHit(ctx context.Context, userID, hitID int64, request SendRequest) error {
	hit, err := m.store.HitByID(ctx, hitID, userID)
	if err != nil {
		return err
	}
	if !hit.SMTPUsable || (hit.Service != "smtp" && hit.Service != "o365") {
		return errors.New("ce hit n'est pas un identifiant SMTP utilisable")
	}
	if hit.SecretEnc == "" {
		return errors.New("valeur en clair absente: relancer le scan")
	}
	secret, err := m.store.Decrypt(hit.SecretEnc)
	if err != nil {
		return err
	}
	config, err := DeriveTransport(ctx, m.resolver, secret, request)
	if err != nil {
		return err
	}
	record := store.Send{UserID: userID, HitID: hit.ID, Transport: "smtp", From: config.From, To: config.ControlAddress, Subject: strings.TrimSpace(request.Subject), SMTPHost: config.Host, SMTPPort: strconv.Itoa(config.Port), SMTPUser: config.Username}
	if err := sendSMTP(ctx, config, record.Subject, request.Body); err != nil {
		classified := ClassifySMTPError(err)
		record.Status, record.Error = "failed", classified.Code+": "+classified.Message
		_ = m.store.RecordSend(ctx, record)
		return classified
	}
	record.Status = "sent"
	return m.store.RecordSend(ctx, record)
}
