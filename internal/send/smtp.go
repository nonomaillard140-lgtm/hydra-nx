package send

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"hydra/internal/store"
)

type SMTPConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	From           string `json:"from"`
	ControlAddress string `json:"control_address"`
}

type Manager struct {
	store    *store.Store
	resolver MXResolver
}

func NewManager(st *store.Store) *Manager {
	return &Manager{store: st, resolver: NetMXResolver{}}
}

func (m *Manager) SetResolver(resolver MXResolver) { m.resolver = resolver }

func (m *Manager) Configure(ctx context.Context, config SMTPConfig) error {
	if err := validateConfig(config); err != nil {
		return err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return err
	}
	encrypted, err := m.store.Encrypt(string(encoded))
	if err != nil {
		return err
	}
	return m.store.SetSetting(ctx, "smtp_control_config", "enc:"+encrypted)
}

func (m *Manager) Config(ctx context.Context) (SMTPConfig, error) {
	value, err := m.store.Setting(ctx, "smtp_control_config")
	if err != nil {
		return SMTPConfig{}, errors.New("transport SMTP de contrôle non configuré")
	}
	if !strings.HasPrefix(value, "enc:") {
		return SMTPConfig{}, errors.New("configuration SMTP non chiffrée refusée")
	}
	plain, err := m.store.Decrypt(strings.TrimPrefix(value, "enc:"))
	if err != nil {
		return SMTPConfig{}, err
	}
	var config SMTPConfig
	if err := json.Unmarshal([]byte(plain), &config); err != nil {
		return SMTPConfig{}, err
	}
	return config, validateConfig(config)
}

func validateConfig(config SMTPConfig) error {
	if config.Host != "" && strings.ContainsAny(config.Host, "\r\n /") {
		return errors.New("hôte SMTP invalide")
	}
	if _, err := mail.ParseAddress(config.From); err != nil {
		return errors.New("expéditeur SMTP invalide")
	}
	if _, err := mail.ParseAddress(config.ControlAddress); err != nil {
		return errors.New("adresse de contrôle invalide")
	}
	if config.Port < 0 || config.Port > 65535 {
		return errors.New("port SMTP invalide")
	}
	return nil
}

// SendControl n'envoie qu'au destinataire de contrôle explicitement configuré.
func (m *Manager) SendControl(ctx context.Context, userID int64, subject, body string) error {
	config, err := m.Config(ctx)
	if err != nil {
		return err
	}
	if len(body) > 100000 || len(subject) > 200 {
		return errors.New("message de contrôle trop volumineux")
	}
	host, port, err := ResolveHost(ctx, m.resolver, config.Username, config.Host)
	if err != nil {
		return &SMTPError{Code: "hote_injoignable", Field: "host", Kind: "configuration", Message: err.Error(), Cause: err}
	}
	if config.Port != 0 {
		port = config.Port
	}
	attempt := config
	attempt.Host, attempt.Port = host, port
	record := store.Send{UserID: userID, Transport: "smtp", From: attempt.From, To: attempt.ControlAddress, Subject: subject, SMTPHost: host, SMTPPort: strconv.Itoa(port), SMTPUser: attempt.Username}
	if err := sendSMTP(ctx, attempt, subject, body); err != nil {
		classified := ClassifySMTPError(err)
		record.Status, record.Error = "failed", classified.Code+": "+classified.Message
		_ = m.store.RecordSend(ctx, record)
		return classified
	}
	record.Status = "sent"
	return m.store.RecordSend(ctx, record)
}

func sendSMTP(ctx context.Context, config SMTPConfig, subject, body string) error {
	if strings.ContainsAny(subject, "\r\n") || strings.ContainsAny(config.From, "\r\n") {
		return errors.New("en-tête de message invalide")
	}
	ports := []int{config.Port}
	if config.Port == 0 {
		ports = []int{587, 465, 25}
	}
	var errorsSeen []string
	for _, port := range ports {
		dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := sendOnPort(dialCtx, config, port, subject, body)
		cancel()
		if err == nil {
			return nil
		}
		errorsSeen = append(errorsSeen, strconv.Itoa(port)+": "+err.Error())
	}
	return fmt.Errorf("envoi SMTP impossible (%s)", strings.Join(errorsSeen, "; "))
}

func sendOnPort(ctx context.Context, config SMTPConfig, port int, subject, body string) error {
	address := net.JoinHostPort(config.Host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 12 * time.Second}
	var client *smtp.Client
	if port == 465 {
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12})
		if err != nil {
			return err
		}
		client, err = smtp.NewClient(conn, config.Host)
		if err != nil {
			conn.Close()
			return err
		}
	} else {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return err
		}
		client, err = smtp.NewClient(conn, config.Host)
		if err != nil {
			conn.Close()
			return err
		}
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: config.Host, MinVersion: tls.VersionTLS12}); err != nil {
				client.Close()
				return err
			}
		} else if config.Username != "" {
			client.Close()
			return errors.New("AUTH sans TLS refusé")
		}
	}
	defer client.Close()
	if config.Username != "" {
		if advertised, _ := client.Extension("AUTH"); advertised {
			if err := client.Auth(smtp.PlainAuth("", config.Username, config.Password, config.Host)); err != nil {
				return fmt.Errorf("authentification SMTP refusée: %w", err)
			}
		}
	}
	if err := client.Mail(config.From); err != nil {
		return err
	}
	if err := client.Rcpt(config.ControlAddress); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	message := "From: " + config.From + "\r\nTo: " + config.ControlAddress + "\r\nSubject: " + subject +
		"\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMessage-ID: <" + strconv.FormatInt(time.Now().UnixNano(), 10) + "@hydra.local>" +
		"\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + strings.ReplaceAll(body, "\r\n", "\n")
	if _, err := writer.Write([]byte(message)); err != nil {
		writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
