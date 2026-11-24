package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"hydra/internal/send"
	"hydra/internal/store"
)

type Dispatcher struct {
	store  *store.Store
	client *http.Client
}

func NewDispatcher(st *store.Store) *Dispatcher {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		resolver := dialer.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("destination réseau privée ou injoignable refusée")
	}}
	return &Dispatcher{store: st, client: &http.Client{Timeout: 10 * time.Second, Transport: transport}}
}

func (d *Dispatcher) Dispatch(ctx context.Context, userID int64, addon, message string) {
	configs, err := d.store.NotificationConfigs(ctx, userID)
	if err != nil {
		return
	}
	for _, config := range configs {
		if !config.Enabled || (config.Addon != "*" && config.Addon != addon) {
			continue
		}
		if config.Channel == "smtp" {
			smtpCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
			_ = send.NewManager(d.store).SendControl(smtpCtx, userID, "Notification HYDRA", message)
			cancel()
			continue
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = d.send(ctx, config, message)
		cancel()
	}
}

func (d *Dispatcher) Test(ctx context.Context, config store.Notification) error {
	if config.Channel == "smtp" {
		return send.NewManager(d.store).SendControl(ctx, config.UserID, "Contrôle notification HYDRA", "HYDRA: notification de contrôle")
	}
	return d.send(ctx, config, "HYDRA: notification de contrôle")
}

func (d *Dispatcher) send(ctx context.Context, config store.Notification, message string) error {
	if len(message) > 3500 {
		message = message[:3500]
	}
	secretJSON := config.SecretJSON
	if strings.HasPrefix(secretJSON, "enc:") {
		plain, err := d.store.Decrypt(strings.TrimPrefix(secretJSON, "enc:"))
		if err != nil {
			return err
		}
		secretJSON = plain
	}
	var secrets map[string]string
	if secretJSON != "" && secretJSON != "{}" {
		if err := json.Unmarshal([]byte(secretJSON), &secrets); err != nil {
			return err
		}
	}
	var endpoint string
	var payload any
	switch config.Channel {
	case "telegram":
		token := secrets["bot_token"]
		if token == "" || strings.ContainsAny(token, "/\r\n") {
			return errors.New("jeton de bot Telegram absent ou invalide")
		}
		endpoint = "https://api.telegram.org/bot" + token + "/sendMessage"
		payload = map[string]any{"chat_id": config.Target, "text": message, "disable_web_page_preview": true}
	case "discord":
		endpoint = config.Target
		payload = map[string]string{"content": message}
	case "webhook":
		endpoint = config.Target
		payload = map[string]any{"text": message, "source": "hydra", "secret": secrets["secret"]}
	default:
		return errors.New("canal non pris en charge")
	}
	if err := validateHTTPSURL(endpoint); err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("notification refusée: HTTP %d", resp.StatusCode)
	}
	return nil
}

func validateHTTPSURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return errors.New("URL HTTPS valide requise")
	}
	if addr, err := netip.ParseAddr(parsed.Hostname()); err == nil {
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() {
			return errors.New("adresse de notification privée refusée")
		}
	}
	return nil
}

func IsTemporaryNetworkError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.Temporary()
	}
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED)
}
