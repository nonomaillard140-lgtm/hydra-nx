package send

import (
	"context"
	"errors"
	"net"
	"net/mail"
	"net/textproto"
	"sort"
	"strings"
	"time"
)

type MXResolver interface {
	Lookup(ctx context.Context, domain string) ([]string, error)
}

type NetMXResolver struct{}

func (NetMXResolver) Lookup(ctx context.Context, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	records, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(records, func(i, j int) bool {
		if records[i].Pref != records[j].Pref {
			return records[i].Pref < records[j].Pref
		}
		return records[i].Host < records[j].Host
	})
	hosts := make([]string, 0, len(records))
	for _, record := range records {
		hosts = append(hosts, record.Host)
	}
	return hosts, nil
}

type providerHost struct {
	domains  []string
	host     string
	port     int
	template bool
}

var providerHosts = []providerHost{
	{domains: []string{"ovh.net", "ovh.com", "ovh.fr"}, host: "ssl0.ovh.net", port: 465},
	{domains: []string{"gmail.com", "googlemail.com"}, host: "smtp.gmail.com", port: 587},
	{domains: []string{"outlook.com", "hotmail.com", "hotmail.fr", "live.com", "live.fr"}, host: "smtp-mail.outlook.com", port: 587},
	{domains: []string{"infomaniak.com", "infomaniak.ch"}, host: "mail.infomaniak.com", port: 587},
	{domains: []string{"ionos.fr", "ionos.com", "1and1.fr", "1and1.com"}, host: "smtp.ionos.fr", port: 587},
	{domains: []string{"hostinger.com", "hostinger.fr"}, host: "smtp.hostinger.com", port: 465},
	{domains: []string{"gandi.net"}, host: "mail.gandi.net", port: 587},
	{domains: []string{"alwaysdata.net", "alwaysdata.com"}, host: "smtp.alwaysdata.com", port: 587},
	{domains: []string{"o2switch.net", "o2switch.fr"}, template: true, port: 465},
	{domains: []string{"planethoster.net", "planethoster.com", "planethoster.fr"}, template: true, port: 465},
}

func providerFor(domain string) (providerHost, bool) {
	domain = strings.ToLower(domain)
	for _, entry := range providerHosts {
		for _, candidate := range entry.domains {
			if domain == candidate || strings.HasSuffix(domain, "."+candidate) {
				return entry, true
			}
		}
	}
	return providerHost{}, false
}

func domainOf(identity string) (string, error) {
	address, err := mail.ParseAddress(strings.TrimSpace(identity))
	if err != nil {
		return "", errors.New("identifiant SMTP invalide")
	}
	_, domain, found := strings.Cut(address.Address, "@")
	if !found || domain == "" {
		return "", errors.New("identifiant SMTP sans domaine")
	}
	return strings.ToLower(domain), nil
}

// ResolveHost deduit l'hote et le port: hote fourni, puis MX en 25, puis table de secours, puis convention en 587.
func ResolveHost(ctx context.Context, resolver MXResolver, username, host string) (string, int, error) {
	host = strings.TrimSpace(host)
	if strings.Contains(host, "@") {
		if _, domain, found := strings.Cut(host, "@"); found {
			host = strings.TrimSuffix(strings.TrimSpace(domain), ".")
		}
	}
	if host != "" {
		if strings.ContainsAny(host, "\r\n /") {
			return "", 0, errors.New("hote SMTP invalide")
		}
		return host, 587, nil
	}
	domain, err := domainOf(username)
	if err != nil {
		return "", 0, err
	}
	if resolver != nil {
		if hosts, lookupErr := resolver.Lookup(ctx, domain); lookupErr == nil {
			for _, candidate := range hosts {
				candidate = strings.TrimSuffix(strings.TrimSpace(candidate), ".")
				if candidate == "" || strings.ContainsAny(candidate, "\r\n /") {
					continue
				}
				return candidate, 25, nil
			}
		}
	}
	if entry, ok := providerFor(domain); ok {
		if entry.template {
			return "mail." + domain, entry.port, nil
		}
		return entry.host, entry.port, nil
	}
	return "smtp." + domain, 587, nil
}

type SMTPError struct {
	Code    string
	Field   string
	Kind    string
	Message string
	Cause   error
}

func (e *SMTPError) Error() string { return e.Message }
func (e *SMTPError) Unwrap() error { return e.Cause }

// ClassifySMTPError traduit une erreur d'envoi en code exploitable, sans exposer le mot de passe.
func ClassifySMTPError(err error) *SMTPError {
	if err == nil {
		return nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &SMTPError{Code: "timeout", Field: "host", Kind: "network", Message: "delai depasse vers le serveur SMTP", Cause: err}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &SMTPError{Code: "timeout", Field: "host", Kind: "network", Message: "delai depasse vers le serveur SMTP", Cause: err}
	}
	var protocolErr *textproto.Error
	if errors.As(err, &protocolErr) {
		if protocolErr.Code == 550 && strings.Contains(protocolErr.Msg, "5.1.1") {
			return &SMTPError{Code: "destinataire_refuse", Field: "to", Kind: "configuration", Message: "destinataire inconnu du serveur", Cause: err}
		}
		switch protocolErr.Code {
		case 530, 534, 535, 538:
			return &SMTPError{Code: "auth_refusee", Field: "username", Kind: "configuration", Message: "authentification refusee par le serveur", Cause: err}
		case 550, 551, 553, 554:
			return &SMTPError{Code: "relais_refuse", Field: "from", Kind: "configuration", Message: "expediteur ou relais refuse", Cause: err}
		}
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "5.1.1") {
		return &SMTPError{Code: "destinataire_refuse", Field: "to", Kind: "configuration", Message: "destinataire inconnu du serveur", Cause: err}
	}
	if strings.Contains(lower, "authentification smtp refusee") {
		return &SMTPError{Code: "auth_refusee", Field: "username", Kind: "configuration", Message: "authentification refusee par le serveur", Cause: err}
	}
	if strings.Contains(lower, "starttls") || strings.Contains(lower, "certificate") || strings.Contains(lower, "tls") {
		return &SMTPError{Code: "tls_refuse", Field: "port", Kind: "configuration", Message: "chiffrement refuse par le serveur", Cause: err}
	}
	return &SMTPError{Code: "hote_injoignable", Field: "host", Kind: "network", Message: "serveur SMTP injoignable", Cause: err}
}
