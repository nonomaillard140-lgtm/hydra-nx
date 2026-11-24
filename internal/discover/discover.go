package discover

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"
)

// NormalizeTarget n'accepte que des cibles explicitement fournies, jamais de wildcard.
func NormalizeTarget(raw, kind string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 253 || strings.ContainsAny(raw, "\x00\r\n\t *") {
		return "", errors.New("cible vide, trop longue ou wildcard interdite")
	}
	if kind == "L4" {
		addr, err := netip.ParseAddr(strings.Trim(raw, "[]"))
		if err != nil {
			return "", errors.New("adresse IP L4 invalide")
		}
		return addr.String(), nil
	}
	if kind != "L7" {
		return "", errors.New("type de cible invalide")
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return "", errors.New("URL de cible invalide")
		}
		raw = parsed.Hostname()
	}
	raw = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if addr, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return addr.String(), nil
	}
	if len(raw) > 253 || !strings.Contains(raw, ".") {
		return "", errors.New("nom de domaine pleinement qualifié requis")
	}
	labels := strings.Split(raw, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("label DNS invalide")
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", errors.New("nom DNS ASCII invalide; convertir d'abord en punycode")
			}
		}
	}
	return raw, nil
}

func MergeAndNormalize(kind string, groups ...[]string) ([]string, error) {
	seen := make(map[string]struct{})
	var invalid []string
	for _, group := range groups {
		for _, raw := range group {
			value, err := NormalizeTarget(raw, kind)
			if err != nil {
				if raw = strings.TrimSpace(raw); raw != "" {
					invalid = append(invalid, raw)
				}
				continue
			}
			seen[value] = struct{}{}
		}
	}
	if len(seen) == 0 {
		if len(invalid) > 0 {
			return nil, fmt.Errorf("aucune cible valide; %d entrées rejetées", len(invalid))
		}
		return nil, errors.New("aucune cible")
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func Shuffle(values []string, seed int64) []string {
	out := append([]string(nil), values...)
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

func FilterPTR(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		lower := strings.ToLower(value)
		if strings.HasSuffix(lower, ".in-addr.arpa") || strings.HasSuffix(lower, ".ip6.arpa") ||
			strings.Contains(lower, ".clients.") || strings.Contains(lower, ".dynamic.") || strings.Contains(lower, ".static.") {
			continue
		}
		out = append(out, value)
	}
	return out
}

func Resolve(ctx context.Context, resolver *net.Resolver, domain string) ([]string, error) {
	domain, err := NormalizeTarget(domain, "L7")
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return []string{domain}, nil
	}
	addresses, err := resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, address := range addresses {
		seen[address.String()] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for address := range seen {
		out = append(out, address)
	}
	sort.Strings(out)
	return out, nil
}

func Reachable(ctx context.Context, target string, timeout time.Duration) error {
	host, err := NormalizeTarget(target, "L7")
	if err != nil {
		if addr, addrErr := netip.ParseAddr(target); addrErr == nil {
			host = addr.String()
		} else {
			return err
		}
	}
	var lastErr error
	for _, port := range []string{"443", "80"} {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
		cancel()
		if err == nil {
			return conn.Close()
		}
		lastErr = err
	}
	return lastErr
}

func DanglingCNAME(ctx context.Context, resolver *net.Resolver, domain string) (string, bool, error) {
	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil || cname == "" || strings.TrimSuffix(cname, ".") == strings.TrimSuffix(domain, ".") {
		return "", false, err
	}
	cname = strings.TrimSuffix(cname, ".")
	_, err = resolver.LookupIP(ctx, "ip", cname)
	if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
		return cname, true, nil
	}
	return cname, false, err
}

func ScopeFingerprint(values []string) string {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	hash := sha256.New()
	for _, value := range sorted {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}
