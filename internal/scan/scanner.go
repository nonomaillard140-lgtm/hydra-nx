package scan

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"hydra/internal/addons"
	"hydra/internal/extract"
	"hydra/internal/fuzz"
	"hydra/internal/score"
	"hydra/internal/store"
)

type Scanner struct {
	store   *store.Store
	client  *http.Client
	limiter *HostLimiter
	addons  *addons.Registry
	OnHit   func(store.Hit)
}

type Stats struct {
	Targets   int `json:"targets"`
	Requests  int `json:"requests"`
	Divergent int `json:"divergent"`
	Hits      int `json:"hits"`
	Errors    int `json:"errors"`
}

func NewScanner(st *store.Store, timeout time.Duration, hostLimit int) *Scanner {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: timeout,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     60 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{Transport: transport, Timeout: timeout + 5*time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("trop de redirections")
		}
		if !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
			return errors.New("redirection hors de la cible autorisée refusée")
		}
		return nil
	}}
	return &Scanner{store: st, client: client, limiter: NewHostLimiter(hostLimit), addons: addons.NewRegistry()}
}

func (s *Scanner) RunCrack(ctx context.Context, crackID int64) error {
	crack, err := s.store.CrackByID(ctx, crackID, 0)
	if err != nil {
		return err
	}
	if crack.Status == "cancelled" {
		return nil
	}
	list, err := s.store.ListByID(ctx, crack.ListID, 0)
	if err != nil {
		return err
	}
	pathConfig, err := s.store.PathByID(ctx, crack.PathID, 0)
	if err != nil {
		return err
	}
	if !list.Authorized || !crack.Confirmed {
		return errors.New("périmètre sans autorisation confirmée")
	}
	stats := Stats{Targets: len(list.Items)}
	_ = s.store.SetCrackStatus(ctx, crack.ID, "running", store.MarshalJSON(stats))
	for _, target := range list.Items {
		if err := ctx.Err(); err != nil {
			_ = s.store.SetCrackStatus(ctx, crack.ID, "cancelled", store.MarshalJSON(stats))
			return err
		}
		s.scanTarget(ctx, crack, target, pathConfig, &stats)
		_ = s.store.SetCrackStatus(ctx, crack.ID, "running", store.MarshalJSON(stats))
	}
	return s.store.SetCrackStatus(context.WithoutCancel(ctx), crack.ID, "completed", store.MarshalJSON(stats))
}

func (s *Scanner) scanTarget(ctx context.Context, crack store.Crack, target string, pathConfig store.Path, stats *Stats) {
	base, baseline, err := s.baseline(ctx, target)
	if err != nil {
		stats.Errors++
		return
	}
	variants := pathConfig.Variants
	if len(variants) == 0 {
		variants = fuzz.VariantPaths(pathConfig.Raw)
		if s.store.StringSetting(ctx, "variants_extended", "false") == "true" {
			variants = fuzz.VariantsExtended(pathConfig.Raw)
		}
	}
	responses := make([]fuzz.Response, 0, len(variants))
	for _, variant := range variants {
		requestURL, err := joinTargetPath(base, variant)
		if err != nil {
			stats.Errors++
			continue
		}
		response, err := s.get(ctx, requestURL)
		stats.Requests++
		if err != nil {
			stats.Errors++
			continue
		}
		responses = append(responses, response)
		decision := fuzz.Compare(baseline, response)
		if !decision.Divergent {
			continue
		}
		stats.Divergent++
		exposure, ok := extract.Detect(pathConfig.Raw, response.Body)
		if !ok || exposure.Confidence < 55 {
			continue
		}
		if fuzz.RegularResponses(responses) && len(responses) >= 3 {
			continue
		}
		created, err := s.recordExposure(ctx, crack, target, variant, response, exposure)
		if err != nil {
			stats.Errors++
			continue
		}
		stats.Hits += created
	}
}

func joinTargetPath(base *url.URL, variant string) (string, error) {
	if !strings.HasPrefix(variant, "/") || strings.ContainsAny(variant, "\x00\r\n") {
		return "", errors.New("variante de chemin invalide")
	}
	raw, query, _ := strings.Cut(variant, "?")
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", err
	}
	copy := *base
	copy.Path = decoded
	copy.RawPath = raw
	copy.RawQuery = query
	return copy.String(), nil
}

func (s *Scanner) baseline(ctx context.Context, target string) (*url.URL, fuzz.Response, error) {
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		base := &url.URL{Scheme: scheme, Host: target}
		baselineURL, err := joinTargetPath(base, fmt.Sprintf("/.hydra-absent-%d", time.Now().UnixNano()))
		if err != nil {
			return nil, fuzz.Response{}, err
		}
		response, err := s.get(ctx, baselineURL)
		if err != nil {
			lastErr = err
			continue
		}
		if response.Status == 403 || response.Status == 404 {
			return base, response, nil
		}
		lastErr = fmt.Errorf("référence HTTP %d non concluante", response.Status)
	}
	return nil, fuzz.Response{}, lastErr
}

func (s *Scanner) get(ctx context.Context, requestURL string) (fuzz.Response, error) {
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return fuzz.Response{}, err
	}
	release, err := s.limiter.Acquire(ctx, parsed.Host)
	if err != nil {
		return fuzz.Response{}, err
	}
	defer release()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
		if err != nil {
			return fuzz.Response{}, err
		}
		req.Header.Set("User-Agent", "Hydra-Defensive-Scanner/1.0")
		req.Header.Set("Accept", "text/plain,application/json,text/html;q=0.8")
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			break
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
		resp.Body.Close()
		if readErr != nil {
			return fuzz.Response{}, readErr
		}
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			lastErr = fmt.Errorf("limitation HTTP %d", resp.StatusCode)
			delay := time.Duration(1<<attempt) * time.Second
			if retry := resp.Header.Get("Retry-After"); retry != "" {
				if seconds, err := strconv.Atoi(retry); err == nil && seconds >= 0 && seconds <= 30 {
					delay = time.Duration(seconds) * time.Second
				}
			}
			select {
			case <-ctx.Done():
				return fuzz.Response{}, ctx.Err()
			case <-time.After(delay):
				continue
			}
		}
		if resp.Header.Get("CF-RAY") != "" || resp.Header.Get("X-Sucuri-ID") != "" {
			select {
			case <-ctx.Done():
				return fuzz.Response{}, ctx.Err()
			case <-time.After(150 * time.Millisecond):
			}
		}
		return fuzz.Response{Status: resp.StatusCode, Body: body}, nil
	}
	return fuzz.Response{}, lastErr
}

func (s *Scanner) recordExposure(ctx context.Context, crack store.Crack, host, requestPath string, response fuzz.Response, exposure extract.Exposure) (int, error) {
	findings := exposure.Findings
	if len(findings) == 0 {
		sum := sha256.Sum256(response.Body)
		findings = []extract.Finding{{Service: "generic", Variable: "exposure", Redacted: exposure.Summary, ValueHash: base64.RawURLEncoding.EncodeToString(sum[:])}}
	}
	created := 0
	seenServices := make(map[string]struct{})
	for _, finding := range findings {
		service := finding.Service
		if service == "" {
			service = "generic"
		}
		if _, duplicate := seenServices[service+"\x00"+finding.ValueHash]; duplicate {
			continue
		}
		seenServices[service+"\x00"+finding.ValueHash] = struct{}{}
		rating := score.Score(exposure.Vuln, service, len(findings))
		result := s.addons.Validate(ctx, addons.Evidence{Service: service, Redacted: finding.Redacted, Hash: finding.ValueHash, Value: finding.Value})
		smtpUsable := result.Status == addons.StatusPlausible && (service == "smtp" || service == "o365")
		hit, err := s.store.UpsertHit(ctx, store.Hit{CrackID: crack.ID, UserID: crack.UserID, Host: host, Path: requestPath,
			Vuln: exposure.Vuln, Service: service, SecretRedacted: finding.Redacted, SecretHash: s.store.Fingerprint(finding.ValueHash),
			Status: string(result.Status), Points: rating.Points, CashScore: rating.Priority, SMTPUsable: smtpUsable})
		if err != nil {
			return created, err
		}
		encoded, _ := json.Marshal(result)
		if err := s.store.RecordHitCheck(ctx, hit.ID, service, string(encoded)); err != nil {
			return created, err
		}
		created++
		if s.OnHit != nil {
			s.OnHit(hit)
		}
	}
	return created, nil
}
