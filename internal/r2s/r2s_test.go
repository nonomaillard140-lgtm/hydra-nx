package r2s_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"hydra/internal/r2s"
)

func TestNextJSFingerprint(t *testing.T) {
	if !r2s.NextJS([]byte("<script src=\"/_next/static/chunks/main.js\"></script>")) {
		t.Fatal("marqueur Next.js non reconnu")
	}
	if r2s.NextJS([]byte("<html><body>bonjour</body></html>")) {
		t.Fatal("faux positif Next.js")
	}
}

func TestProbeVulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Next-Action") == "" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/x-component")
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "0:{\"a\":\"$@1\",\"f\":\"\",\"b\":\"yd-J8UfWl70zwtaAy83s7\"}\n1:E{\"digest\":\"2971658870\"}\n")
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	result, err := r2s.Probe(context.Background(), server.Client(), target)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Vulnerable || result.Digest != "2971658870" || result.Status != http.StatusInternalServerError {
		t.Fatalf("sonde non concluante: %+v", result)
	}
}

func TestProbePatched(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-component")
		io.WriteString(w, "0:{\"a\":\"$@1\"}\n")
	}))
	defer server.Close()
	target, _ := url.Parse(server.URL)
	result, err := r2s.Probe(context.Background(), server.Client(), target)
	if err != nil {
		t.Fatal(err)
	}
	if result.Vulnerable {
		t.Fatalf("hôte corrigé signalé vulnérable: %+v", result)
	}
}
