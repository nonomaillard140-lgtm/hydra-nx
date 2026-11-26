package scan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hydra/internal/auth"
	"hydra/internal/scan"
	"hydra/internal/store"
)

func runBlockedScan(t *testing.T, extended bool) []store.Hit {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.RequestURI, "%") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("APP_NAME=hydra\nDB_PASSWORD=Qm7Tz4Lp9Rv2Xk8Bw3Nc6Yd\n"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden by waf"))
	}))
	defer server.Close()
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if extended {
		if err := st.SetSetting(ctx, "variants_extended", "true"); err != nil {
			t.Fatal(err)
		}
	}
	hash, err := auth.HashPassword("variants-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, "variants@example.com", "variants", hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	list, err := st.CreateList(ctx, user.ID, "lab", "L7", []string{strings.TrimPrefix(server.URL, "http://")}, true)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.CreatePath(ctx, user.ID, "/.env", nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	crack, err := st.CreateCrack(ctx, user.ID, list.ID, path.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := scan.NewScanner(st, 3*time.Second, 2).RunCrack(ctx, crack.ID); err != nil {
		t.Fatal(err)
	}
	hits, err := st.Hits(ctx, user.ID, "", "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	return hits
}

func TestEncodedVariantsReachBlockedPath(t *testing.T) {
	hits := runBlockedScan(t, true)
	if len(hits) == 0 {
		t.Fatal("aucun hit via les variantes")
	}
	if !strings.Contains(hits[0].Path, "%") {
		t.Fatalf("le hit ne vient pas d'une forme encodee: %q", hits[0].Path)
	}
	if hits[0].Vuln != "env_exposure" {
		t.Fatalf("detection basee sur la reference attendue, obtenu %q", hits[0].Vuln)
	}
}

func TestLiteralOnlyMissesBlockedPath(t *testing.T) {
	if hits := runBlockedScan(t, false); len(hits) != 0 {
		t.Fatalf("le mode par defaut ne devrait rien trouver: %+v", hits)
	}
}
