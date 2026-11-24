package scan_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hydra/internal/auth"
	"hydra/internal/scan"
	"hydra/internal/store"
)

func TestAuthorizedScanStoresOnlyRedactedProof(t *testing.T) {
	const rawSecret = "super-private-value-123"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("DB_PASSWORD=" + rawSecret + "\nAPP_NAME=hydra\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
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
	hash, _ := auth.HashPassword("scanner-passphrase")
	user, err := st.CreateUser(ctx, "scanner@example.com", "scanner", hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	target := strings.TrimPrefix(server.URL, "http://")
	list, err := st.CreateList(ctx, user.ID, "lab", "L7", []string{target}, true)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.CreatePath(ctx, user.ID, "/.env", []string{"/.env"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	crack, err := st.CreateCrack(ctx, user.ID, list.ID, path.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	scanner := scan.NewScanner(st, 3*time.Second, 2)
	var notifications atomic.Int32
	scanner.OnHit = func(hit store.Hit) {
		if strings.Contains(hit.SecretRedacted, rawSecret) {
			t.Error("secret brut dans la notification")
		}
		notifications.Add(1)
	}
	if err := scanner.RunCrack(ctx, crack.ID); err != nil {
		t.Fatal(err)
	}
	hits, err := st.Hits(ctx, user.ID, "", "", "", 10)
	if err != nil || len(hits) != 1 {
		t.Fatalf("hits inattendus: %+v %v", hits, err)
	}
	if strings.Contains(hits[0].SecretRedacted, rawSecret) || !strings.Contains(hits[0].SecretRedacted, "<redacted>") {
		t.Fatalf("preuve non rédigée: %+v", hits[0])
	}
	if notifications.Load() != 1 {
		t.Fatalf("callback appelé %d fois", notifications.Load())
	}
	updated, err := st.CrackByID(ctx, crack.ID, user.ID)
	if err != nil || updated.Status != "completed" || !strings.Contains(updated.StatsJSON, `"hits":1`) {
		t.Fatalf("scan non terminé: %+v %v", updated, err)
	}
}
