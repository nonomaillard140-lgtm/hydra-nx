package license_test

import (
	"context"
	"strings"
	"testing"

	"hydra/internal/auth"
	"hydra/internal/license"
	"hydra/internal/store"
)

func TestIssueVerifyAndTamper(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("license-passphrase")
	user, err := st.CreateUser(ctx, "user@example.com", "licensed", hash, "user")
	if err != nil {
		t.Fatal(err)
	}
	manager := license.NewManager(st)
	item, err := manager.Issue(ctx, user.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := manager.Verify(item.Key)
	if err != nil || payload.UserID != user.ID || payload.PlanID != 1 {
		t.Fatalf("licence valide refusée: %+v %v", payload, err)
	}
	parts := strings.Split(item.Key, ".")
	if len(parts) != 3 {
		t.Fatalf("format de licence inattendu: %q", item.Key)
	}
	body := parts[1]
	middle := len(body) / 2
	flip := byte('A')
	if body[middle] == 'A' {
		flip = 'B'
	}
	parts[1] = body[:middle] + string(flip) + body[middle+1:]
	tampered := strings.Join(parts, ".")
	if _, err := manager.Verify(tampered); err == nil {
		t.Fatal("licence modifiée acceptée")
	}
	if _, err := manager.PublicKey(); err != nil {
		t.Fatal(err)
	}
}
