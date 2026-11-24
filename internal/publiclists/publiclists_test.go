package publiclists_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hydra/internal/auth"
	"hydra/internal/publiclists"
	"hydra/internal/store"
)

func TestPublishManifestChecksum(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("publisher-passphrase")
	publisher, err := st.CreateUser(ctx, "publisher@example.com", "publisher", hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(source, []byte("b.example.com\na.example.com\na.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := publiclists.NewService(st)
	item, err := service.Publish(ctx, source, "Actifs de test", "L7", "txt", publisher.ID)
	if err != nil {
		t.Fatal(err)
	}
	if item.Lines != 2 || item.SHA256 == "" {
		t.Fatalf("métadonnées incorrectes: %+v", item)
	}
	if err := service.Verify(item); err != nil {
		t.Fatal(err)
	}
	manifest, err := service.Manifest(ctx)
	if err != nil || !strings.Contains(string(manifest), item.SHA256) {
		t.Fatalf("manifest incomplet: %s", manifest)
	}
	if err := st.IncrementPublicListDownload(ctx, item.ID); err != nil {
		t.Fatal(err)
	}
	updated, err := st.PublicListByID(ctx, item.ID, false)
	if err != nil || updated.Downloads != 1 {
		t.Fatalf("compteur non incrémenté: %+v %v", updated, err)
	}
}
