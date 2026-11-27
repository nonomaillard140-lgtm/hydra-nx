package store_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hydra/internal/auth"
	"hydra/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func adminUser(t *testing.T, st *store.Store) store.User {
	t.Helper()
	hash, err := auth.HashPassword("admin-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(context.Background(), "admin@example.com", "admin", hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func TestMigrationCryptoSessionsAndCredits(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migration non idempotente: %v", err)
	}
	encrypted, err := st.Encrypt("valeur sensible")
	if err != nil {
		t.Fatal(err)
	}
	plain, err := st.Decrypt(encrypted)
	if err != nil || plain != "valeur sensible" {
		t.Fatalf("chiffrement: %q %v", plain, err)
	}
	if _, err := st.Decrypt("truncated"); err == nil {
		t.Fatal("secret tronqué accepté")
	}
	user := adminUser(t, st)
	token, _, err := st.CreateSession(ctx, user.ID, "test-agent", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, logged, err := st.SessionByToken(ctx, token)
	if err != nil || logged.ID != user.ID {
		t.Fatalf("session: %+v %v", logged, err)
	}
	remaining, limit, err := st.CreditStatus(ctx, user.ID)
	if err != nil || remaining != -1 || limit != -1 {
		t.Fatalf("bypass admin absent: %d %d %v", remaining, limit, err)
	}
	if err := st.ConsumeCredits(ctx, user.ID, 1000000, "test"); err != nil {
		t.Fatalf("admin limité: %v", err)
	}
}

func TestInventoryDedupBackupRestore(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	user := adminUser(t, st)
	if _, err := st.CreateList(ctx, user.ID, "refused", "L7", []string{"a.example.com"}, false); err == nil {
		t.Fatal("liste sans autorisation acceptée")
	}
	list, err := st.CreateList(ctx, user.ID, "production", "L7", []string{"a.example.com"}, true)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.CreatePath(ctx, user.ID, "/.env", []string{"/.env"}, "config")
	if err != nil {
		t.Fatal(err)
	}
	crack, err := st.CreateCrack(ctx, user.ID, list.ID, path.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	hit, err := st.UpsertHit(ctx, store.Hit{CrackID: crack.ID, UserID: user.ID, Host: "a.example.com", Path: "/.env", Vuln: "env_exposure", Service: "database", SecretRedacted: "DB_PASSWORD=<redacted>", SecretHash: st.Fingerprint("hash"), Status: "detected_unvalidated"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := st.UpsertHit(ctx, store.Hit{CrackID: crack.ID, UserID: user.ID, Host: "a.example.com", Path: "/.env", Vuln: "env_exposure", Service: "database", SecretRedacted: "DB_PASSWORD=<redacted>", SecretHash: st.Fingerprint("hash"), Status: "detected_unvalidated"})
	if err != nil || again.ID != hit.ID {
		t.Fatalf("doublon créé: %d %d %v", hit.ID, again.ID, err)
	}
	token, _, err := st.CreateSession(ctx, user.ID, "backup-agent", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := st.Backup(ctx, archive); err != nil {
		t.Fatal(err)
	}
	restoredDir := filepath.Join(t.TempDir(), "restored")
	if err := store.RestoreArchive(archive, restoredDir); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(ctx, restoredDir)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	_, logged, err := restored.SessionByToken(ctx, token)
	if err != nil || logged.ID != user.ID {
		t.Fatalf("session non restaurée: %v", err)
	}
	if _, err := os.Stat(filepath.Join(restoredDir, "master.key")); err != nil {
		t.Fatal("clé maître non restaurée")
	}
}

func TestDeleteUsedListPurgesScans(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	user := adminUser(t, st)
	list, err := st.CreateList(ctx, user.ID, "production", "L7", []string{"a.example.com"}, true)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.CreatePath(ctx, user.ID, "/.env", []string{"/.env"}, "")
	if err != nil {
		t.Fatal(err)
	}
	crack, err := st.CreateCrack(ctx, user.ID, list.ID, path.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetCrackStatus(ctx, crack.ID, "completed", "{}"); err != nil {
		t.Fatal(err)
	}
	hit, err := st.UpsertHit(ctx, store.Hit{CrackID: crack.ID, UserID: user.ID, Host: "a.example.com", Path: "/.env", Vuln: "env_exposure", Service: "database", SecretRedacted: "DB_PASSWORD=<redacted>", SecretHash: st.Fingerprint("liste"), Status: "detected_unvalidated"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordSend(ctx, store.Send{HitID: hit.ID, UserID: user.ID, Transport: "smtp", From: "a@example.com", To: "b@example.com", Subject: "test", Status: "sent"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteList(ctx, list.ID, user.ID); err != nil {
		t.Fatalf("suppression d'une liste utilisée: %v", err)
	}
	if _, err := st.ListByID(ctx, list.ID, user.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("liste encore présente: %v", err)
	}
	if cracks, err := st.Cracks(ctx, user.ID, 10); err != nil || len(cracks) != 0 {
		t.Fatalf("scans résiduels: %d %v", len(cracks), err)
	}
	if hits, err := st.Hits(ctx, user.ID, "", "", "", 10); err != nil || len(hits) != 0 {
		t.Fatalf("hits résiduels: %d %v", len(hits), err)
	}
	sends, err := st.Sends(ctx, user.ID)
	if err != nil || len(sends) != 1 || sends[0].HitID != 0 {
		t.Fatalf("historique d'envoi altéré: %+v %v", sends, err)
	}
}

func TestDeleteUsedPathPurgesScans(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	user := adminUser(t, st)
	list, err := st.CreateList(ctx, user.ID, "production", "L7", []string{"a.example.com"}, true)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.CreatePath(ctx, user.ID, "/.git/HEAD", []string{"/.git/HEAD"}, "")
	if err != nil {
		t.Fatal(err)
	}
	crack, err := st.CreateCrack(ctx, user.ID, list.ID, path.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertHit(ctx, store.Hit{CrackID: crack.ID, UserID: user.ID, Host: "a.example.com", Path: "/.git/HEAD", Vuln: "git_exposure", Service: "vcs", SecretRedacted: "ref: refs/heads/main", SecretHash: st.Fingerprint("chemin"), Status: "detected_unvalidated"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePath(ctx, path.ID, user.ID); err != nil {
		t.Fatalf("suppression d'un chemin utilisé: %v", err)
	}
	if _, err := st.PathByID(ctx, path.ID, user.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("chemin encore présent: %v", err)
	}
	if cracks, err := st.Cracks(ctx, user.ID, 10); err != nil || len(cracks) != 0 {
		t.Fatalf("scans résiduels: %d %v", len(cracks), err)
	}
}

func TestClearScansKeepsActive(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	user := adminUser(t, st)
	list, err := st.CreateList(ctx, user.ID, "production", "L7", []string{"a.example.com"}, true)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.CreatePath(ctx, user.ID, "/.env", []string{"/.env"}, "")
	if err != nil {
		t.Fatal(err)
	}
	done, err := st.CreateCrack(ctx, user.ID, list.ID, path.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetCrackStatus(ctx, done.ID, "completed", "{}"); err != nil {
		t.Fatal(err)
	}
	live, err := st.CreateCrack(ctx, user.ID, list.ID, path.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetCrackStatus(ctx, live.ID, "running", "{}"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertHit(ctx, store.Hit{CrackID: done.ID, UserID: user.ID, Host: "a.example.com", Path: "/.env", Vuln: "env_exposure", Service: "database", SecretRedacted: "DB_PASSWORD=<redacted>", SecretHash: st.Fingerprint("purge"), Status: "detected_unvalidated"}); err != nil {
		t.Fatal(err)
	}
	count, err := st.ClearScans(ctx, user.ID)
	if err != nil || count != 1 {
		t.Fatalf("purge: %d %v", count, err)
	}
	cracks, err := st.Cracks(ctx, user.ID, 10)
	if err != nil || len(cracks) != 1 || cracks[0].ID != live.ID || cracks[0].Status != "running" {
		t.Fatalf("scan actif non conservé: %+v %v", cracks, err)
	}
	if hits, err := st.Hits(ctx, user.ID, "", "", "", 10); err != nil || len(hits) != 0 {
		t.Fatalf("hits résiduels: %d %v", len(hits), err)
	}
}
