package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("élément introuvable")

type Store struct {
	db      *sql.DB
	dataDir string
	key     []byte
}

func Open(ctx context.Context, dataDir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "public", "lists"), 0o750); err != nil {
		return nil, fmt.Errorf("créer le répertoire de données: %w", err)
	}
	key, err := loadOrCreateKey(filepath.Join(dataDir, "master.key"))
	if err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", filepath.Join(dataDir, "hydra.db"))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	s := &Store{db: db, dataDir: dataDir, key: key}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ouvrir SQLite: %w", err)
	}
	return s, nil
}

func loadOrCreateKey(path string) ([]byte, error) {
	if key, err := os.ReadFile(path); err == nil {
		if len(key) != 32 {
			return nil, fmt.Errorf("clé maître invalide dans %s", path)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("créer la clé maître: %w", err)
	}
	return key, nil
}

func (s *Store) Close() error    { return s.db.Close() }
func (s *Store) DB() *sql.DB     { return s.db }
func (s *Store) DataDir() string { return s.dataDir }

func (s *Store) derive(purpose string) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write([]byte(purpose))
	return h.Sum(nil)
}

func (s *Store) Fingerprint(value string) string {
	h := hmac.New(sha256.New, s.derive("hit-fingerprint"))
	h.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (s *Store) Sign(value string) string {
	h := hmac.New(sha256.New, s.derive("session-cookie"))
	h.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func (s *Store) VerifySignature(value, signature string) bool {
	return hmac.Equal([]byte(s.Sign(value)), []byte(signature))
}

func (s *Store) Encrypt(plain string) (string, error) {
	block, err := aes.NewCipher(s.derive("secret-at-rest"))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *Store) Decrypt(encoded string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.derive("secret-at-rest"))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("secret chiffré tronqué")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *Store) Audit(ctx context.Context, actorID int64, action, target string, meta string) error {
	if meta == "" {
		meta = "{}"
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO audit_log(actor_id, action, target, meta_json) VALUES(NULLIF(?,0),?,?,?)", actorID, action, target, meta)
	return err
}

func (s *Store) Cleanup(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < ?", now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM sends WHERE sent_at < ?", now.AddDate(0, 0, -90)); err != nil {
		return err
	}
	return tx.Commit()
}
