package license

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hydra/internal/store"
)

type Payload struct {
	UserID     int64  `json:"user_id"`
	PlanID     int64  `json:"plan_id"`
	MaxDevices int    `json:"max_devices"`
	ExpiresAt  int64  `json:"expires_at"`
	Nonce      string `json:"nonce"`
}

type Manager struct {
	store   *store.Store
	dataDir string
}

func NewManager(st *store.Store) *Manager { return &Manager{store: st, dataDir: st.DataDir()} }

type keyFile struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

func (m *Manager) Keygen() (ed25519.PublicKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(keyFile{Private: base64.RawStdEncoding.EncodeToString(private), Public: base64.RawStdEncoding.EncodeToString(public)})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(m.keyPath(), encoded, 0o600); err != nil {
		return nil, err
	}
	return public, nil
}

func (m *Manager) keyPath() string { return filepath.Join(m.dataDir, "license_ed25519.json") }

func (m *Manager) keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	encoded, err := os.ReadFile(m.keyPath())
	if errors.Is(err, os.ErrNotExist) {
		public, err := m.Keygen()
		if err != nil {
			return nil, nil, err
		}
		return m.keysWithPublic(public)
	}
	if err != nil {
		return nil, nil, err
	}
	var keys keyFile
	if err := json.Unmarshal(encoded, &keys); err != nil {
		return nil, nil, err
	}
	private, err := base64.RawStdEncoding.DecodeString(keys.Private)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("clé privée Ed25519 invalide")
	}
	public, err := base64.RawStdEncoding.DecodeString(keys.Public)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, nil, errors.New("clé publique Ed25519 invalide")
	}
	return public, private, nil
}

func (m *Manager) keysWithPublic(public ed25519.PublicKey) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	_, private, err := m.keys()
	return public, private, err
}

func (m *Manager) Issue(ctx context.Context, userID, planID int64) (store.License, error) {
	plan, err := m.store.PlanByID(ctx, planID)
	if err != nil {
		return store.License{}, err
	}
	if _, err := m.store.UserByID(ctx, userID); err != nil {
		return store.License{}, err
	}
	_, private, err := m.keys()
	if err != nil {
		return store.License{}, err
	}
	nonceRaw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceRaw); err != nil {
		return store.License{}, err
	}
	payload := Payload{UserID: userID, PlanID: planID, MaxDevices: plan.MaxDevices, ExpiresAt: time.Now().UTC().Add(time.Duration(plan.DurationHours) * time.Hour).Unix(), Nonce: base64.RawURLEncoding.EncodeToString(nonceRaw)}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		return store.License{}, err
	}
	signature := ed25519.Sign(private, encodedPayload)
	key := "HYDRA1." + base64.RawURLEncoding.EncodeToString(encodedPayload) + "." + base64.RawURLEncoding.EncodeToString(signature)
	return m.store.CreateLicense(ctx, store.License{Key: key, PlanID: planID, UserID: userID, MaxDevices: payload.MaxDevices, ExpiresAt: time.Unix(payload.ExpiresAt, 0).UTC(), Signature: base64.RawURLEncoding.EncodeToString(signature)})
}

func (m *Manager) Verify(encoded string) (Payload, error) {
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 || parts[0] != "HYDRA1" {
		return Payload{}, errors.New("format de licence invalide")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Payload{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Payload{}, err
	}
	public, _, err := m.keys()
	if err != nil {
		return Payload{}, err
	}
	if !ed25519.Verify(public, payloadBytes, signature) {
		return Payload{}, errors.New("signature de licence invalide")
	}
	var payload Payload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return Payload{}, err
	}
	if time.Now().UTC().Unix() >= payload.ExpiresAt {
		return Payload{}, errors.New("licence expirée")
	}
	return payload, nil
}

func (m *Manager) PublicKey() (string, error) {
	public, _, err := m.keys()
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(public), nil
}

func (m *Manager) Summary(ctx context.Context, userID int64) (map[string]any, error) {
	remaining, limit, err := m.store.CreditStatus(ctx, userID)
	if err != nil {
		return nil, err
	}
	licenses, err := m.store.Licenses(ctx, userID)
	if err != nil {
		return nil, err
	}
	publicKey, err := m.PublicKey()
	if err != nil {
		return nil, err
	}
	return map[string]any{"licenses": licenses, "credits_remaining": remaining, "daily_limit": limit, "public_key": publicKey, "verification": "Ed25519 hors ligne"}, nil
}

func (m *Manager) String() string {
	return fmt.Sprintf("Ed25519 licenses in %s", m.keyPath())
}
