package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"hydra/internal/store"
)

type Service struct {
	store *store.Store
}

type BootstrapCredentials struct {
	Username string
	Email    string
	Password string
}

func NewService(st *store.Store) *Service { return &Service{store: st} }

func (s *Service) EnsureAdmin(ctx context.Context) (*BootstrapCredentials, error) {
	count, err := s.store.CountUsers(ctx)
	if err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, nil
	}
	password, err := RandomString(24)
	if err != nil {
		return nil, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	if _, err := s.store.CreateUser(ctx, "admin@localhost", "admin", hash, "admin"); err != nil {
		return nil, err
	}
	if err := s.store.Audit(ctx, 0, "admin.bootstrap", "admin", "{}"); err != nil {
		return nil, err
	}
	return &BootstrapCredentials{Username: "admin", Email: "admin@localhost", Password: password}, nil
}

func (s *Service) Authenticate(ctx context.Context, identity, password, code string) (store.User, error) {
	u, err := s.store.UserByIdentity(ctx, identity)
	if err != nil {
		return store.User{}, errors.New("identifiants invalides")
	}
	if u.Banned || !VerifyPassword(u.PassHash, password) {
		return store.User{}, errors.New("identifiants invalides")
	}
	if u.TOTPSecret != "" {
		code = strings.TrimSpace(code)
		if code == "" {
			return store.User{}, errors.New("code TOTP ou code de récupération requis")
		}
		if VerifyTOTP(u.TOTPSecret, code, time.Now()) {
			return u, nil
		}
		updated, ok := ConsumeRecoveryCode(u.RecoveryJSON, code)
		if !ok {
			return store.User{}, errors.New("code de second facteur invalide")
		}
		if err := s.store.UpdateRecoveryJSON(ctx, u.ID, updated); err != nil {
			return store.User{}, err
		}
	}
	return u, nil
}

func (s *Service) ChangePassword(ctx context.Context, userID int64, current, next string) error {
	u, err := s.store.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !VerifyPassword(u.PassHash, current) {
		return errors.New("mot de passe actuel invalide")
	}
	hash, err := HashPassword(next)
	if err != nil {
		return err
	}
	return s.store.UpdatePassword(ctx, userID, hash)
}

func (s *Service) ResetAdminPassword(ctx context.Context) (string, error) {
	u, err := s.store.UserByIdentity(ctx, "admin")
	if err != nil || u.Role != "admin" {
		return "", fmt.Errorf("compte admin introuvable")
	}
	password, err := RandomString(24)
	if err != nil {
		return "", err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	if err := s.store.UpdatePassword(ctx, u.ID, hash); err != nil {
		return "", err
	}
	return password, s.store.Audit(ctx, u.ID, "admin.password.reset", "admin", "{}")
}
