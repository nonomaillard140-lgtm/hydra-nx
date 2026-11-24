package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

func scanUser(scanner interface{ Scan(...any) error }) (User, error) {
	var u User
	var banned int
	err := scanner.Scan(&u.ID, &u.Email, &u.Username, &u.PassHash, &u.Role, &u.TOTPSecret, &u.RecoveryJSON, &u.CreatedAt, &banned, &u.TelegramID)
	u.Banned = banned != 0
	return u, err
}

const userColumns = "id,email,username,pass_hash,role,totp_secret,recovery_hashes_json,created_at,banned,telegram_id"

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM users").Scan(&count)
	return count, err
}

func (s *Store) CreateUser(ctx context.Context, email, username, passHash, role string) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	username = strings.TrimSpace(username)
	if !strings.Contains(email, "@") || len(username) < 3 || len(username) > 64 {
		return User{}, errors.New("email ou nom d'utilisateur invalide")
	}
	if role != "admin" {
		role = "user"
	}
	result, err := s.db.ExecContext(ctx, "INSERT INTO users(email,username,pass_hash,role) VALUES(?,?,?,?)", email, username, passHash, role)
	if err != nil {
		return User{}, fmt.Errorf("créer l'utilisateur: %w", err)
	}
	id, _ := result.LastInsertId()
	return s.UserByID(ctx, id)
}

func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) UserByIdentity(ctx context.Context, identity string) (User, error) {
	identity = strings.TrimSpace(identity)
	u, err := scanUser(s.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE email=? COLLATE NOCASE OR username=? COLLATE NOCASE", identity, identity))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) UpdatePassword(ctx context.Context, userID int64, passHash string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET pass_hash=? WHERE id=?", passHash, userID)
	if err == nil {
		_, err = s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", userID)
	}
	return err
}

func (s *Store) EnableTOTP(ctx context.Context, userID int64, secret, recoveryJSON string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET totp_secret=?, recovery_hashes_json=? WHERE id=?", secret, recoveryJSON, userID)
	return err
}

func (s *Store) DisableTOTP(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET totp_secret='',recovery_hashes_json='[]' WHERE id=?", userID)
	return err
}

func (s *Store) UpdateRecoveryJSON(ctx context.Context, userID int64, recoveryJSON string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET recovery_hashes_json=? WHERE id=?", recoveryJSON, userID)
	return err
}

func (s *Store) CreateSession(ctx context.Context, userID int64, ua, ip string, ttl time.Duration) (string, Session, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", Session{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	idRaw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idRaw); err != nil {
		return "", Session{}, err
	}
	id := base64.RawURLEncoding.EncodeToString(idRaw)
	sum := sha256.Sum256([]byte(token))
	hash := base64.RawURLEncoding.EncodeToString(sum[:])
	expires := time.Now().Add(ttl).UTC()
	_, err := s.db.ExecContext(ctx, "INSERT INTO sessions(id,user_id,token_hash,ua,ip,expires_at) VALUES(?,?,?,?,?,?)", id, userID, hash, ua, ip, expires)
	return token, Session{ID: id, UserID: userID, TokenHash: hash, UA: ua, IP: ip, ExpiresAt: expires}, err
}

func (s *Store) SessionByToken(ctx context.Context, token string) (Session, User, error) {
	sum := sha256.Sum256([]byte(token))
	hash := base64.RawURLEncoding.EncodeToString(sum[:])
	var session Session
	err := s.db.QueryRowContext(ctx, "SELECT id,user_id,token_hash,ua,ip,expires_at FROM sessions WHERE token_hash=? AND expires_at>?", hash, time.Now().UTC()).Scan(
		&session.ID, &session.UserID, &session.TokenHash, &session.UA, &session.IP, &session.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, User{}, ErrNotFound
	}
	if err != nil {
		return Session{}, User{}, err
	}
	user, err := s.UserByID(ctx, session.UserID)
	if err != nil || user.Banned {
		return Session{}, User{}, ErrNotFound
	}
	return session, user, nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	sum := sha256.Sum256([]byte(token))
	hash := base64.RawURLEncoding.EncodeToString(sum[:])
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", hash)
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", userID)
	return err
}

func (s *Store) SetUserBanned(ctx context.Context, userID int64, banned bool) error {
	_, err := s.db.ExecContext(ctx, "UPDATE users SET banned=? WHERE id=?", banned, userID)
	if err == nil && banned {
		return s.DeleteUserSessions(ctx, userID)
	}
	return err
}

func (s *Store) licenseValidSince(ctx context.Context) time.Time {
	grace, _ := strconv.Atoi(s.StringSetting(ctx, "grace_hours", "0"))
	if grace < 0 || grace > 720 {
		grace = 0
	}
	return time.Now().UTC().Add(-time.Duration(grace) * time.Hour)
}

func (s *Store) ActiveLicense(ctx context.Context, userID int64) (License, Plan, error) {
	var l License
	var p Plan
	var revoked int
	err := s.db.QueryRowContext(ctx, `SELECT l.id,l.key,l.plan_id,l.user_id,l.max_devices,l.expires_at,l.signature,l.revoked,
p.id,p.name,p.price_cents,p.duration_hours,p.max_devices,p.daily_credits,p.features_json
FROM licenses l JOIN plans p ON p.id=l.plan_id
WHERE l.user_id=? AND l.revoked=0 AND l.expires_at>? ORDER BY l.expires_at DESC LIMIT 1`, userID, s.licenseValidSince(ctx)).Scan(
		&l.ID, &l.Key, &l.PlanID, &l.UserID, &l.MaxDevices, &l.ExpiresAt, &l.Signature, &revoked,
		&p.ID, &p.Name, &p.PriceCents, &p.DurationHours, &p.MaxDevices, &p.DailyCredits, &p.FeaturesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return License{}, Plan{}, ErrNotFound
	}
	l.Revoked = revoked != 0
	return l, p, err
}

func (s *Store) CreditStatus(ctx context.Context, userID int64) (remaining int, limit int, err error) {
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return 0, 0, err
	}
	if u.Role == "admin" {
		return -1, -1, nil
	}
	_, plan, err := s.ActiveLicense(ctx, userID)
	if err != nil {
		return 0, 0, nil
	}
	dayStart := time.Now().UTC().Truncate(24 * time.Hour)
	var used int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(-SUM(delta),0) FROM credits_ledger WHERE user_id=? AND delta<0 AND created_at>=?", userID, dayStart).Scan(&used); err != nil {
		return 0, 0, err
	}
	remaining = plan.DailyCredits - used
	if remaining < 0 {
		remaining = 0
	}
	return remaining, plan.DailyCredits, nil
}

func (s *Store) ConsumeCredits(ctx context.Context, userID int64, amount int, reason string) error {
	if amount <= 0 {
		return nil
	}
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if u.Role == "admin" {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var role string
	if err := tx.QueryRowContext(ctx, "SELECT role FROM users WHERE id=?", userID).Scan(&role); err != nil {
		return err
	}
	if role == "admin" {
		return tx.Commit()
	}
	var daily int
	err = tx.QueryRowContext(ctx, `SELECT p.daily_credits FROM licenses l JOIN plans p ON p.id=l.plan_id
WHERE l.user_id=? AND l.revoked=0 AND l.expires_at>? ORDER BY l.expires_at DESC LIMIT 1`, userID, s.licenseValidSince(ctx)).Scan(&daily)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("aucune licence active: crédits indisponibles")
	}
	if err != nil {
		return err
	}
	dayStart := time.Now().UTC().Truncate(24 * time.Hour)
	var used int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(-SUM(delta),0) FROM credits_ledger WHERE user_id=? AND delta<0 AND created_at>=?", userID, dayStart).Scan(&used); err != nil {
		return err
	}
	if used+amount > daily {
		return fmt.Errorf("crédits insuffisants: %d requis, %d restants", amount, daily-used)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO credits_ledger(user_id,delta,reason) VALUES(?,?,?)", userID, -amount, reason); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GrantCredits(ctx context.Context, userID int64, amount int, reason string) error {
	if amount == 0 {
		return errors.New("crédit nul interdit")
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO credits_ledger(user_id,delta,reason) VALUES(?,?,?)", userID, amount, reason)
	return err
}

func (s *Store) CreditHistory(ctx context.Context, userID int64, limit int) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT delta,reason,created_at FROM credits_ledger WHERE user_id=? ORDER BY id DESC LIMIT ?", userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var delta int
		var reason string
		var created time.Time
		if err := rows.Scan(&delta, &reason, &created); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"delta": delta, "reason": reason, "created_at": created})
	}
	return out, rows.Err()
}

func (s *Store) SetDevice(ctx context.Context, userID int64, fingerprint string, maxDevices int) error {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" || len(fingerprint) > 256 {
		return errors.New("empreinte d'appareil invalide")
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM devices WHERE user_id=? AND fingerprint=?", userID, fingerprint).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		_, err := s.db.ExecContext(ctx, "UPDATE devices SET last_seen=CURRENT_TIMESTAMP WHERE user_id=? AND fingerprint=?", userID, fingerprint)
		return err
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM devices WHERE user_id=?", userID).Scan(&count); err != nil {
		return err
	}
	if maxDevices > 0 && count >= maxDevices {
		return errors.New("nombre maximal d'appareils atteint")
	}
	_, err := s.db.ExecContext(ctx, "INSERT INTO devices(user_id,fingerprint) VALUES(?,?)", userID, fingerprint)
	return err
}

func (s *Store) UpdateUserTelegram(ctx context.Context, userID int64, telegramID string) error {
	if len(telegramID) > 64 {
		return errors.New("identifiant Telegram trop long")
	}
	_, err := s.db.ExecContext(ctx, "UPDATE users SET telegram_id=? WHERE id=?", userID, telegramID)
	return err
}

func MarshalJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}
