package store

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

func (s *Store) UpsertHit(ctx context.Context, hit Hit) (Hit, error) {
	if hit.SecretHash == "" || hit.Service == "" || hit.Host == "" || hit.Vuln == "" {
		return Hit{}, errors.New("empreinte, service, hôte et vulnérabilité requis")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Hit{}, err
	}
	defer tx.Rollback()
	var existingID int64
	err = tx.QueryRowContext(ctx, "SELECT id FROM hits WHERE secret_hash=? AND service=?", hit.SecretHash, hit.Service).Scan(&existingID)
	if err == nil {
		if _, err := tx.ExecContext(ctx, `UPDATE hits SET crack_id=?,user_id=?,host=?,path=?,vuln=?,secret_redacted=?,status=?,points=?,cash_score=?,smtp_usable=?,last_seen=? WHERE id=?`,
			hit.CrackID, hit.UserID, hit.Host, hit.Path, hit.Vuln, hit.SecretRedacted, hit.Status, hit.Points, hit.CashScore, hit.SMTPUsable, time.Now().UTC(), existingID); err != nil {
			return Hit{}, err
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		result, err := tx.ExecContext(ctx, `INSERT INTO hits(crack_id,user_id,host,path,vuln,service,secret_redacted,secret_hash,status,points,cash_score,smtp_usable)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, hit.CrackID, hit.UserID, hit.Host, hit.Path, hit.Vuln, hit.Service, hit.SecretRedacted, hit.SecretHash, hit.Status, hit.Points, hit.CashScore, hit.SMTPUsable)
		if err != nil {
			return Hit{}, err
		}
		existingID, _ = result.LastInsertId()
	} else {
		return Hit{}, err
	}
	if err := tx.Commit(); err != nil {
		return Hit{}, err
	}
	return s.HitByID(ctx, existingID, hit.UserID)
}

func scanHit(scanner interface{ Scan(...any) error }) (Hit, error) {
	var h Hit
	var smtp int
	err := scanner.Scan(&h.ID, &h.CrackID, &h.UserID, &h.Host, &h.Path, &h.Vuln, &h.Service, &h.SecretRedacted, &h.SecretHash, &h.Status, &h.Points, &h.CashScore, &smtp, &h.FirstSeen, &h.LastSeen)
	h.SMTPUsable = smtp != 0
	return h, err
}

const hitColumns = "id,crack_id,user_id,host,path,vuln,service,secret_redacted,secret_hash,status,points,cash_score,smtp_usable,first_seen,last_seen"

func (s *Store) HitByID(ctx context.Context, id, userID int64) (Hit, error) {
	h, err := scanHit(s.db.QueryRowContext(ctx, "SELECT "+hitColumns+" FROM hits WHERE id=? AND (?=0 OR user_id=?)", id, userID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return Hit{}, ErrNotFound
	}
	return h, err
}

func (s *Store) Hits(ctx context.Context, userID int64, service, status, query string, limit int) ([]Hit, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+hitColumns+` FROM hits
WHERE (?=0 OR user_id=?) AND (?='' OR service=?) AND (?='' OR status=?)
AND (?='' OR host LIKE '%'||?||'%' OR path LIKE '%'||?||'%' OR vuln LIKE '%'||?||'%')
ORDER BY cash_score DESC,last_seen DESC LIMIT ?`, userID, userID, service, service, status, status, query, query, query, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hits := make([]Hit, 0)
	for rows.Next() {
		h, err := scanHit(rows)
		if err != nil {
			return nil, err
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

func (s *Store) RecordHitCheck(ctx context.Context, hitID int64, addon, resultJSON string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO hit_checks(hit_id,addon,result_json) VALUES(?,?,?)", hitID, addon, resultJSON)
	return err
}

func (s *Store) ExportHitsCSV(ctx context.Context, userID int64, output io.Writer) error {
	hits, err := s.Hits(ctx, userID, "", "", "", 1000)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(output)
	if err := writer.Write([]string{"id", "hote", "chemin", "vulnerabilite", "service", "preuve_redactee", "statut", "points", "priorite", "derniere_observation"}); err != nil {
		return err
	}
	for _, h := range hits {
		if err := writer.Write([]string{strconv.FormatInt(h.ID, 10), h.Host, h.Path, h.Vuln, h.Service, h.SecretRedacted, h.Status, strconv.Itoa(h.Points), strconv.Itoa(h.CashScore), h.LastSeen.Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func (s *Store) Dashboard(ctx context.Context, userID int64) (map[string]int64, error) {
	result := make(map[string]int64)
	queries := map[string]string{
		"lists":  "SELECT COUNT(1) FROM lists WHERE ?=0 OR user_id=?",
		"scans":  "SELECT COUNT(1) FROM cracks WHERE ?=0 OR user_id=?",
		"hits":   "SELECT COUNT(1) FROM hits WHERE ?=0 OR user_id=?",
		"active": "SELECT COUNT(1) FROM cracks WHERE (?=0 OR user_id=?) AND status IN ('queued','running')",
	}
	for key, query := range queries {
		var value int64
		if err := s.db.QueryRowContext(ctx, query, userID, userID).Scan(&value); err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, nil
}

func (s *Store) NotificationConfigs(ctx context.Context, userID int64) ([]Notification, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,user_id,addon,channel,target,secret_json,enabled FROM notifications WHERE user_id=? ORDER BY id", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Notification, 0)
	for rows.Next() {
		var n Notification
		var enabled int
		if err := rows.Scan(&n.ID, &n.UserID, &n.Addon, &n.Channel, &n.Target, &n.SecretJSON, &enabled); err != nil {
			return nil, err
		}
		n.Enabled = enabled != 0
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) SaveNotification(ctx context.Context, n Notification) (Notification, error) {
	if n.UserID == 0 || n.Target == "" {
		return Notification{}, errors.New("utilisateur et destination requis")
	}
	switch n.Channel {
	case "telegram", "discord", "webhook", "smtp":
	default:
		return Notification{}, errors.New("canal de notification invalide")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO notifications(user_id,addon,channel,target,secret_json,enabled) VALUES(?,?,?,?,?,?)
ON CONFLICT(user_id,addon,channel,target) DO UPDATE SET secret_json=excluded.secret_json,enabled=excluded.enabled`, n.UserID, n.Addon, n.Channel, n.Target, n.SecretJSON, n.Enabled)
	if err != nil {
		return Notification{}, err
	}
	configs, err := s.NotificationConfigs(ctx, n.UserID)
	if err != nil {
		return Notification{}, err
	}
	for _, config := range configs {
		if config.Channel == n.Channel && config.Target == n.Target && config.Addon == n.Addon {
			return config, nil
		}
	}
	return Notification{}, ErrNotFound
}

func (s *Store) DeleteNotification(ctx context.Context, id, userID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM notifications WHERE id=? AND user_id=?", id, userID)
	return err
}

func (s *Store) RecordSend(ctx context.Context, send Send) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO sends(hit_id,user_id,transport,from_addr,to_addr,subject,status,error) VALUES(NULL,?,?,?,?,?,?,?)", send.UserID, send.Transport, send.From, send.To, send.Subject, send.Status, send.Error)
	return err
}

func (s *Store) Sends(ctx context.Context, userID int64) ([]Send, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,user_id,transport,from_addr,to_addr,subject,status,error,sent_at FROM sends WHERE ?=0 OR user_id=? ORDER BY id DESC LIMIT 200", userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Send, 0)
	for rows.Next() {
		var item Send
		if err := rows.Scan(&item.ID, &item.UserID, &item.Transport, &item.From, &item.To, &item.Subject, &item.Status, &item.Error, &item.SentAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return value, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	if len(key) > 100 || len(value) > 8192 || strings.ContainsAny(key, "\r\n") {
		return errors.New("réglage invalide")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`, key, value)
	return err
}

func (s *Store) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key,value FROM settings ORDER BY key")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		out[key] = value
	}
	return out, rows.Err()
}

func (s *Store) StringSetting(ctx context.Context, key, fallback string) string {
	value, err := s.Setting(ctx, key)
	if err != nil || strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func (s *Store) HitCountSince(ctx context.Context, since time.Time) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM hits WHERE last_seen>=?", since).Scan(&count)
	return count, err
}
