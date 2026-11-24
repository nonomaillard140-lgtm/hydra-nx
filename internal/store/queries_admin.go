package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) Users(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+userColumns+" FROM users ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) Plans(ctx context.Context) ([]Plan, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,price_cents,duration_hours,max_devices,daily_credits,features_json FROM plans ORDER BY price_cents")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := make([]Plan, 0)
	for rows.Next() {
		var p Plan
		if err := rows.Scan(&p.ID, &p.Name, &p.PriceCents, &p.DurationHours, &p.MaxDevices, &p.DailyCredits, &p.FeaturesJSON); err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, rows.Err()
}

func (s *Store) PlanByID(ctx context.Context, id int64) (Plan, error) {
	var p Plan
	err := s.db.QueryRowContext(ctx, "SELECT id,name,price_cents,duration_hours,max_devices,daily_credits,features_json FROM plans WHERE id=?", id).Scan(
		&p.ID, &p.Name, &p.PriceCents, &p.DurationHours, &p.MaxDevices, &p.DailyCredits, &p.FeaturesJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	return p, err
}

func (s *Store) UpdatePlan(ctx context.Context, p Plan) error {
	if p.PriceCents < 0 || p.DurationHours <= 0 || p.MaxDevices <= 0 || p.DailyCredits < 0 {
		return errors.New("paramètres de plan invalides")
	}
	_, err := s.db.ExecContext(ctx, "UPDATE plans SET price_cents=?,duration_hours=?,max_devices=?,daily_credits=?,features_json=? WHERE id=?", p.PriceCents, p.DurationHours, p.MaxDevices, p.DailyCredits, p.FeaturesJSON, p.ID)
	return err
}

func (s *Store) CreateLicense(ctx context.Context, license License) (License, error) {
	if license.ExpiresAt.IsZero() || license.Key == "" || license.Signature == "" {
		return License{}, errors.New("licence incomplète")
	}
	result, err := s.db.ExecContext(ctx, "INSERT INTO licenses(key,plan_id,user_id,max_devices,expires_at,signature) VALUES(?,?,?,?,?,?)", license.Key, license.PlanID, license.UserID, license.MaxDevices, license.ExpiresAt, license.Signature)
	if err != nil {
		return License{}, err
	}
	license.ID, _ = result.LastInsertId()
	return license, nil
}

func (s *Store) Licenses(ctx context.Context, userID int64) ([]License, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT l.id,l.key,l.plan_id,l.user_id,l.max_devices,l.expires_at,l.signature,l.revoked,p.name
FROM licenses l JOIN plans p ON p.id=l.plan_id WHERE ?=0 OR l.user_id=? ORDER BY l.id DESC`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]License, 0)
	for rows.Next() {
		var l License
		var revoked int
		if err := rows.Scan(&l.ID, &l.Key, &l.PlanID, &l.UserID, &l.MaxDevices, &l.ExpiresAt, &l.Signature, &revoked, &l.PlanName); err != nil {
			return nil, err
		}
		l.Revoked = revoked != 0
		items = append(items, l)
	}
	return items, rows.Err()
}

func (s *Store) RevokeLicense(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, "UPDATE licenses SET revoked=1 WHERE id=?", id)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AuditLog(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.id,COALESCE(a.actor_id,0),COALESCE(u.username,'système'),a.action,a.target,a.meta_json,a.created_at
FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AuditEntry, 0)
	for rows.Next() {
		var entry AuditEntry
		if err := rows.Scan(&entry.ID, &entry.ActorID, &entry.ActorName, &entry.Action, &entry.Target, &entry.MetaJSON, &entry.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, entry)
	}
	return items, rows.Err()
}

func (s *Store) DeleteAllCracks(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE cracks SET status='cancelled',finished_at=? WHERE (?=0 OR user_id=?) AND status IN ('queued','running')", time.Now().UTC(), userID, userID)
	return err
}
