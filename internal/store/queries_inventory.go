package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (s *Store) CreateList(ctx context.Context, userID int64, name, kind string, items []string, authorized bool) (List, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 || (kind != "L7" && kind != "L4") {
		return List{}, errors.New("nom ou type de liste invalide")
	}
	if !authorized {
		return List{}, errors.New("la propriété ou l'autorisation écrite des cibles doit être confirmée")
	}
	if len(items) == 0 || len(items) > 100000 {
		return List{}, errors.New("la liste doit contenir entre 1 et 100000 éléments")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return List{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT INTO lists(user_id,name,kind,size,authorized) VALUES(?,?,?,?,1)", userID, name, kind, len(items))
	if err != nil {
		return List{}, fmt.Errorf("créer la liste: %w", err)
	}
	id, _ := result.LastInsertId()
	for _, value := range items {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO list_items(list_id,value) VALUES(?,?)", id, value); err != nil {
			return List{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE lists SET size=(SELECT COUNT(1) FROM list_items WHERE list_id=?) WHERE id=?", id, id); err != nil {
		return List{}, err
	}
	if err := tx.Commit(); err != nil {
		return List{}, err
	}
	return s.ListByID(ctx, id, userID)
}

func scanList(scanner interface{ Scan(...any) error }) (List, error) {
	var l List
	var authorized int
	err := scanner.Scan(&l.ID, &l.UserID, &l.Name, &l.Kind, &l.Size, &authorized, &l.CreatedAt)
	l.Authorized = authorized != 0
	return l, err
}

func (s *Store) ListByID(ctx context.Context, id, userID int64) (List, error) {
	l, err := scanList(s.db.QueryRowContext(ctx, `SELECT id,user_id,name,kind,size,authorized,created_at FROM lists WHERE id=? AND (?=0 OR user_id=?)`, id, userID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return List{}, ErrNotFound
	}
	if err != nil {
		return List{}, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT value FROM list_items WHERE list_id=? ORDER BY id", id)
	if err != nil {
		return List{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return List{}, err
		}
		l.Items = append(l.Items, value)
	}
	return l, rows.Err()
}

func (s *Store) Lists(ctx context.Context, userID int64) ([]List, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,user_id,name,kind,size,authorized,created_at FROM lists WHERE ?=0 OR user_id=? ORDER BY id DESC`, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	lists := make([]List, 0)
	for rows.Next() {
		l, err := scanList(rows)
		if err != nil {
			return nil, err
		}
		lists = append(lists, l)
	}
	return lists, rows.Err()
}

func (s *Store) DeleteList(ctx context.Context, id, userID int64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM lists WHERE id=? AND (?=0 OR user_id=?)", id, userID, userID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreatePath(ctx context.Context, userID int64, raw string, variants []string, tags string) (Path, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 || !strings.HasPrefix(raw, "/") || strings.ContainsAny(raw, "\x00\r\n") {
		return Path{}, errors.New("chemin absolu valide requis")
	}
	encoded, err := json.Marshal(variants)
	if err != nil {
		return Path{}, err
	}
	result, err := s.db.ExecContext(ctx, "INSERT INTO paths(user_id,raw,encoded_variants_json,tags) VALUES(?,?,?,?)", userID, raw, string(encoded), strings.TrimSpace(tags))
	if err != nil {
		return Path{}, fmt.Errorf("créer le chemin: %w", err)
	}
	id, _ := result.LastInsertId()
	return Path{ID: id, UserID: userID, Raw: raw, Variants: variants, Tags: tags}, nil
}

func (s *Store) EnsurePath(ctx context.Context, userID int64, raw string, variants []string, tags string) (Path, error) {
	p, err := s.PathByRaw(ctx, userID, raw)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return Path{}, err
	}
	return s.CreatePath(ctx, userID, raw, variants, tags)
}

func (s *Store) PathByRaw(ctx context.Context, userID int64, raw string) (Path, error) {
	return scanPathRow(s.db.QueryRowContext(ctx, "SELECT id,user_id,raw,encoded_variants_json,tags FROM paths WHERE user_id=? AND raw=?", userID, raw))
}

func scanPathRow(scanner interface{ Scan(...any) error }) (Path, error) {
	var p Path
	var variants string
	err := scanner.Scan(&p.ID, &p.UserID, &p.Raw, &variants, &p.Tags)
	if errors.Is(err, sql.ErrNoRows) {
		return Path{}, ErrNotFound
	}
	if err != nil {
		return Path{}, err
	}
	if err := json.Unmarshal([]byte(variants), &p.Variants); err != nil {
		return Path{}, fmt.Errorf("variantes de chemin invalides: %w", err)
	}
	return p, nil
}

func (s *Store) PathByID(ctx context.Context, id, userID int64) (Path, error) {
	return scanPathRow(s.db.QueryRowContext(ctx, "SELECT id,user_id,raw,encoded_variants_json,tags FROM paths WHERE id=? AND (?=0 OR user_id=?)", id, userID, userID))
}

func (s *Store) Paths(ctx context.Context, userID int64) ([]Path, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,user_id,raw,encoded_variants_json,tags FROM paths WHERE ?=0 OR user_id=? ORDER BY id DESC", userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	paths := make([]Path, 0)
	for rows.Next() {
		p, err := scanPathRow(rows)
		if err != nil {
			return nil, err
		}
		paths = append(paths, p)
	}
	return paths, rows.Err()
}

func (s *Store) DeletePath(ctx context.Context, id, userID int64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM paths WHERE id=? AND (?=0 OR user_id=?)", id, userID, userID)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) CreateCrack(ctx context.Context, userID, listID, pathID int64, confirmed bool) (Crack, error) {
	if !confirmed {
		return Crack{}, errors.New("confirmation d'autorisation requise")
	}
	list, err := s.ListByID(ctx, listID, userID)
	if err != nil {
		return Crack{}, err
	}
	if !list.Authorized {
		return Crack{}, errors.New("la liste n'a pas d'autorisation enregistrée")
	}
	if _, err := s.PathByID(ctx, pathID, userID); err != nil {
		return Crack{}, err
	}
	result, err := s.db.ExecContext(ctx, "INSERT INTO cracks(user_id,list_id,path_id,status,authorization_confirmed) VALUES(?,?,?,'queued',1)", userID, listID, pathID)
	if err != nil {
		return Crack{}, err
	}
	id, _ := result.LastInsertId()
	return s.CrackByID(ctx, id, userID)
}

func scanCrack(scanner interface{ Scan(...any) error }) (Crack, error) {
	var c Crack
	var confirmed int
	var started, finished sql.NullTime
	err := scanner.Scan(&c.ID, &c.UserID, &c.ListID, &c.PathID, &c.Status, &started, &finished, &c.StatsJSON, &confirmed, &c.CreatedAt, &c.ListName, &c.PathRaw)
	if started.Valid {
		t := started.Time
		c.StartedAt = &t
	}
	if finished.Valid {
		t := finished.Time
		c.FinishedAt = &t
	}
	c.Confirmed = confirmed != 0
	return c, err
}

const crackSelect = `SELECT c.id,c.user_id,c.list_id,c.path_id,c.status,c.started_at,c.finished_at,c.stats_json,c.authorization_confirmed,c.created_at,l.name,p.raw
FROM cracks c JOIN lists l ON l.id=c.list_id JOIN paths p ON p.id=c.path_id`

func (s *Store) CrackByID(ctx context.Context, id, userID int64) (Crack, error) {
	c, err := scanCrack(s.db.QueryRowContext(ctx, crackSelect+" WHERE c.id=? AND (?=0 OR c.user_id=?)", id, userID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return Crack{}, ErrNotFound
	}
	return c, err
}

func (s *Store) Cracks(ctx context.Context, userID int64, limit int) ([]Crack, error) {
	rows, err := s.db.QueryContext(ctx, crackSelect+" WHERE ?=0 OR c.user_id=? ORDER BY c.id DESC LIMIT ?", userID, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cracks := make([]Crack, 0)
	for rows.Next() {
		c, err := scanCrack(rows)
		if err != nil {
			return nil, err
		}
		cracks = append(cracks, c)
	}
	return cracks, rows.Err()
}

func (s *Store) SetCrackStatus(ctx context.Context, id int64, status, stats string) error {
	if stats == "" {
		stats = "{}"
	}
	switch status {
	case "running":
		_, err := s.db.ExecContext(ctx, "UPDATE cracks SET status=?,started_at=COALESCE(started_at,?),stats_json=? WHERE id=?", status, time.Now().UTC(), stats, id)
		return err
	case "completed", "failed", "cancelled":
		_, err := s.db.ExecContext(ctx, "UPDATE cracks SET status=?,finished_at=?,stats_json=? WHERE id=?", status, time.Now().UTC(), stats, id)
		return err
	default:
		_, err := s.db.ExecContext(ctx, "UPDATE cracks SET status=?,stats_json=? WHERE id=?", status, stats, id)
		return err
	}
}

func (s *Store) QueuedCracks(ctx context.Context) ([]Crack, error) {
	rows, err := s.db.QueryContext(ctx, crackSelect+" WHERE c.status IN ('queued','running') ORDER BY c.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cracks []Crack
	for rows.Next() {
		c, err := scanCrack(rows)
		if err != nil {
			return nil, err
		}
		cracks = append(cracks, c)
	}
	return cracks, rows.Err()
}
