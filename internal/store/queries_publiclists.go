package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

func (s *Store) CreatePublicList(ctx context.Context, item PublicList) (PublicList, error) {
	if item.Name == "" || item.Filename == "" || item.SHA256 == "" {
		return PublicList{}, errors.New("métadonnées de liste publique incomplètes")
	}
	if item.Kind != "L7" && item.Kind != "L4" && item.Kind != "PATHS" {
		return PublicList{}, errors.New("type de liste publique invalide")
	}
	if item.Format != "txt" && item.Format != "csv" {
		return PublicList{}, errors.New("format de liste publique invalide")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO public_lists(name,kind,filename,size_bytes,lines,sha256,format,published_by)
VALUES(?,?,?,?,?,?,?,NULLIF(?,0))`, item.Name, item.Kind, item.Filename, item.SizeBytes, item.Lines, item.SHA256, item.Format, item.PublishedBy)
	if err != nil {
		return PublicList{}, err
	}
	id, _ := result.LastInsertId()
	return s.PublicListByID(ctx, id, true)
}

func scanPublicList(scanner interface{ Scan(...any) error }) (PublicList, error) {
	var item PublicList
	var publishedBy sql.NullInt64
	var hidden int
	err := scanner.Scan(&item.ID, &item.Name, &item.Kind, &item.Filename, &item.SizeBytes, &item.Lines, &item.SHA256, &item.Format, &item.PublishedAt, &publishedBy, &item.Downloads, &hidden)
	item.PublishedBy = publishedBy.Int64
	item.Hidden = hidden != 0
	return item, err
}

const publicListColumns = "id,name,kind,filename,size_bytes,lines,sha256,format,published_at,published_by,downloads,hidden"

func (s *Store) PublicListByID(ctx context.Context, id int64, includeHidden bool) (PublicList, error) {
	item, err := scanPublicList(s.db.QueryRowContext(ctx, "SELECT "+publicListColumns+" FROM public_lists WHERE id=? AND (? OR hidden=0)", id, includeHidden))
	if errors.Is(err, sql.ErrNoRows) {
		return PublicList{}, ErrNotFound
	}
	return item, err
}

func (s *Store) PublicLists(ctx context.Context, includeHidden bool, kind, query, sort string) ([]PublicList, error) {
	order := "published_at DESC"
	if sort == "volume" {
		order = "lines DESC"
	} else if sort == "downloads" {
		order = "downloads DESC"
	} else if sort == "name" {
		order = "name COLLATE NOCASE ASC"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+publicListColumns+` FROM public_lists
WHERE (? OR hidden=0) AND (?='' OR kind=?) AND (?='' OR name LIKE '%'||?||'%') ORDER BY `+order,
		includeHidden, kind, kind, query, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PublicList, 0)
	for rows.Next() {
		item, err := scanPublicList(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) IncrementPublicListDownload(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE public_lists SET downloads=downloads+1 WHERE id=? AND hidden=0", id)
	return err
}

func (s *Store) HidePublicList(ctx context.Context, id int64, hidden bool) error {
	_, err := s.db.ExecContext(ctx, "UPDATE public_lists SET hidden=? WHERE id=?", hidden, id)
	return err
}

func (s *Store) FindPublicListByFilename(ctx context.Context, filename string) (PublicList, error) {
	item, err := scanPublicList(s.db.QueryRowContext(ctx, "SELECT "+publicListColumns+" FROM public_lists WHERE filename=?", strings.TrimSpace(filename)))
	if errors.Is(err, sql.ErrNoRows) {
		return PublicList{}, ErrNotFound
	}
	return item, err
}
