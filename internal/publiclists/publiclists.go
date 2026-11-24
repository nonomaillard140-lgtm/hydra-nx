package publiclists

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"hydra/internal/discover"
	"hydra/internal/store"
)

type Service struct {
	store *store.Store
	dir   string
}

func NewService(st *store.Store) *Service {
	return &Service{store: st, dir: filepath.Join(st.DataDir(), "public", "lists")}
}

func (s *Service) Publish(ctx context.Context, source, name, kind, format string, publisher int64) (store.PublicList, error) {
	file, err := os.Open(source)
	if err != nil {
		return store.PublicList{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return store.PublicList{}, err
	}
	if info.Size() <= 0 || info.Size() > 100*1024*1024 {
		return store.PublicList{}, errors.New("fichier vide ou supérieur à 100 Mio")
	}
	if format == "" {
		format = strings.TrimPrefix(strings.ToLower(filepath.Ext(source)), ".")
	}
	if format != "txt" && format != "csv" {
		return store.PublicList{}, errors.New("format txt ou csv requis")
	}
	lines, err := normalizedLines(file, kind, format)
	if err != nil {
		return store.PublicList{}, err
	}
	content := []byte(strings.Join(lines, "\n") + "\n")
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	slug := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(name), "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "liste"
	}
	if len(slug) > 48 {
		slug = slug[:48]
	}
	filename := fmt.Sprintf("%s-%s-%s.%s", time.Now().UTC().Format("20060102T150405Z"), slug, hash[:12], format)
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return store.PublicList{}, err
	}
	destination := filepath.Join(s.dir, filename)
	if err := os.WriteFile(destination, content, 0o640); err != nil {
		return store.PublicList{}, err
	}
	item, err := s.store.CreatePublicList(ctx, store.PublicList{Name: name, Kind: kind, Filename: filename, SizeBytes: int64(len(content)), Lines: len(lines), SHA256: hash, Format: format, PublishedBy: publisher})
	if err != nil {
		os.Remove(destination)
		return store.PublicList{}, err
	}
	return item, nil
}

func normalizedLines(reader io.Reader, kind, format string) ([]string, error) {
	seen := make(map[string]struct{})
	var lines []string
	add := func(raw string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			return nil
		}
		var value string
		var err error
		if kind == "PATHS" {
			value = raw
			if !strings.HasPrefix(value, "/") || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
				return errors.New("chemin public invalide")
			}
		} else {
			value, err = discover.NormalizeTarget(raw, kind)
			if err != nil {
				return err
			}
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			lines = append(lines, value)
		}
		return nil
	}
	if format == "csv" {
		csvReader := csv.NewReader(reader)
		csvReader.FieldsPerRecord = -1
		for {
			record, err := csvReader.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, err
			}
			if len(record) > 0 {
				if err := add(record[0]); err != nil {
					return nil, err
				}
			}
		}
	} else {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			if err := add(scanner.Text()); err != nil {
				return nil, err
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	if len(lines) == 0 {
		return nil, errors.New("aucune ligne valide à publier")
	}
	sort.Strings(lines)
	return lines, nil
}

func (s *Service) Open(item store.PublicList) (io.ReadSeekCloser, error) {
	if filepath.Base(item.Filename) != item.Filename || item.Filename == "" {
		return nil, errors.New("nom de fichier invalide")
	}
	file, err := os.Open(filepath.Join(s.dir, item.Filename))
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.Size() != item.SizeBytes {
		file.Close()
		return nil, errors.New("taille du fichier publié modifiée")
	}
	return file, nil
}

func (s *Service) Verify(item store.PublicList) error {
	file, err := s.Open(item)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != item.SHA256 {
		return errors.New("SHA-256 du fichier publié incorrect")
	}
	return nil
}

func (s *Service) Manifest(ctx context.Context) ([]byte, error) {
	items, err := s.store.PublicLists(ctx, false, "", "", "date")
	if err != nil {
		return nil, err
	}
	manifest := struct {
		Version   int                `json:"version"`
		Generated time.Time          `json:"generated_at"`
		Lists     []store.PublicList `json:"lists"`
	}{Version: 1, Generated: time.Now().UTC(), Lists: items}
	return json.MarshalIndent(manifest, "", "  ")
}

func (s *Service) ImportBytes(ctx context.Context, content []byte, name, kind, format string, publisher int64) (store.PublicList, error) {
	if len(content) == 0 || len(content) > 100*1024*1024 {
		return store.PublicList{}, errors.New("contenu de publication invalide")
	}
	temp, err := os.CreateTemp(s.dir, ".import-*")
	if err != nil {
		return store.PublicList{}, err
	}
	path := temp.Name()
	defer os.Remove(path)
	if _, err := io.Copy(temp, bytes.NewReader(content)); err != nil {
		temp.Close()
		return store.PublicList{}, err
	}
	if err := temp.Close(); err != nil {
		return store.PublicList{}, err
	}
	return s.Publish(ctx, path, name, kind, format, publisher)
}
