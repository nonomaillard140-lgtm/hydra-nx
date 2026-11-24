package store

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Store) Backup(ctx context.Context, destination string) error {
	if destination == "" {
		return errors.New("destination de sauvegarde requise")
	}
	snapshot := filepath.Join(s.dataDir, fmt.Sprintf(".snapshot-%d.db", time.Now().UnixNano()))
	defer os.Remove(snapshot)
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", snapshot); err != nil {
		return fmt.Errorf("instantané SQLite: %w", err)
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	gzipWriter := gzip.NewWriter(output)
	tarWriter := tar.NewWriter(gzipWriter)
	root := filepath.Clean(s.dataDir)
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return err
		}
		name := filepath.ToSlash(rel)
		base := info.Name()
		if strings.HasPrefix(base, ".snapshot-") || strings.HasSuffix(base, "-wal") || strings.HasSuffix(base, "-shm") || info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = name
		header.Uid, header.Gid = 0, 0
		if info.IsDir() {
			return tarWriter.WriteHeader(header)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		sourcePath := path
		if base == "hydra.db" {
			sourcePath = snapshot
			snapshotInfo, err := os.Stat(snapshot)
			if err != nil {
				return err
			}
			header.Size = snapshotInfo.Size()
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		file, err := os.Open(sourcePath)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tarWriter, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		tarWriter.Close()
		gzipWriter.Close()
		output.Close()
		os.Remove(destination)
		return err
	}
	if err := tarWriter.Close(); err != nil {
		output.Close()
		return err
	}
	if err := gzipWriter.Close(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func RestoreArchive(archive, dataDir string) error {
	if archive == "" || dataDir == "" {
		return errors.New("archive et répertoire de destination requis")
	}
	if entries, err := os.ReadDir(dataDir); err == nil && len(entries) > 0 {
		return errors.New("le répertoire de restauration doit être vide")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	input, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer input.Close()
	gzipReader, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	tarReader := tar.NewReader(gzipReader)
	var total int64
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(filepath.FromSlash(header.Name))
		if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return errors.New("chemin d'archive non sûr")
		}
		destination := filepath.Join(dataDir, clean)
		if !strings.HasPrefix(destination, filepath.Clean(dataDir)+string(filepath.Separator)) {
			return errors.New("évasion du répertoire de restauration")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(destination, 0o750); err != nil {
				return err
			}
		case tar.TypeReg:
			total += header.Size
			if total > 2*1024*1024*1024 {
				return errors.New("archive de restauration supérieure à 2 Gio")
			}
			if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
				return err
			}
			mode := os.FileMode(header.Mode) & 0o777
			if mode == 0 || mode&0o600 != 0o600 {
				mode = 0o600
			}
			file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(file, tarReader, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return errors.New("type d'entrée non pris en charge dans la sauvegarde")
		}
	}
	if _, err := os.Stat(filepath.Join(dataDir, "hydra.db")); err != nil {
		return errors.New("sauvegarde sans base hydra.db")
	}
	return nil
}
