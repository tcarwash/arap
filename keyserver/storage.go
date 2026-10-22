package keyserver

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Options bound persisted objects and authenticated write volume. A zero
// retention means stored proof and key objects do not expire automatically.
type Options struct {
	MaxProofObjects     int64
	MaxKeyObjects       int64
	MaxTotalBytes       int64
	MaxUploadsPerMinute int64
	Retention           time.Duration
}

func DefaultOptions() Options {
	return Options{MaxProofObjects: 100_000, MaxKeyObjects: 10_000, MaxTotalBytes: 10 << 30, MaxUploadsPerMinute: 600}
}

type objectStore struct {
	root    string
	db      *sql.DB
	options Options
	// Serialize quota reservation, expiration cleanup and immutable-file
	// publication so stale cleanup cannot remove a newly published replacement.
	writeMu sync.Mutex
}

var errQuotaExceeded = errors.New("keyserver storage quota exceeded")

func openObjectStore(root string, options Options) (*objectStore, error) {
	defaults := DefaultOptions()
	if options.MaxProofObjects < 0 || options.MaxKeyObjects < 0 || options.MaxTotalBytes < 0 || options.MaxUploadsPerMinute < 0 {
		return nil, errors.New("object and upload limits cannot be negative")
	}
	if options.MaxProofObjects <= 0 {
		options.MaxProofObjects = defaults.MaxProofObjects
	}
	if options.MaxKeyObjects <= 0 {
		options.MaxKeyObjects = defaults.MaxKeyObjects
	}
	if options.MaxTotalBytes <= 0 {
		options.MaxTotalBytes = defaults.MaxTotalBytes
	}
	if options.MaxUploadsPerMinute <= 0 {
		options.MaxUploadsPerMinute = defaults.MaxUploadsPerMinute
	}
	if options.Retention < 0 {
		return nil, errors.New("retention cannot be negative")
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.Join(root, "keyserver-index.sqlite"), RawQuery: "_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(8)
	store := &objectStore{root: root, db: db, options: options}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS usage (id INTEGER PRIMARY KEY CHECK(id=1), proof_objects INTEGER NOT NULL, key_objects INTEGER NOT NULL, total_bytes INTEGER NOT NULL)`,
		`INSERT OR IGNORE INTO usage(id,proof_objects,key_objects,total_bytes) VALUES(1,0,0,0)`,
		`CREATE TABLE IF NOT EXISTS objects (kind TEXT NOT NULL CHECK(kind IN ('proof','key')), id TEXT NOT NULL, size INTEGER NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(kind,id))`,
		`CREATE INDEX IF NOT EXISTS objects_created_at ON objects(created_at)`,
		`CREATE TABLE IF NOT EXISTS upload_windows (window_start INTEGER PRIMARY KEY, upload_count INTEGER NOT NULL)`,
		`CREATE TRIGGER IF NOT EXISTS object_insert_usage AFTER INSERT ON objects BEGIN UPDATE usage SET proof_objects=proof_objects+CASE WHEN NEW.kind='proof' THEN 1 ELSE 0 END, key_objects=key_objects+CASE WHEN NEW.kind='key' THEN 1 ELSE 0 END, total_bytes=total_bytes+NEW.size WHERE id=1; END`,
		`CREATE TRIGGER IF NOT EXISTS object_delete_usage AFTER DELETE ON objects BEGIN UPDATE usage SET proof_objects=proof_objects-CASE WHEN OLD.kind='proof' THEN 1 ELSE 0 END, key_objects=key_objects-CASE WHEN OLD.kind='key' THEN 1 ELSE 0 END, total_bytes=total_bytes-OLD.size WHERE id=1; END`,
	}
	for _, q := range statements {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	indexPath := filepath.Join(root, "keyserver-index.sqlite")
	if err := os.Chmod(indexPath, 0600); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.reconcile(time.Now()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *objectStore) close() error { return s.db.Close() }

func (s *objectStore) reconcile(now time.Time) error {
	type record struct {
		kind, id string
		size     int64
		created  int64
	}
	var found []record
	for _, kind := range []string{"proof", "key"} {
		dir := filepath.Join(s.root, kind+"s")
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			id := entry.Name()
			if !validObjectID(kind, id) || entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				continue
			}
			created := info.ModTime().Unix()
			if s.expired(created, now) {
				if err := os.Remove(filepath.Join(dir, id)); err != nil && !os.IsNotExist(err) {
					return err
				}
				continue
			}
			found = append(found, record{kind: kind, id: id, size: info.Size(), created: created})
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM objects`); err != nil {
		return err
	}
	for _, obj := range found {
		if _, err := tx.Exec(`INSERT INTO objects(kind,id,size,created_at) VALUES(?,?,?,?)`, obj.kind, obj.id, obj.size, obj.created); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func validObjectID(kind, id string) bool {
	switch kind {
	case "proof":
		return hexHash.MatchString(id)
	case "key":
		return keyHash.MatchString(id)
	default:
		return false
	}
}
func (s *objectStore) expired(created int64, now time.Time) bool {
	return s.options.Retention > 0 && created <= now.Add(-s.options.Retention).Unix()
}

// allowUpload is a persistent, service-wide fixed-window write limit.
func (s *objectStore) allowUpload(now time.Time) (bool, error) {
	window := now.Unix() / 60 * 60
	res, err := s.db.Exec(`INSERT INTO upload_windows(window_start,upload_count) VALUES(?,1) ON CONFLICT(window_start) DO UPDATE SET upload_count=upload_count+1 WHERE upload_count<?`, window, s.options.MaxUploadsPerMinute)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	_, _ = s.db.Exec(`DELETE FROM upload_windows WHERE window_start<?`, window-120)
	return n == 1, nil
}

func (s *objectStore) pruneExpired(now time.Time) error {
	if s.options.Retention <= 0 {
		return nil
	}
	cutoff := now.Add(-s.options.Retention).Unix()
	rows, err := s.db.Query(`SELECT kind,id FROM objects WHERE created_at<=?`, cutoff)
	if err != nil {
		return err
	}
	type key struct{ kind, id string }
	var expired []key
	for rows.Next() {
		var x key
		if err := rows.Scan(&x.kind, &x.id); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, x)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, x := range expired {
		path := filepath.Join(s.root, x.kind+"s", x.id)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		if _, err := s.db.Exec(`DELETE FROM objects WHERE kind=? AND id=? AND created_at<=?`, x.kind, x.id, cutoff); err != nil {
			return err
		}
	}
	return nil
}

func (s *objectStore) prune(now time.Time) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.pruneExpired(now)
}

func (s *objectStore) reserve(kind, id string, size int64, now time.Time) (bool, error) {
	if !validObjectID(kind, id) || size <= 0 {
		return false, errors.New("invalid object reservation")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT OR IGNORE INTO objects(kind,id,size,created_at) VALUES(?,?,?,?)`, kind, id, size, now.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return false, nil
	}
	var proofs, keys, total int64
	if err := tx.QueryRow(`SELECT proof_objects,key_objects,total_bytes FROM usage WHERE id=1`).Scan(&proofs, &keys, &total); err != nil {
		return false, err
	}
	if proofs > s.options.MaxProofObjects || keys > s.options.MaxKeyObjects || total > s.options.MaxTotalBytes {
		return false, errQuotaExceeded
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *objectStore) release(kind, id string) error {
	_, err := s.db.Exec(`DELETE FROM objects WHERE kind=? AND id=?`, kind, id)
	return err
}

func (s *objectStore) write(kind, path, id string, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	now := time.Now()
	if err := s.pruneExpired(now); err != nil {
		return err
	}
	reserved, err := s.reserve(kind, id, int64(len(data)), now)
	if err != nil {
		return err
	}
	if err := storeImmutable(path, data); err != nil {
		if reserved {
			_ = s.release(kind, id)
		}
		return err
	}
	return nil
}

func (s *objectStore) read(kind, path, id string) ([]byte, error) {
	if err := s.prune(time.Now()); err != nil {
		return nil, err
	}
	var exists bool
	if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM objects WHERE kind=? AND id=?)`, kind, id).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, os.ErrNotExist
	}
	limit := int64(0)
	switch kind {
	case "proof":
		limit = ProofLimit
	case "key":
		limit = PublicKeyLimit
	default:
		return nil, errors.New("invalid object kind")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("stored object is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("stored object exceeds its size limit")
	}
	return data, nil
}

func (s *objectStore) proofsWithPrefix(prefixHex string, limit int) ([]string, error) {
	prefixBytes, err := hex.DecodeString(prefixHex)
	if err != nil || len(prefixBytes) != 10 || strings.ToLower(prefixHex) != prefixHex || limit <= 0 {
		return nil, errors.New("invalid proof prefix query")
	}
	rows, err := s.db.Query(`SELECT id FROM objects WHERE kind='proof' AND id>=? AND id<? ORDER BY id LIMIT ?`, prefixHex, prefixHex+"g", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if !validObjectID("proof", id) || !strings.HasPrefix(id, prefixHex) {
			return nil, errors.New("invalid proof index entry")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *objectStore) usage() (proofs, keys, bytes int64, err error) {
	err = s.db.QueryRow(`SELECT proof_objects,key_objects,total_bytes FROM usage WHERE id=1`).Scan(&proofs, &keys, &bytes)
	return
}
