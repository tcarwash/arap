package challenge

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore persists outstanding challenges and atomically consumes each once.
type SQLiteStore struct{ db *sql.DB }

func OpenSQLite(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("challenge database path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	dsn := (&url.URL{Scheme: "file", Path: abs, RawQuery: "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS challenges (
		request_hash BLOB PRIMARY KEY CHECK(length(request_hash)=32),
		requester TEXT NOT NULL,
		responder TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		state TEXT NOT NULL CHECK(state IN ('pending','consumed')),
		created_at INTEGER NOT NULL
	)`); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(abs, 0600); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *SQLiteStore) Issue(requestHash []byte, requester, responder string, expiresAt int64) error {
	if s == nil || s.db == nil || len(requestHash) != 32 || requester == "" || responder == "" || expiresAt <= 0 {
		return errors.New("invalid challenge issue record")
	}
	now := time.Now().UTC().Unix()
	if err := s.PruneExpired(now); err != nil {
		return fmt.Errorf("prune expired challenges: %w", err)
	}
	_, err := s.db.Exec(`INSERT INTO challenges(request_hash,requester,responder,expires_at,state,created_at) VALUES(?,?,?,?, 'pending', ?)`, requestHash, requester, responder, expiresAt, now)
	if err != nil {
		return fmt.Errorf("record outstanding challenge: %w", err)
	}
	return nil
}

// PruneExpired removes expired records. Callers may use it at startup or
// before issuance; correctness does not depend on cleanup because Consume
// always checks expiry in its conditional write.
func (s *SQLiteStore) PruneExpired(now int64) error {
	if s == nil || s.db == nil || now < 0 {
		return errors.New("invalid challenge prune request")
	}
	_, err := s.db.Exec(`DELETE FROM challenges WHERE expires_at<=?`, now)
	return err
}

// CancelPending removes an issued request that was not successfully published
// to its output file. It never deletes a consumed record.
func (s *SQLiteStore) CancelPending(requestHash []byte) error {
	if s == nil || s.db == nil || len(requestHash) != 32 {
		return errors.New("invalid challenge cancellation request")
	}
	_, err := s.db.Exec(`DELETE FROM challenges WHERE request_hash=? AND state='pending'`, requestHash)
	return err
}

// Consume uses a single conditional write. Exactly one verifier can transition
// a live pending record, even when concurrent processes share this database.
func (s *SQLiteStore) Consume(requestHash []byte, now int64) (bool, error) {
	if s == nil || s.db == nil || len(requestHash) != 32 {
		return false, errors.New("invalid challenge consume request")
	}
	res, err := s.db.Exec(`UPDATE challenges SET state='consumed' WHERE request_hash=? AND state='pending' AND expires_at>?`, requestHash, now)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// ConsumePair changes two live pending challenges in one transaction. If
// either challenge is absent, expired, or already consumed, neither is used.
func (s *SQLiteStore) ConsumePair(firstHash, secondHash []byte, now int64) (bool, error) {
	if s == nil || s.db == nil || len(firstHash) != 32 || len(secondHash) != 32 || bytes.Equal(firstHash, secondHash) {
		return false, errors.New("invalid challenge-pair consume request")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	consume := func(hash []byte) (bool, error) {
		result, err := tx.Exec(`UPDATE challenges SET state='consumed' WHERE request_hash=? AND state='pending' AND expires_at>?`, hash, now)
		if err != nil {
			return false, err
		}
		rows, err := result.RowsAffected()
		return rows == 1, err
	}
	first, err := consume(firstHash)
	if err != nil || !first {
		_ = tx.Rollback()
		return false, err
	}
	second, err := consume(secondHash)
	if err != nil || !second {
		_ = tx.Rollback()
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}
