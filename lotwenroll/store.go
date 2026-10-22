package lotwenroll

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tcarwash/arap/protocol"
	_ "modernc.org/sqlite"
)

// SQLiteStore persists outstanding enrollment challenges and accepted
// callsign-to-Ed25519 bindings in one transaction domain.
type SQLiteStore struct{ db *sql.DB }

func OpenSQLite(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("enrollment database path is required")
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
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS enrollment_challenges (
		request_hash BLOB PRIMARY KEY CHECK(length(request_hash)=32),
		requester TEXT NOT NULL,
		responder TEXT NOT NULL,
		key_id TEXT NOT NULL CHECK(length(key_id)=64),
		expires_at INTEGER NOT NULL,
		state TEXT NOT NULL CHECK(state IN ('pending','consumed')),
		created_at INTEGER NOT NULL
	)`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS enrollment_bindings (
		callsign TEXT NOT NULL,
		key_id TEXT NOT NULL CHECK(length(key_id)=64),
		public_key BLOB NOT NULL CHECK(length(public_key)=32),
		purposes TEXT NOT NULL,
		certificate_sha256 TEXT NOT NULL CHECK(length(certificate_sha256)=64),
		certificate_issuer TEXT NOT NULL,
		certificate_expires_at INTEGER NOT NULL,
		verified_at INTEGER NOT NULL,
		certificate_status TEXT NOT NULL,
		status_source TEXT NOT NULL,
		status_observed_at INTEGER NOT NULL,
		disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
		PRIMARY KEY(callsign,key_id)
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

func (s *SQLiteStore) Issue(hash []byte, requester, responder, keyID string, expiresAt int64) error {
	keyBytes, keyErr := hex.DecodeString(keyID)
	if s == nil || s.db == nil || len(hash) != 32 || requester == "" || responder == "" || keyErr != nil || len(keyBytes) != 32 || strings.ToLower(keyID) != keyID || expiresAt <= 0 {
		return errors.New("invalid enrollment challenge issue record")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Unix()
	if _, err := tx.Exec(`DELETE FROM enrollment_challenges WHERE expires_at<=?`, now); err != nil {
		return fmt.Errorf("prune expired enrollment challenges: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO enrollment_challenges(request_hash,requester,responder,key_id,expires_at,state,created_at) VALUES(?,?,?,?,?, 'pending', ?)`, hash, requester, responder, keyID, expiresAt, now); err != nil {
		return fmt.Errorf("record enrollment challenge: %w", err)
	}
	return tx.Commit()
}

// CancelPending removes a challenge that was persisted but could not be
// published to its recipient. A consumed challenge is never cancellable.
func (s *SQLiteStore) CancelPending(hash []byte) error {
	if s == nil || s.db == nil || len(hash) != 32 {
		return errors.New("invalid enrollment challenge cancellation")
	}
	_, err := s.db.Exec(`DELETE FROM enrollment_challenges WHERE request_hash=? AND state='pending'`, hash)
	return err
}

func (s *SQLiteStore) Complete(hash []byte, binding Binding, now int64) (bool, error) {
	if s == nil || s.db == nil || len(hash) != 32 || now <= 0 {
		return false, errors.New("invalid enrollment completion request")
	}
	if err := validateBinding(binding); err != nil {
		return false, err
	}
	if binding.VerifiedAt != now || binding.CertificateExpiry <= now || binding.StatusObservedAt > now {
		return false, errors.New("enrollment binding times do not match current verification")
	}
	purposes, err := json.Marshal(binding.Purposes)
	if err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	updated, err := tx.Exec(`UPDATE enrollment_challenges SET state='consumed' WHERE request_hash=? AND responder=? AND key_id=? AND state='pending' AND expires_at>?`, hash, binding.Callsign, binding.KeyID, now)
	if err != nil {
		return false, err
	}
	n, err := updated.RowsAffected()
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, nil
	}
	_, err = tx.Exec(`INSERT INTO enrollment_bindings(
		callsign,key_id,public_key,purposes,certificate_sha256,certificate_issuer,
		certificate_expires_at,verified_at,certificate_status,status_source,status_observed_at,disabled
	) VALUES(?,?,?,?,?,?,?,?,?,?,?,0)
	ON CONFLICT(callsign,key_id) DO UPDATE SET
		public_key=excluded.public_key,purposes=excluded.purposes,
		certificate_sha256=excluded.certificate_sha256,certificate_issuer=excluded.certificate_issuer,
		certificate_expires_at=excluded.certificate_expires_at,verified_at=excluded.verified_at,
		certificate_status=excluded.certificate_status,status_source=excluded.status_source,
		status_observed_at=excluded.status_observed_at,disabled=0`,
		binding.Callsign, binding.KeyID, binding.PublicKey, string(purposes), binding.CertificateSHA256,
		binding.CertificateIssuer, binding.CertificateExpiry, binding.VerifiedAt,
		string(binding.Status), binding.StatusSource, binding.StatusObservedAt)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) Bindings() ([]Binding, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("enrollment store is closed")
	}
	rows, err := s.db.Query(`SELECT callsign,key_id,public_key,purposes,certificate_sha256,certificate_issuer,
		certificate_expires_at,verified_at,certificate_status,status_source,status_observed_at,disabled
		FROM enrollment_bindings ORDER BY callsign,key_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Binding, 0)
	for rows.Next() {
		var b Binding
		var purposes string
		var disabled int
		if err := rows.Scan(&b.Callsign, &b.KeyID, &b.PublicKey, &purposes, &b.CertificateSHA256, &b.CertificateIssuer,
			&b.CertificateExpiry, &b.VerifiedAt, &b.Status, &b.StatusSource, &b.StatusObservedAt, &disabled); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(purposes), &b.Purposes); err != nil {
			return nil, fmt.Errorf("decode stored enrollment purposes: %w", err)
		}
		b.Disabled = disabled != 0
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) Disable(callsign, keyID string) error {
	if s == nil || s.db == nil {
		return errors.New("enrollment store is closed")
	}
	call, err := protocol.NormalizeCallsign(callsign)
	if err != nil || call != callsign {
		return errors.New("callsign must be normalized")
	}
	keyID = strings.ToLower(keyID)
	decoded, err := hex.DecodeString(keyID)
	if err != nil || len(decoded) != 32 {
		return errors.New("key fingerprint must be a 32-byte SHA-256 hex value")
	}
	result, err := s.db.Exec(`UPDATE enrollment_bindings SET disabled=1 WHERE callsign=? AND key_id=?`, call, keyID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return sql.ErrNoRows
	}
	return err
}

// RefreshStatus atomically records new certificate-status evidence for an
// existing binding. Disabled, expired, or certificate-mismatched bindings are
// never changed or re-enabled.
func (s *SQLiteStore) RefreshStatus(callsign, keyID, certificateSHA256 string, evidence StatusEvidence, now time.Time, maxAge time.Duration) (bool, error) {
	if s == nil || s.db == nil || maxAge <= 0 || evidence.Status != StatusGood || evidence.Source == "" || evidence.ObservedAt.IsZero() {
		return false, errors.New("invalid enrollment status refresh")
	}
	call, err := protocol.NormalizeCallsign(callsign)
	if err != nil || call != callsign {
		return false, errors.New("callsign must be normalized")
	}
	keyID = strings.ToLower(keyID)
	keyBytes, err := hex.DecodeString(keyID)
	if err != nil || len(keyBytes) != 32 {
		return false, errors.New("key fingerprint must be a 32-byte SHA-256 hex value")
	}
	certID, err := hex.DecodeString(certificateSHA256)
	if err != nil || len(certID) != 32 || strings.ToLower(certificateSHA256) != certificateSHA256 {
		return false, errors.New("certificate fingerprint must be lowercase SHA-256 hex")
	}
	observed := evidence.ObservedAt.UTC()
	if now.IsZero() || observed.After(now) || now.Sub(observed) > maxAge {
		return false, errors.New("certificate-status evidence is future-dated or stale")
	}
	result, err := s.db.Exec(`UPDATE enrollment_bindings SET certificate_status=?,status_source=?,status_observed_at=?
		WHERE callsign=? AND key_id=? AND certificate_sha256=? AND disabled=0 AND certificate_expires_at>?`,
		string(evidence.Status), evidence.Source, observed.Unix(), call, keyID, certificateSHA256, now.UTC().Unix())
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows == 1, err
}

// TrustStatus grants only the purposes recorded in an accepted enrollment,
// while its binding is enabled, its certificate is unexpired, and its stored
// status evidence is within maxAge. Version 1 bindings remain challenge-only.
func (s *SQLiteStore) TrustStatus(callsign, keyID, purpose string, now time.Time, maxAge time.Duration) string {
	if s == nil || s.db == nil || (purpose != PurposeChallengeResponse && purpose != PurposeContentSignature) || maxAge <= 0 {
		return "untrusted"
	}
	call, err := protocol.NormalizeCallsign(callsign)
	if err != nil || call != callsign {
		return "untrusted"
	}
	keyID = strings.ToLower(keyID)
	if decoded, err := hex.DecodeString(keyID); err != nil || len(decoded) != 32 {
		return "untrusted"
	}
	var status, statusSource, purposesJSON string
	var statusObserved, certExpiry int64
	var disabled int
	err = s.db.QueryRow(`SELECT certificate_status,status_source,status_observed_at,certificate_expires_at,disabled,purposes
		FROM enrollment_bindings WHERE callsign=? AND key_id=?`, call, keyID).Scan(&status, &statusSource, &statusObserved, &certExpiry, &disabled, &purposesJSON)
	if err == sql.ErrNoRows || err != nil {
		return "untrusted"
	}
	if disabled != 0 {
		return "disabled"
	}
	var purposes []string
	if json.Unmarshal([]byte(purposesJSON), &purposes) != nil || !containsEnrollmentPurpose(purposes, purpose) {
		return "untrusted"
	}
	observedAge := now.Sub(time.Unix(statusObserved, 0))
	if status != string(StatusGood) || statusSource == "" || certExpiry <= now.UTC().Unix() || observedAge < 0 || observedAge > maxAge {
		return "untrusted"
	}
	return "trusted"
}

func validateBinding(b Binding) error {
	call, err := protocol.NormalizeCallsign(b.Callsign)
	if err != nil || call != b.Callsign {
		return errors.New("binding callsign must be normalized")
	}
	keyID, err := hex.DecodeString(b.KeyID)
	if err != nil || len(keyID) != 32 || strings.ToLower(b.KeyID) != b.KeyID {
		return errors.New("binding key fingerprint must be lowercase SHA-256 hex")
	}
	certID, err := hex.DecodeString(b.CertificateSHA256)
	if err != nil || len(certID) != 32 || strings.ToLower(b.CertificateSHA256) != b.CertificateSHA256 {
		return errors.New("binding certificate fingerprint must be lowercase SHA-256 hex")
	}
	if len(b.PublicKey) != 32 || b.CertificateIssuer == "" || b.CertificateExpiry <= b.VerifiedAt || b.VerifiedAt <= 0 || b.Status != StatusGood || b.StatusSource == "" || b.StatusObservedAt <= 0 || b.StatusObservedAt > b.VerifiedAt || len(b.Purposes) == 0 {
		return errors.New("binding is missing required key, certificate, status or purpose evidence")
	}
	derived, err := protocol.KeyID(ed25519.PublicKey(b.PublicKey))
	if err != nil || hex.EncodeToString(derived) != b.KeyID {
		return errors.New("binding key fingerprint does not match the public key")
	}
	if !sort.StringsAreSorted(b.Purposes) {
		return errors.New("binding purposes must be sorted")
	}
	for i, purpose := range b.Purposes {
		if purpose != PurposeChallengeResponse && purpose != PurposeContentSignature {
			return errors.New("LoTW enrollment contains an unsupported key-use purpose")
		}
		if i > 0 && purpose == b.Purposes[i-1] {
			return errors.New("binding purposes must be unique")
		}
	}
	return nil
}
