package keyserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tcarwash/arap/identity"
	"github.com/tcarwash/arap/protocol"
)

const (
	ProofLimit     = 64 * 1024
	PublicKeyLimit = 1024 * 1024
	CandidateLimit = 100
)

var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var keyHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var b32Prefix = regexp.MustCompile(`^[A-Z2-7]{16}$`)

type Server struct {
	root, token string
	mux         *http.ServeMux
	storage     *objectStore
}

func New(root, uploadToken string) (*Server, error) {
	return NewWithOptions(root, uploadToken, DefaultOptions())
}

func NewWithOptions(root, uploadToken string, options Options) (*Server, error) {
	if root == "" {
		return nil, fmt.Errorf("data root is required")
	}
	if err := ValidateUploadToken(uploadToken); err != nil {
		return nil, err
	}
	for _, sub := range []string{"proofs", "keys"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0700); err != nil {
			return nil, err
		}
	}
	storage, err := openObjectStore(root, options)
	if err != nil {
		return nil, err
	}
	s := &Server{root: root, token: uploadToken, mux: http.NewServeMux(), storage: storage}
	s.mux.HandleFunc("/healthz", s.health)
	s.mux.HandleFunc("/v1/proofs/", s.proofs)
	s.mux.HandleFunc("/v1/lookup/", s.lookup)
	s.mux.HandleFunc("/v1/keys/", s.keys)
	return s, nil
}

// ValidateUploadToken enforces a minimum bearer-token length and the RFC 6750
// bearer-token character set for every server construction path. Operators
// must still supply a cryptographically random token; length alone is not
// evidence of entropy.
func ValidateUploadToken(token string) error {
	if token == "" {
		return fmt.Errorf("ARAP_UPLOAD_TOKEN is required")
	}
	payloadLength := len(token)
	for payloadLength > 0 && token[payloadLength-1] == '=' {
		payloadLength--
	}
	if payloadLength < 32 {
		return fmt.Errorf("ARAP_UPLOAD_TOKEN must contain at least 32 non-padding characters")
	}
	if len(token)-payloadLength > 2 {
		return fmt.Errorf("ARAP_UPLOAD_TOKEN has invalid bearer-token padding")
	}
	padding := false
	for i := 0; i < len(token); i++ {
		c := token[i]
		if c == '=' {
			padding = true
			continue
		}
		if padding {
			return fmt.Errorf("ARAP_UPLOAD_TOKEN has data after padding")
		}
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '-', '.', '_', '~', '+', '/':
		default:
			return fmt.Errorf("ARAP_UPLOAD_TOKEN contains characters invalid in a bearer token")
		}
	}
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	s.mux.ServeHTTP(w, r)
}
func (s *Server) Close() error {
	if s.storage == nil {
		return nil
	}
	return s.storage.close()
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		method(w)
		return
	}
	if s.storage == nil || s.storage.db == nil || s.storage.db.Ping() != nil {
		http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
		return
	}
	for _, sub := range []string{"proofs", "keys"} {
		path := filepath.Join(s.root, sub)
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
		probe, err := os.CreateTemp(path, ".arap-health-*")
		if err != nil {
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
		probePath := probe.Name()
		if err := probe.Close(); err != nil {
			_ = os.Remove(probePath)
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := os.Remove(probePath); err != nil {
			http.Error(w, "storage unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}
func (s *Server) proofs(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/proofs/")
	if !hexHash.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.root, "proofs", id)
	switch r.Method {
	case http.MethodGet:
		data, err := s.storage.read("proof", path, id)
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		hash := sha256Sum(data)
		if hex.EncodeToString(hash[:]) != id {
			http.Error(w, "stored object failed its content hash", 500)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Content-Type", "application/cose")
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		w.WriteHeader(200)
		_, _ = w.Write(data)
	case http.MethodPut:
		if !s.authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if ok, err := s.storage.allowUpload(time.Now()); err != nil {
			http.Error(w, "upload limit storage error", 500)
			return
		} else if !ok {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "upload rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		data, err := readLimit(r.Body, ProofLimit)
		if err != nil {
			http.Error(w, "proof too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		if len(data) == 0 {
			http.Error(w, "empty proof", 400)
			return
		}
		hash := sha256Sum(data)
		if hex.EncodeToString(hash[:]) != id {
			http.Error(w, "path hash does not match proof", 400)
			return
		}
		if err := s.storage.write("proof", path, id, data); err != nil {
			if errors.Is(err, errQuotaExceeded) {
				http.Error(w, "storage quota exceeded", http.StatusInsufficientStorage)
				return
			}
			if os.IsExist(err) {
				http.Error(w, "immutable object already exists with different bytes", http.StatusConflict)
			} else {
				http.Error(w, "storage error", 500)
			}
			return
		}
		w.WriteHeader(http.StatusCreated)
	default:
		method(w)
	}
}
func (s *Server) lookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		method(w)
		return
	}
	prefix := strings.TrimPrefix(r.URL.Path, "/v1/lookup/")
	if !b32Prefix.MatchString(prefix) {
		http.NotFound(w, r)
		return
	}
	if err := s.storage.prune(time.Now()); err != nil {
		http.Error(w, "storage cleanup error", 500)
		return
	}
	firstTenBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(prefix)
	if err != nil {
		http.Error(w, "invalid lookup prefix", http.StatusBadRequest)
		return
	}
	if len(firstTenBytes) != 10 {
		http.Error(w, "invalid lookup prefix", http.StatusBadRequest)
		return
	}
	prefixHex := hex.EncodeToString(firstTenBytes)
	matches, err := s.storage.proofsWithPrefix(prefixHex, CandidateLimit+1)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	truncated := len(matches) > CandidateLimit
	if truncated {
		matches = matches[:CandidateLimit]
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Proofs    []string `json:"proofs"`
		Truncated bool     `json:"truncated"`
	}{matches, truncated})
}
func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/keys/")
	if !keyHash.MatchString(id) {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(s.root, "keys", id)
	switch r.Method {
	case http.MethodGet:
		data, err := s.storage.read("key", path, id)
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			http.Error(w, "storage error", 500)
			return
		}
		pub, err := publicKey(data)
		if err != nil {
			http.Error(w, "stored key is malformed", 500)
			return
		}
		fingerprint, err := protocol.KeyID(pub)
		if err != nil || hex.EncodeToString(fingerprint) != id {
			http.Error(w, "stored key failed its fingerprint", 500)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		_, _ = w.Write(data)
	case http.MethodPut:
		if !s.authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if ok, err := s.storage.allowUpload(time.Now()); err != nil {
			http.Error(w, "upload limit storage error", 500)
			return
		} else if !ok {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "upload rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		data, err := readLimit(r.Body, PublicKeyLimit)
		if err != nil {
			http.Error(w, "key object too large or unreadable", 413)
			return
		}
		pub, err := publicKey(data)
		if err != nil {
			http.Error(w, "expected a PEM public key or X.509 certificate", 400)
			return
		}
		fingerprint, err := protocol.KeyID(pub)
		if err != nil || hex.EncodeToString(fingerprint) != id {
			http.Error(w, "key fingerprint does not match path", 400)
			return
		}
		if err := s.storage.write("key", path, id, data); err != nil {
			if errors.Is(err, errQuotaExceeded) {
				http.Error(w, "storage quota exceeded", http.StatusInsufficientStorage)
				return
			}
			if os.IsExist(err) {
				http.Error(w, "immutable object already exists with different bytes", 409)
			} else {
				http.Error(w, "storage error", 500)
			}
			return
		}
		w.WriteHeader(201)
	default:
		method(w)
	}
}
func publicKey(data []byte) (any, error) {
	return identity.ParsePublicKey(data)
}
func (s *Server) authorized(r *http.Request) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	header := values[0]
	space := strings.IndexByte(header, ' ')
	if space <= 0 || !strings.EqualFold(header[:space], "Bearer") {
		return false
	}
	value := strings.TrimLeft(header[space:], " ")
	if value == "" || strings.ContainsAny(value, " \t\r\n") || len(value) != len(s.token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(value), []byte(s.token)) == 1
}
func readLimit(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("limit exceeded")
	}
	return b, nil
}
func storeImmutable(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(name, path); err != nil {
		if !os.IsExist(err) {
			return err
		}
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Size() != int64(len(data)) {
			return os.ErrExist
		}
		existingFile, e := os.Open(path)
		if e != nil {
			return e
		}
		defer existingFile.Close()
		matches, e := existingObjectMatches(existingFile, data)
		if e != nil {
			return e
		}
		if matches {
			return nil
		}
		return os.ErrExist
	}
	return nil
}

func existingObjectMatches(existing io.Reader, data []byte) (bool, error) {
	current, err := io.ReadAll(io.LimitReader(existing, int64(len(data))+1))
	if err != nil {
		return false, err
	}
	return len(current) == len(data) && subtle.ConstantTimeCompare(current, data) == 1, nil
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
func method(w http.ResponseWriter) {
	w.Header().Set("Allow", "GET, PUT")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
