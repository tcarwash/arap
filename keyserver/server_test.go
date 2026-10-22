package keyserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tcarwash/arap/protocol"
)

const testUploadToken = "0123456789abcdef0123456789abcdef"

type countedReader struct {
	remaining int
	read      int
}

func (r *countedReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	clear(p[:n])
	r.remaining -= n
	r.read += n
	return n, nil
}

func TestExistingObjectComparisonReadsAtMostIncomingSizePlusOne(t *testing.T) {
	data := []byte("small")
	existing := &countedReader{remaining: 1 << 30}
	matches, err := existingObjectMatches(existing, data)
	if err != nil || matches {
		t.Fatalf("oversized existing object comparison=(%v,%v)", matches, err)
	}
	if existing.read != len(data)+1 {
		t.Fatalf("read %d existing bytes, want bounded read of %d", existing.read, len(data)+1)
	}
}

func TestNewRejectsWeakUploadTokens(t *testing.T) {
	for _, token := range []string{"", "short-token", strings.Repeat("a", 31), strings.Repeat("a", 31) + "=", strings.Repeat("a", 32) + "==="} {
		if err := ValidateUploadToken(token); err == nil {
			t.Errorf("accepted weak or malformed upload token %q", token)
		}
		if _, err := New(t.TempDir(), token); err == nil {
			t.Errorf("constructed server with weak or malformed upload token %q", token)
		}
	}
	if err := ValidateUploadToken(testUploadToken); err != nil {
		t.Fatalf("rejected valid upload token: %v", err)
	}
}

func TestProofObjectHashAuthAndLookup(t *testing.T) {
	s, err := New(t.TempDir(), testUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("test proof bytes")
	h := sha256Sum(data)
	id := hex.EncodeToString(h[:])
	req := httptest.NewRequest(http.MethodPut, "/v1/proofs/"+id, bytes.NewReader(data))
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized upload status=%d", response.Code)
	}
	req = httptest.NewRequest(http.MethodPut, "/v1/proofs/"+id, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+testUploadToken)
	response = httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("upload status=%d body=%s", response.Code, response.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/proofs/"+id, nil)
	response = httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), data) {
		t.Fatalf("get status=%d body=%q", response.Code, response.Body.Bytes())
	}
	prefix := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:10])
	req = httptest.NewRequest(http.MethodGet, "/v1/lookup/"+prefix, nil)
	response = httptest.NewRecorder()
	s.ServeHTTP(response, req)
	var result struct {
		Proofs    []string `json:"proofs"`
		Truncated bool     `json:"truncated"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || result.Truncated || len(result.Proofs) != 1 || result.Proofs[0] != id {
		t.Fatalf("lookup: status=%d result=%+v", response.Code, result)
	}
	req = httptest.NewRequest(http.MethodPut, "/v1/proofs/"+id, bytes.NewReader([]byte("changed")))
	req.Header.Set("Authorization", "Bearer "+testUploadToken)
	response = httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("hash mismatch status=%d", response.Code)
	}
}

func TestHealthReflectsStorageReadiness(t *testing.T) {
	t.Run("healthy storage", func(t *testing.T) {
		s, err := New(t.TempDir(), testUploadToken)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		response := httptest.NewRecorder()
		s.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if response.Code != http.StatusOK || response.Body.String() != "ok\n" {
			t.Fatalf("healthy storage response=%d %q", response.Code, response.Body.String())
		}
	})

	t.Run("closed database", func(t *testing.T) {
		s, err := New(t.TempDir(), testUploadToken)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		s.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("closed database health status=%d body=%q, want 503", response.Code, response.Body.String())
		}
	})

	t.Run("missing object directory", func(t *testing.T) {
		root := t.TempDir()
		s, err := New(root, testUploadToken)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := os.RemoveAll(filepath.Join(root, "keys")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "keys"), []byte("not a directory"), 0600); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		s.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("missing object directory health status=%d body=%q, want 503", response.Code, response.Body.String())
		}
	})
}

func TestProofGetRejectsCorruptedHashAddressedObject(t *testing.T) {
	s, err := New(t.TempDir(), testUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	proof := []byte("original proof bytes")
	id := proofID(proof)
	path := filepath.Join(s.root, "proofs", id)
	if err := s.storage.write("proof", path, id, proof); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered proof bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/proofs/"+id, nil)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("corrupted object status=%d body=%q, want 500", response.Code, response.Body.String())
	}
}

func TestProofGetRejectsOversizedStoredObject(t *testing.T) {
	s, err := New(t.TempDir(), testUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	proof := []byte("original proof bytes")
	id := proofID(proof)
	path := filepath.Join(s.root, "proofs", id)
	if err := s.storage.write("proof", path, id, proof); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, ProofLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/proofs/"+id, nil)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("oversized object status=%d body=%q, want 500", response.Code, response.Body.String())
	}
}

func TestUploadRequiresBearerAuthorizationScheme(t *testing.T) {
	s, err := New(t.TempDir(), testUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	data := []byte("auth scheme test")
	id := proofID(data)
	for _, header := range []string{testUploadToken, "Basic " + testUploadToken, "Bearer " + testUploadToken + " extra", "Bearer\t" + testUploadToken, "Bearer " + testUploadToken + " "} {
		req := httptest.NewRequest(http.MethodPut, "/v1/proofs/"+id, bytes.NewReader(data))
		req.Header.Set("Authorization", header)
		response := httptest.NewRecorder()
		s.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q status=%d, want 401", header, response.Code)
		}
	}
	for _, headers := range [][]string{
		{"Bearer " + testUploadToken, "Bearer wrong-token"},
		{"Bearer wrong-token", "Bearer " + testUploadToken},
		{"Bearer " + testUploadToken, "Bearer " + testUploadToken},
	} {
		req := httptest.NewRequest(http.MethodPut, "/v1/proofs/"+id, bytes.NewReader(data))
		for _, header := range headers {
			req.Header.Add("Authorization", header)
		}
		response := httptest.NewRecorder()
		s.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("duplicate Authorization values %q status=%d, want 401", headers, response.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPut, "/v1/proofs/"+id, bytes.NewReader(data))
	req.Header.Set("Authorization", "bearer "+testUploadToken)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("case-insensitive Bearer scheme status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPublicKeyStoreIsContentAddressedBySPKI(t *testing.T) {
	s, err := New(t.TempDir(), testUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := pemPublic(der)
	id, err := protocol.KeyID(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := hex.EncodeToString(id)
	req := httptest.NewRequest(http.MethodPut, "/v1/keys/"+fingerprint, bytes.NewReader(pubBytes))
	req.Header.Set("Authorization", "Bearer "+testUploadToken+"")
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusCreated {
		t.Fatalf("key upload status=%d body=%s", response.Code, response.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/keys/"+fingerprint, nil)
	response = httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), pubBytes) {
		t.Fatalf("key get status=%d", response.Code)
	}
	if _, err := os.Stat(filepath.Join(s.root, "keys", fingerprint)); err != nil {
		t.Fatal(err)
	}
}

func TestLookupReturnsSortedCandidatesAndMarksCandidateLimit(t *testing.T) {
	s, err := New(t.TempDir(), testUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const collidingPrefix = "00000000000000000000"
	for i := 0; i < CandidateLimit+1; i++ {
		id := collidingPrefix + fmt.Sprintf("%044x", i)
		path := filepath.Join(s.root, "proofs", id)
		if err := s.storage.write("proof", path, id, []byte(fmt.Sprintf("proof %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	token := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(make([]byte, 10))
	req := httptest.NewRequest(http.MethodGet, "/v1/lookup/"+token, nil)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	var result struct {
		Proofs    []string `json:"proofs"`
		Truncated bool     `json:"truncated"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !result.Truncated || len(result.Proofs) != CandidateLimit {
		t.Fatalf("lookup status=%d result=(%d candidates, truncated=%v)", response.Code, len(result.Proofs), result.Truncated)
	}
	for i, id := range result.Proofs {
		want := collidingPrefix + fmt.Sprintf("%044x", i)
		if id != want {
			t.Fatalf("candidate[%d]=%s, want %s", i, id, want)
		}
	}
}

func pemPublic(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
