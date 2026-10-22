package keyserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func proofID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func putProof(t *testing.T, s *Server, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/v1/proofs/"+proofID(data), bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+testUploadToken)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	return response
}

func TestQuotaPersistsAcrossRestartAndAllowsIdempotentPut(t *testing.T) {
	root := t.TempDir()
	options := DefaultOptions()
	options.MaxProofObjects = 1
	options.MaxTotalBytes = 128
	s, err := NewWithOptions(root, testUploadToken, options)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("proof one")
	if got := putProof(t, s, first).Code; got != http.StatusCreated {
		t.Fatalf("first upload status=%d", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewWithOptions(root, testUploadToken, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := putProof(t, s, first).Code; got != http.StatusCreated {
		t.Fatalf("idempotent upload status=%d", got)
	}
	if got := putProof(t, s, []byte("proof two")).Code; got != http.StatusInsufficientStorage {
		t.Fatalf("over-quota upload status=%d", got)
	}
	proofs, keys, size, err := s.storage.usage()
	if err != nil || proofs != 1 || keys != 0 || size != int64(len(first)) {
		t.Fatalf("usage=(%d,%d,%d), err=%v", proofs, keys, size, err)
	}
}

func TestNewWithOptionsRejectsNegativeLimits(t *testing.T) {
	options := DefaultOptions()
	options.MaxKeyObjects = -1
	if _, err := NewWithOptions(t.TempDir(), testUploadToken, options); err == nil {
		t.Fatal("negative key quota was accepted")
	}
}

func TestKeyObjectQuota(t *testing.T) {
	options := DefaultOptions()
	options.MaxKeyObjects = 1
	s, err := NewWithOptions(t.TempDir(), testUploadToken, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	firstID := fmt.Sprintf("%064x", 1)
	if err := s.storage.write("key", s.root+"/keys/"+firstID, firstID, []byte("public key one")); err != nil {
		t.Fatal(err)
	}
	secondID := fmt.Sprintf("%064x", 2)
	err = s.storage.write("key", s.root+"/keys/"+secondID, secondID, []byte("public key two"))
	if err != errQuotaExceeded {
		t.Fatalf("second key error=%v, want quota exceeded", err)
	}
	_, keys, _, err := s.storage.usage()
	if err != nil || keys != 1 {
		t.Fatalf("key count=%d, err=%v", keys, err)
	}
}

func TestConcurrentWritesCannotExceedObjectQuota(t *testing.T) {
	options := DefaultOptions()
	options.MaxProofObjects = 3
	options.MaxTotalBytes = 1 << 20
	s, err := NewWithOptions(t.TempDir(), testUploadToken, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	const writers = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for i := 0; i < writers; i++ {
		data := []byte(fmt.Sprintf("proof %02d", i))
		id := proofID(data)
		path := s.root + "/proofs/" + id
		wg.Add(1)
		go func(id, path string, data []byte) {
			defer wg.Done()
			if err := s.storage.write("proof", path, id, data); err == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			} else if err != errQuotaExceeded {
				t.Errorf("write: %v", err)
			}
		}(id, path, data)
	}
	wg.Wait()
	proofs, _, _, err := s.storage.usage()
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 3 || proofs != 3 {
		t.Fatalf("accepted=%d indexed proofs=%d, want both 3", accepted, proofs)
	}
}

func TestConcurrentIdempotentWritesKeepObjectIndexed(t *testing.T) {
	s, err := New(t.TempDir(), testUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	data := []byte("identical immutable proof")
	id := proofID(data)
	path := filepath.Join(s.root, "proofs", id)
	const writers = 16
	var wait sync.WaitGroup
	errorsFound := make(chan error, writers)
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsFound <- s.storage.write("proof", path, id, data)
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("idempotent concurrent write failed: %v", err)
		}
	}
	proofs, _, size, err := s.storage.usage()
	if err != nil || proofs != 1 || size != int64(len(data)) {
		t.Fatalf("usage=(%d,%d), err=%v", proofs, size, err)
	}
	got, err := s.storage.read("proof", path, id)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("indexed object read=(%q,%v)", got, err)
	}
}

func TestTotalByteQuotaIsSharedByProofsAndKeys(t *testing.T) {
	options := DefaultOptions()
	options.MaxTotalBytes = 10
	s, err := NewWithOptions(t.TempDir(), testUploadToken, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	proof := []byte("1234567")
	proofHash := proofID(proof)
	if err := s.storage.write("proof", s.root+"/proofs/"+proofHash, proofHash, proof); err != nil {
		t.Fatal(err)
	}
	keyID := fmt.Sprintf("%064x", 1)
	err = s.storage.write("key", s.root+"/keys/"+keyID, keyID, []byte("1234"))
	if err != errQuotaExceeded {
		t.Fatalf("cross-kind byte limit error=%v, want quota exceeded", err)
	}
	proofs, keys, size, err := s.storage.usage()
	if err != nil || proofs != 1 || keys != 0 || size != int64(len(proof)) {
		t.Fatalf("usage=(%d,%d,%d), err=%v", proofs, keys, size, err)
	}
}

func TestUploadRateLimitAndWindowReset(t *testing.T) {
	options := DefaultOptions()
	options.MaxUploadsPerMinute = 1
	s, err := NewWithOptions(t.TempDir(), testUploadToken, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Unix(1_800_000_000, 0)
	if ok, err := s.storage.allowUpload(now); err != nil || !ok {
		t.Fatalf("first upload allowed=%v err=%v", ok, err)
	}
	if ok, err := s.storage.allowUpload(now.Add(30 * time.Second)); err != nil || ok {
		t.Fatalf("second upload allowed=%v err=%v, want rejected", ok, err)
	}
	if ok, err := s.storage.allowUpload(now.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("next-window upload allowed=%v err=%v", ok, err)
	}
}

func TestHTTPUploadRateLimitReturns429(t *testing.T) {
	options := DefaultOptions()
	options.MaxUploadsPerMinute = 1
	s, err := NewWithOptions(t.TempDir(), testUploadToken, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := putProof(t, s, []byte("accepted")).Code; got != http.StatusCreated {
		t.Fatalf("first upload status=%d", got)
	}
	response := putProof(t, s, []byte("rate limited"))
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "60" {
		t.Fatalf("second upload status=%d Retry-After=%q", response.Code, response.Header().Get("Retry-After"))
	}
}

func TestRetentionRemovesExpiredObjectsAndReleasesQuota(t *testing.T) {
	options := DefaultOptions()
	options.Retention = time.Hour
	s, err := NewWithOptions(t.TempDir(), testUploadToken, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	data := []byte("short lived proof")
	id := proofID(data)
	path := s.root + "/proofs/" + id
	if err := s.storage.write("proof", path, id, data); err != nil {
		t.Fatal(err)
	}
	if _, err := s.storage.db.Exec(`UPDATE objects SET created_at=? WHERE kind='proof' AND id=?`, time.Now().Add(-2*time.Hour).Unix(), id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.storage.read("proof", path, id); err == nil {
		t.Fatal("expired proof remained readable")
	}
	proofs, _, size, err := s.storage.usage()
	if err != nil || proofs != 0 || size != 0 {
		t.Fatalf("usage after expiry=(%d,%d), err=%v", proofs, size, err)
	}
}

func TestConcurrentRetentionPruneAndRewritePreservesReplacement(t *testing.T) {
	options := DefaultOptions()
	options.Retention = time.Hour
	s, err := NewWithOptions(t.TempDir(), testUploadToken, options)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	data := []byte("immutable proof restored after retention")
	id := proofID(data)
	path := filepath.Join(s.root, "proofs", id)
	for i := 0; i < 40; i++ {
		if err := s.storage.write("proof", path, id, data); err != nil {
			t.Fatal(err)
		}
		if _, err := s.storage.db.Exec(`UPDATE objects SET created_at=? WHERE kind='proof' AND id=?`, time.Now().Add(-2*time.Hour).Unix(), id); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wait sync.WaitGroup
		var pruneErr, writeErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			pruneErr = s.storage.prune(time.Now())
		}()
		go func() {
			defer wait.Done()
			<-start
			writeErr = s.storage.write("proof", path, id, data)
		}()
		close(start)
		wait.Wait()
		if pruneErr != nil || writeErr != nil {
			t.Fatalf("prune error=%v rewrite error=%v", pruneErr, writeErr)
		}
		got, err := s.storage.read("proof", path, id)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("replacement missing after concurrent prune: bytes=%q err=%v", got, err)
		}
	}
}
