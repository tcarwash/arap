package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestParsePublicKeyRequiresSingleCleanPEMBlock(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	for _, input := range [][]byte{
		encoded,
		append(append([]byte(nil), encoded...), []byte("\n \t")...),
	} {
		if _, err := ParsePublicKey(input); err != nil {
			t.Fatalf("rejected valid single-block PEM: %v", err)
		}
	}
	if _, err := ParsePublicKey(der); err != nil {
		t.Fatalf("rejected valid SPKI DER: %v", err)
	}

	second := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	for name, input := range map[string][]byte{
		"leading prose": append([]byte("untrusted label\n"), encoded...),
		"second block":  append(append([]byte(nil), encoded...), second...),
		"trailing data": append(append([]byte(nil), encoded...), []byte("unexpected\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePublicKey(input); err == nil {
				t.Fatalf("accepted malformed public-key input %q", name)
			}
		})
	}
}

func TestLoadPrivateRejectsPEMWithLeadingProse(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	if err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	noisyPath := filepath.Join(dir, "private-with-prose.pem")
	if err := os.WriteFile(noisyPath, append([]byte("station key:\n"), data...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(noisyPath); err == nil {
		t.Fatal("accepted private-key PEM with leading prose")
	}
}

func TestLoadPrivateRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	if err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(privatePath); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("LoadPrivate error=%v, want actionable permissions error", err)
	}
	if err := os.Chmod(privatePath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(privatePath); err != nil {
		t.Fatalf("LoadPrivate rejected owner-only key: %v", err)
	}
}

func TestEncryptedPrivateKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	passphrase := []byte("correct horse battery staple")
	if err := GenerateEncryptedKeyPair(privatePath, publicPath, passphrase); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(privatePath); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("LoadPrivate error=%v, want passphrase required", err)
	}
	private, err := LoadPrivateWithPassphrase(privatePath, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	public, err := LoadPublic(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		t.Fatal("decrypted private key does not match generated public key")
	}
	if _, err := LoadPrivateWithPassphrase(privatePath, []byte("incorrect horse battery staple")); err == nil {
		t.Fatal("decrypted private key with an incorrect passphrase")
	}
	encoded, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(bytes.TrimSpace(encoded), []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		t.Fatal("generated private key is not in the armored age format")
	}
	altered := append([]byte(nil), encoded...)
	body := bytes.IndexByte(altered, '\n') + 1
	for body < len(altered) && (altered[body] == '\n' || altered[body] == '\r') {
		body++
	}
	if body >= len(altered) {
		t.Fatal("missing armored age body")
	}
	if altered[body] == 'A' {
		altered[body] = 'B'
	} else {
		altered[body] = 'A'
	}
	cases := map[string][]byte{
		"armored ciphertext": altered,
		"trailing data":      append(append([]byte(nil), encoded...), []byte("unexpected\n")...),
	}
	for name, changed := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "damaged.age")
			if err := os.WriteFile(path, changed, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadPrivateWithPassphrase(path, passphrase); err == nil {
				t.Fatal("accepted altered encrypted key")
			}
		})
	}
	if _, err := EncryptPrivate(private, []byte("short")); err == nil {
		t.Fatal("encrypted private key with a short passphrase")
	}
}

func FuzzParsePublicKey(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	f.Add(der)
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("leading prose -----BEGIN PUBLIC KEY-----"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1024*1024 {
			return
		}
		_, _ = ParsePublicKey(data)
	})
}

func TestWriteExclusivePublishesOneCompleteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proof.cose")
	const workers = 12
	payloads := make([][]byte, workers)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte(i + 1)}, 64*1024)
	}
	var wait sync.WaitGroup
	var mutex sync.Mutex
	successes := 0
	for i := range payloads {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			err := WriteExclusive(path, payloads[index], 0600)
			mutex.Lock()
			defer mutex.Unlock()
			if err == nil {
				successes++
			} else if !errors.Is(err, os.ErrExist) {
				t.Errorf("write %d failed unexpectedly: %v", index, err)
			}
		}(i)
	}
	wait.Wait()
	if successes != 1 {
		t.Fatalf("successful creates=%d, want exactly one", successes)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	complete := false
	for _, payload := range payloads {
		if bytes.Equal(got, payload) {
			complete = true
			break
		}
	}
	if !complete {
		t.Fatal("published file is not one complete writer payload")
	}
	if err := WriteExclusive(path, []byte("replacement"), 0600); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second write error=%v, want file-exists", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("temporary output was not cleaned up: %#v", entries)
	}
}

func TestGenerateKeyPairWritesPrivateAndPublicFiles(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "station-private.pem")
	publicPath := filepath.Join(dir, "station-public.pem")
	if err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	private, err := LoadPrivate(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	public, err := LoadPublic(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		t.Fatal("generated public and private key files do not match")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(privatePath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Fatalf("private key mode=%#o, want 0600", got)
		}
	}
	if err := GenerateKeyPair(privatePath, publicPath); !errors.Is(err, os.ErrExist) {
		t.Fatalf("keygen overwrite error=%v, want file-exists", err)
	}
	if _, err := os.Stat(privatePath); err != nil {
		t.Fatalf("existing private key was removed after overwrite refusal: %v", err)
	}
	if _, err := os.Stat(publicPath); err != nil {
		t.Fatalf("existing public key was removed after overwrite refusal: %v", err)
	}
}

func TestWriteKeyPairRemovesNewPrivateFileWhenPublicCreationFails(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	if err := os.WriteFile(publicPath, []byte("existing public file"), 0600); err != nil {
		t.Fatal(err)
	}
	err := GenerateKeyPair(privatePath, publicPath)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("key generation error=%v, want file-exists", err)
	}
	if _, err := os.Stat(privatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private file after failed pair creation: %v", err)
	}
	data, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing public file" {
		t.Fatalf("existing public file was changed: %q", data)
	}
}
