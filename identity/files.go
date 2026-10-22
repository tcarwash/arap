package identity

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

func WriteKeyPair(privatePath, publicPath string, private ed25519.PrivateKey) error {
	if privatePath == publicPath {
		return fmt.Errorf("private and public key paths must differ")
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return err
	}
	if err := WriteExclusive(privatePath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		return err
	}
	if err := WriteExclusive(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}

func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	return LoadPrivateWithPassphrase(path, nil)
}

func checkPrivateFileMode(f *os.File, path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("private key file permissions are too broad; restrict it to owner-only mode 0600 (for example: chmod 600 %s)", path)
	}
	return nil
}

func LoadPublic(path string) (ed25519.PublicKey, error) {
	key, err := LoadPublicKey(path)
	if err != nil {
		return nil, err
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return public, nil
}

// LoadPublicKey reads one SubjectPublicKeyInfo PEM block or one X.509
// certificate and returns its public key. It is for fingerprinting and
// untrusted keyserver transport; proof verification still allowlists Ed25519.
func LoadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := readBounded(path, 1024*1024)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(data)
}

// ParsePublicKey accepts one SPKI DER value, one PUBLIC KEY PEM block, or one
// X.509 CERTIFICATE PEM block. PEM input must not contain leading prose,
// additional blocks, or non-whitespace trailing data.
func ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	if len(data) == 0 || len(data) > 1024*1024 {
		return nil, fmt.Errorf("public key input must be 1..1048576 bytes")
	}
	block, err := decodeOnePEMBlock(data)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return x509.ParsePKIXPublicKey(data)
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return certificate.PublicKey, nil
	default:
		return nil, fmt.Errorf("expected one PUBLIC KEY or CERTIFICATE PEM block")
	}
}

func decodeOnePEMBlock(data []byte) (*pem.Block, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, nil
	}
	const begin = "-----BEGIN "
	if !bytes.HasPrefix(trimmed, []byte(begin)) {
		return nil, nil
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, fmt.Errorf("malformed PEM block")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("trailing PEM data")
	}
	return block, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d byte limit", path, limit)
	}
	return data, nil
}

func WriteExclusive(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".arap-write-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	if directory, err := os.Open(dir); err == nil {
		defer directory.Close()
		_ = directory.Sync()
	}
	return nil
}

func GenerateKeyPair(privatePath, publicPath string) error {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return WriteKeyPair(privatePath, publicPath, private)
}
