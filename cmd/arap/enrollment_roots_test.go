package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentRootPathPriority(t *testing.T) {
	t.Setenv("TQSLDIR", filepath.Join("env", "tqsl"))

	got, err := enrollmentRootPath("explicit-roots.pem", filepath.Join("custom", "tqsl"))
	if err != nil || got != "explicit-roots.pem" {
		t.Fatalf("explicit root bundle should take precedence: path=%q err=%v", got, err)
	}

	got, err = enrollmentRootPath("", filepath.Join("custom", "tqsl"))
	want := filepath.Join("custom", "tqsl", "certs", "root")
	if err != nil || got != want {
		t.Fatalf("selected TQSL data directory root path = %q, want %q (err=%v)", got, want, err)
	}

	got, err = enrollmentRootPath("", "")
	want = filepath.Join("env", "tqsl", "certs", "root")
	if err != nil || got != want {
		t.Fatalf("TQSLDIR root path = %q, want %q (err=%v)", got, want, err)
	}
}

func TestResolveTQSLHelperReportsMissingExplicitPath(t *testing.T) {
	t.Setenv("ARAP_TQSL_HELPER", "")
	missing := filepath.Join(t.TempDir(), "missing-tqsl-helper")
	_, err := resolveTQSLHelper(missing)
	if err == nil || !strings.Contains(err.Error(), "TQSL native helper not found or not executable") {
		t.Fatalf("missing helper error = %v", err)
	}
}

func TestLoadEnrollmentRootsFromSelectedTQSLDirectory(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synthetic TQSL Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), "certs", "root")
	if err := os.MkdirAll(filepath.Dir(rootPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	pool, gotPath, err := loadEnrollmentRoots("", filepath.Dir(filepath.Dir(rootPath)))
	if err != nil {
		t.Fatalf("load custom TQSL root bundle: %v", err)
	}
	if gotPath != rootPath {
		t.Fatalf("loaded root path = %q, want %q", gotPath, rootPath)
	}
	if subjects := pool.Subjects(); len(subjects) != 1 {
		t.Fatalf("loaded root subjects = %d, want 1", len(subjects))
	}
}
