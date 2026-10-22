package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func enrollmentRootPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if tqslDir := strings.TrimSpace(os.Getenv("TQSLDIR")); tqslDir != "" {
		return filepath.Join(tqslDir, "certs", "root"), nil
	}
	if runtime.GOOS == "windows" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("find TQSL configuration directory: %w", err)
		}
		return filepath.Join(configDir, "TrustedQSL", "certs", "root"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find TQSL configuration directory: %w", err)
	}
	return filepath.Join(home, ".tqsl", "certs", "root"), nil
}

func loadEnrollmentRoots(explicit string) (*x509.CertPool, string, error) {
	path, err := enrollmentRootPath(explicit)
	if err != nil {
		return nil, "", err
	}
	data, err := readFileBounded(path, 1024*1024)
	if err != nil {
		if explicit == "" && errors.Is(err, os.ErrNotExist) {
			return nil, path, fmt.Errorf("TQSL root bundle not found at %s; install/update TQSL or pass --roots PEM", path)
		}
		return nil, path, fmt.Errorf("read TQSL root bundle %s: %w", path, err)
	}
	roots, err := parseSelfSignedRoots(data)
	if err != nil {
		return nil, path, fmt.Errorf("load TQSL root bundle %s: %w", path, err)
	}
	return roots, path, nil
}

func parseSelfSignedRoots(bundle []byte) (*x509.CertPool, error) {
	if len(bundle) == 0 || len(bundle) > 1024*1024 {
		return nil, errors.New("bundle must be 1..1048576 bytes")
	}
	pool := x509.NewCertPool()
	remaining := bundle
	count := 0
	for len(bytes.TrimSpace(remaining)) > 0 {
		trimmed := bytes.TrimLeft(remaining, "\r\n\t ")
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("bundle contains non-certificate data")
		}
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("bundle must contain only PEM CERTIFICATE blocks")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse root certificate: %w", err)
		}
		if !cert.IsCA || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			return nil, errors.New("root bundle contains a non-root certificate")
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			return nil, fmt.Errorf("root certificate is not self-signed: %w", err)
		}
		pool.AddCert(cert)
		count++
		remaining = rest
	}
	if count == 0 {
		return nil, errors.New("bundle contains no root certificates")
	}
	return pool, nil
}
