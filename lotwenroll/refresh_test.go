package lotwenroll

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/tcarwash/arap/protocol"
)

func TestRefreshStatusRevalidatesAndCannotReviveDisabledBinding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(102), Subject: pkix.Name{
		ExtraNames: []pkix.AttributeTypeAndValue{{Type: tqslCallsignOID, Value: "N0CALL"}},
	}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	certID := sha256.Sum256(leaf.Raw)
	keyIDHex, certIDHex := hex.EncodeToString(keyID), hex.EncodeToString(certID[:])
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "enrollment.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	requestHash := sha256.Sum256([]byte("refresh test challenge"))
	if err := store.Issue(requestHash[:], "verifier", "N0CALL", keyIDHex, now.Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	binding := Binding{Callsign: "N0CALL", KeyID: keyIDHex, PublicKey: public,
		Purposes: []string{"challenge-response"}, CertificateSHA256: certIDHex,
		CertificateIssuer: leaf.Issuer.String(), CertificateExpiry: leaf.NotAfter.Unix(),
		VerifiedAt: now.Unix(), Status: StatusGood, StatusSource: "fixture-status", StatusObservedAt: now.Unix()}
	if accepted, err := store.Complete(requestHash[:], binding, now.Unix()); err != nil || !accepted {
		t.Fatalf("seed accepted binding: accepted=%v err=%v", accepted, err)
	}

	refreshAt := now.Add(2 * time.Hour)
	stale := RefreshStatus(RefreshConfig{Callsign: "N0CALL", KeyID: keyIDHex,
		CertificateChain: [][]byte{leafDER}, Roots: roots, Now: refreshAt,
		MaxStatusAge: time.Hour, Store: store,
		CertificateStatus: func(*x509.Certificate) StatusEvidence {
			return StatusEvidence{Status: StatusGood, Source: "fixture-status", ObservedAt: now}
		}})
	if stale.Accepted || stale.Reason != "certificate-status evidence is future-dated or stale" {
		t.Fatalf("stale status refresh result=%+v", stale)
	}
	result := RefreshStatus(RefreshConfig{Callsign: "N0CALL", KeyID: keyIDHex,
		CertificateChain: [][]byte{leafDER}, Roots: roots, Now: refreshAt,
		MaxStatusAge: time.Hour, Store: store,
		CertificateStatus: func(*x509.Certificate) StatusEvidence {
			return StatusEvidence{Status: StatusGood, Source: "fixture-status", ObservedAt: refreshAt}
		}})
	if !result.Accepted {
		t.Fatalf("fresh status refresh rejected: %+v", result)
	}
	if got := store.TrustStatus("N0CALL", keyIDHex, "challenge-response", refreshAt, time.Hour); got != "trusted" {
		t.Fatalf("refreshed binding status=%q, want trusted", got)
	}
	expiredAt := now.Add(25 * time.Hour)
	expired := RefreshStatus(RefreshConfig{Callsign: "N0CALL", KeyID: keyIDHex,
		CertificateChain: [][]byte{leafDER}, Roots: roots, Now: expiredAt,
		MaxStatusAge: time.Hour, Store: store,
		CertificateStatus: func(*x509.Certificate) StatusEvidence {
			return StatusEvidence{Status: StatusGood, Source: "fixture-status", ObservedAt: expiredAt}
		}})
	if expired.Accepted || expired.Reason != "callsign certificate chain validation failed" {
		t.Fatalf("expired certificate refresh result=%+v", expired)
	}
	if err := store.Disable("N0CALL", keyIDHex); err != nil {
		t.Fatal(err)
	}
	result = RefreshStatus(RefreshConfig{Callsign: "N0CALL", KeyID: keyIDHex,
		CertificateChain: [][]byte{leafDER}, Roots: roots, Now: refreshAt.Add(time.Minute),
		MaxStatusAge: time.Hour, Store: store,
		CertificateStatus: func(*x509.Certificate) StatusEvidence {
			return StatusEvidence{Status: StatusGood, Source: "fixture-status", ObservedAt: refreshAt.Add(time.Minute)}
		}})
	if result.Accepted || result.Reason != "disabled enrollment bindings cannot be refreshed" {
		t.Fatalf("disabled binding refresh result=%+v", result)
	}
	if got := store.TrustStatus("N0CALL", keyIDHex, "challenge-response", refreshAt.Add(time.Minute), time.Hour); got != "disabled" {
		t.Fatalf("disabled binding status=%q, want disabled", got)
	}
}
