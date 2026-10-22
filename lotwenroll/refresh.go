package lotwenroll

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/tcarwash/arap/protocol"
)

// StatusRefreshStore is implemented by SQLiteStore and can be implemented by
// application-owned storage. The implementation must refuse to update a
// disabled binding.
type StatusRefreshStore interface {
	Bindings() ([]Binding, error)
	RefreshStatus(callsign, keyID, certificateSHA256 string, evidence StatusEvidence, now time.Time, maxAge time.Duration) (bool, error)
}

type RefreshResult struct {
	Accepted          bool   `json:"accepted"`
	Callsign          string `json:"callsign,omitempty"`
	KeyID             string `json:"key_id_sha256,omitempty"`
	CertificateSHA256 string `json:"certificate_sha256,omitempty"`
	CertificateStatus Status `json:"certificate_status"`
	StatusSource      string `json:"status_source,omitempty"`
	StatusObservedAt  int64  `json:"status_observed_at,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

type RefreshConfig struct {
	Callsign          string
	KeyID             string
	CertificateChain  [][]byte // leaf first, then issuer certificates; root is supplied separately
	Roots             *x509.CertPool
	Now               time.Time
	CallsignFromCert  func(*x509.Certificate) (string, error)
	MaxStatusAge      time.Duration
	CertificateStatus func(*x509.Certificate) StatusEvidence
	Store             StatusRefreshStore
}

// RefreshStatus revalidates the saved enrollment certificate chain and obtains
// fresh status evidence before updating an existing local binding. It never
// changes the key, certificate fingerprint, purposes, or disabled state.
func RefreshStatus(config RefreshConfig) RefreshResult {
	result := RefreshResult{CertificateStatus: StatusUnknown}
	fail := func(reason string) RefreshResult { result.Reason = reason; return result }
	if config.Store == nil || config.Roots == nil || config.CertificateStatus == nil || config.MaxStatusAge <= 0 {
		return fail("certificate roots, status provider, store and maximum evidence age are required")
	}
	now := config.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	call, err := protocol.NormalizeCallsign(config.Callsign)
	if err != nil || call != config.Callsign {
		return fail("callsign must be normalized")
	}
	keyID, err := hex.DecodeString(config.KeyID)
	if err != nil || len(keyID) != 32 || hex.EncodeToString(keyID) != config.KeyID {
		return fail("key fingerprint must be lowercase SHA-256 hex")
	}
	if len(config.CertificateChain) == 0 || len(config.CertificateChain) > 8 {
		return fail("certificate chain must contain 1..8 certificates")
	}
	var leaf *x509.Certificate
	intermediates := x509.NewCertPool()
	chainSize := 0
	for i, der := range config.CertificateChain {
		chainSize += len(der)
		if len(der) == 0 || chainSize > MaxChainBytes {
			return fail("certificate chain is empty or too large")
		}
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			return fail("malformed certificate chain")
		}
		if i == 0 {
			leaf = cert
		} else {
			intermediates.AddCert(cert)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: config.Roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fail("callsign certificate chain validation failed")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fail("callsign certificate does not permit digital signatures")
	}
	rsaKey, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || rsaKey.N.BitLen() < 1024 {
		return fail("TQSL enrollment certificate must contain an RSA key of at least 1024 bits")
	}
	callsignFromCert := config.CallsignFromCert
	if callsignFromCert == nil {
		callsignFromCert = CallsignFromCertificate
	}
	certificateCall, err := callsignFromCert(leaf)
	if err != nil || certificateCall != call {
		return fail("certificate callsign does not match enrollment binding")
	}
	certHash := sha256.Sum256(leaf.Raw)
	certID := hex.EncodeToString(certHash[:])
	result.Callsign, result.KeyID, result.CertificateSHA256 = call, config.KeyID, certID
	bindings, err := config.Store.Bindings()
	if err != nil {
		return fail(fmt.Sprintf("read enrollment binding: %v", err))
	}
	found := false
	for _, binding := range bindings {
		if binding.Callsign == call && binding.KeyID == config.KeyID && binding.CertificateSHA256 == certID {
			found = true
			if binding.Disabled {
				return fail("disabled enrollment bindings cannot be refreshed")
			}
			if binding.CertificateIssuer != leaf.Issuer.String() || binding.CertificateExpiry != leaf.NotAfter.UTC().Unix() {
				return fail("certificate metadata does not match the accepted enrollment binding")
			}
			break
		}
	}
	if !found {
		return fail("certificate does not match an existing enrollment binding")
	}
	evidence := config.CertificateStatus(leaf)
	result.CertificateStatus, result.StatusSource = evidence.Status, evidence.Source
	if !evidence.ObservedAt.IsZero() {
		result.StatusObservedAt = evidence.ObservedAt.UTC().Unix()
	}
	if evidence.Status != StatusGood || evidence.Source == "" || evidence.ObservedAt.IsZero() {
		return fail("certificate status is not known good with timestamped evidence")
	}
	updated, err := config.Store.RefreshStatus(call, config.KeyID, certID, evidence, now, config.MaxStatusAge)
	if err != nil {
		return fail(err.Error())
	}
	if !updated {
		return fail("binding is missing, disabled, expired or has a different certificate")
	}
	result.Accepted = true
	result.Reason = "certificate chain and fresh status revalidated; enrollment binding unchanged"
	return result
}
