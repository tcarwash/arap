package lotwenroll

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/tcarwash/arap/protocol"
)

type testSigner struct{ key *rsa.PrivateKey }

func (s testSigner) SignEnrollmentChallenge(data []byte) ([]byte, error) {
	digest := sha1.Sum(data)
	return rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA1, digest[:])
}

type testStore struct {
	issued, consumed bool
	binding          Binding
}

func (s *testStore) Issue([]byte, string, string, string, int64) error { s.issued = true; return nil }
func (s *testStore) Complete(_ []byte, binding Binding, _ int64) (bool, error) {
	if !s.issued || s.consumed {
		return false, nil
	}
	s.consumed = true
	s.binding = binding
	return true, nil
}

func TestEnrollmentRoundTripAndReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tqslKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ARAP test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "N0CALL"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootTmpl, &tqslKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	_, encoded, err := New("https://verifier.example", "N0CALL", edPub, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response, err := Respond(encoded, edKey, testSigner{tqslKey}, [][]byte{leafDER})
	if err != nil {
		t.Fatal(err)
	}
	store := &testStore{}
	if err := Issue(encoded, store); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(mustCert(t, rootDER))
	config := VerifyConfig{Audience: "https://verifier.example", Roots: roots, Now: now, CallsignFromCert: func(c *x509.Certificate) (string, error) { return c.Subject.CommonName, nil }, CertificateStatus: func(*x509.Certificate) StatusEvidence {
		return StatusEvidence{Status: StatusGood, Source: "synthetic-test-ca-status", ObservedAt: now}
	}, MaxStatusAge: time.Hour, Store: store}
	staleStore := &testStore{}
	if err := Issue(encoded, staleStore); err != nil {
		t.Fatal(err)
	}
	staleConfig := config
	staleConfig.Store = staleStore
	staleConfig.CertificateStatus = func(*x509.Certificate) StatusEvidence {
		return StatusEvidence{Status: StatusGood, Source: "synthetic-test-ca-status", ObservedAt: now.Add(-2 * time.Hour)}
	}
	if result := Verify(response, staleConfig); result.Accepted || result.Reason != "certificate-status evidence is future-dated or stale" {
		t.Fatalf("stale certificate status was not rejected: %+v", result)
	}
	badSigStore := &testStore{}
	if err := Issue(encoded, badSigStore); err != nil {
		t.Fatal(err)
	}
	badSig := response
	badSig.TQSL = append([]byte(nil), response.TQSL...)
	badSig.TQSL[0] ^= 1
	badSigConfig := config
	badSigConfig.Store = badSigStore
	if result := Verify(badSig, badSigConfig); result.Accepted || result.Reason != "TQSL RSA-SHA1 challenge signature is invalid" {
		t.Fatalf("altered TQSL signature was not rejected: %+v", result)
	}
	got := Verify(response, config)
	if !got.Accepted || !got.LegacySignatureValid || got.Callsign != "N0CALL" {
		t.Fatalf("enrollment rejected: %+v", got)
	}
	if store.binding.Callsign != "N0CALL" || store.binding.KeyID != got.KeyID || store.binding.Status != StatusGood || store.binding.Disabled {
		t.Fatalf("verified binding was not persisted correctly: %+v", store.binding)
	}
	if replay := Verify(response, config); replay.Accepted {
		t.Fatalf("accepted replay: %+v", replay)
	}

	// Version 2 explicitly binds requested identity purposes into the challenge.
	v2Challenge, v2Encoded, err := NewWithPurposes("https://verifier.example", "N0CALL", edPub,
		[]string{PurposeContentSignature, PurposeChallengeResponse}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	v2Response, err := Respond(v2Encoded, edKey, testSigner{tqslKey}, [][]byte{leafDER})
	if err != nil {
		t.Fatal(err)
	}
	v2Store, err := OpenSQLite(filepath.Join(t.TempDir(), "v2-enrollment.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer v2Store.Close()
	if err := Issue(v2Encoded, v2Store); err != nil {
		t.Fatal(err)
	}
	v2Config := config
	v2Config.Store = v2Store
	if rejected := Verify(v2Response, v2Config); rejected.Accepted || rejected.Reason != "enrollment purpose is not allowed by verifier policy" {
		t.Fatalf("version 2 purposes were accepted without explicit verifier policy: %+v", rejected)
	}
	v2Config.AllowedPurposes = []string{PurposeContentSignature, PurposeChallengeResponse}
	if accepted := Verify(v2Response, v2Config); !accepted.Accepted {
		t.Fatalf("version 2 purposes rejected under explicit policy: %+v", accepted)
	}
	if got := v2Store.TrustStatus("N0CALL", hex.EncodeToString(v2Challenge.KeyID[:]), PurposeContentSignature, now, time.Hour); got != "trusted" {
		t.Fatalf("explicitly enrolled content purpose status=%q, want trusted", got)
	}
	if got := v2Store.TrustStatus("N0CALL", hex.EncodeToString(v2Challenge.KeyID[:]), "key-endorsement", now, time.Hour); got != "untrusted" {
		t.Fatalf("unrequested purpose status=%q, want untrusted", got)
	}
	content := []byte("explicitly authorized LoTW-enrolled content")
	signer, err := protocol.NewEd25519Signer("N0CALL", edKey)
	if err != nil {
		t.Fatal(err)
	}
	contentProof, _, err := protocol.SignContent(signer, bytes.NewReader(content), protocol.ContentMetadata{
		MediaType: "text/plain", Context: "enrollment/content-test/v1",
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	contentVerifier, err := protocol.NewEd25519Verifier(edPub)
	if err != nil {
		t.Fatal(err)
	}
	contentResult := protocol.VerifyContentWithTrust(contentProof, bytes.NewReader(content), contentVerifier,
		protocol.Expected{Purpose: protocol.PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "enrollment/content-test/v1", Callsign: "N0CALL"},
		func(call, id, purpose string) string { return v2Store.TrustStatus(call, id, purpose, now, time.Hour) }, now)
	if contentResult.OverallPolicy != "accepted" {
		t.Fatalf("explicitly enrolled content signature rejected: %+v", contentResult)
	}
}

func TestEnrollmentPolicyGateAndWrongAudience(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, encoded, err := New("https://expected.example", "N0CALL", pub, time.Unix(1_800_000_000, 0), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatal(err)
	}
	store := &testStore{}
	config := VerifyConfig{Audience: "https://wrong.example", Roots: x509.NewCertPool(), CallsignFromCert: func(*x509.Certificate) (string, error) { return "N0CALL", nil }, Store: store}
	if result := Verify(Response{Challenge: encoded}, config); result.Accepted || result.Reason != "challenge audience mismatch" {
		t.Fatalf("wrong audience was not rejected: %+v", result)
	}
	config = VerifyConfig{Audience: "https://expected.example", Roots: x509.NewCertPool(), CallsignFromCert: func(*x509.Certificate) (string, error) { return "N0CALL", nil }, Store: store}
	if result := Verify(Response{Challenge: encoded}, config); result.Accepted || result.Reason != "challenge audience mismatch" {
		t.Fatalf("audience policy did not fail closed: %+v", result)
	}
}

func TestEnrollmentResponseCanonicalCBORRoundTrip(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, encodedChallenge, err := New("https://verifier.example", "N0CALL", public, time.Unix(1_800_000_000, 0), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response := Response{Challenge: encodedChallenge, Chain: [][]byte{{1, 2, 3}}, PublicKey: public, TQSL: []byte{4, 5}, Ed25519: make([]byte, ed25519.SignatureSize)}
	encoded, err := EncodeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResponse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Challenge, response.Challenge) || !bytes.Equal(decoded.Chain[0], response.Chain[0]) || !bytes.Equal(decoded.PublicKey, response.PublicKey) || !bytes.Equal(decoded.TQSL, response.TQSL) || !bytes.Equal(decoded.Ed25519, response.Ed25519) {
		t.Fatal("decoded enrollment response differs from input")
	}
	if _, err := DecodeResponse(append(encoded, 0)); err == nil {
		t.Fatal("accepted trailing data after enrollment response")
	}
}

func TestTQSLCallsignAttributeExtraction(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	base := &x509.Certificate{SerialNumber: big.NewInt(44), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	for _, tc := range []struct {
		name      string
		extra     []pkix.AttributeTypeAndValue
		want      string
		wantError bool
	}{
		{name: "official TQSL callsign OID", extra: []pkix.AttributeTypeAndValue{{Type: tqslCallsignOID, Value: "N0CALL"}}, want: "N0CALL"},
		{name: "common name alone is not enough", wantError: true},
		{name: "duplicate callsign OID", extra: []pkix.AttributeTypeAndValue{{Type: tqslCallsignOID, Value: "N0CALL"}, {Type: tqslCallsignOID, Value: "K1ABC"}}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := *base
			template.Subject = pkix.Name{CommonName: "N0CALL", ExtraNames: tc.extra}
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			got, err := CallsignFromCertificate(cert)
			if tc.wantError {
				if err == nil {
					t.Fatalf("accepted callsign %q", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("callsign=%q err=%v, want %q", got, err, tc.want)
			}
		})
	}
}

func mustCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
