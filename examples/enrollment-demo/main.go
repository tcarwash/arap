// Command enrollment-demo provides synthetic TQSL certificate generation and
// a test-only verifier with injectable certificate-status evidence. It must
// never be used with real station credentials or against the live status API.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tcarwash/arap/lotwenroll"
)

var callsignOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12348, 1, 1}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: enrollment-demo generate|verify [options]"))
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = generate(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "negatives":
		err = negatives(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func generate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	out := fs.String("out", "", "directory for generated synthetic credentials")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("--out is required")
	}
	if err := os.MkdirAll(*out, 0700); err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	intermediateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rootTemplate := caTemplate(1, "ARAP Synthetic Demo Root", now)
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}
	intermediateTemplate := caTemplate(2, "ARAP Synthetic Demo Intermediate", now)
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		return err
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(424242),
		Subject: pkix.Name{
			CommonName: "N0CALL",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: callsignOID, Value: "N0CALL"}},
		},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: false,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*out, "root.pem"), "CERTIFICATE", rootDER, 0644); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*out, "intermediate.pem"), "CERTIFICATE", intermediateDER, 0644); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*out, "leaf.pem"), "CERTIFICATE", leafDER, 0644); err != nil {
		return err
	}
	expiredTemplate := *leafTemplate
	expiredTemplate.SerialNumber = big.NewInt(424243)
	expiredTemplate.NotBefore = now.Add(-48 * time.Hour)
	expiredTemplate.NotAfter = now.Add(-24 * time.Hour)
	expiredDER, err := x509.CreateCertificate(rand.Reader, &expiredTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*out, "leaf-expired.pem"), "CERTIFICATE", expiredDER, 0644); err != nil {
		return err
	}
	leafPrivatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(leafKey)})
	leafPublicDER, err := x509.MarshalPKIXPublicKey(&leafKey.PublicKey)
	if err != nil {
		return err
	}
	leafPublicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: leafPublicDER})
	keyRecord := adif("PRIVATE_KEY", leafPrivatePEM) + adif("PUBLIC_KEY", leafPublicPEM) + "<eor>\n"
	if err := os.WriteFile(filepath.Join(*out, "keybuf.b64"), []byte(wrapBase64(base64.StdEncoding.EncodeToString([]byte(keyRecord)))), 0600); err != nil {
		return err
	}
	fmt.Println("generated synthetic N0CALL root/intermediate/callsign certificates and key record")
	return nil
}

func caTemplate(serial int64, name string, now time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
}

func adif(name string, value []byte) string {
	return fmt.Sprintf("<%s:%d>%s", name, len(value), value)
}

func wrapBase64(value string) string {
	var wrapped strings.Builder
	for len(value) > 64 {
		wrapped.WriteString(value[:64])
		wrapped.WriteByte('\n')
		value = value[64:]
	}
	if value != "" {
		wrapped.WriteString(value)
		wrapped.WriteByte('\n')
	}
	return wrapped.String()
}

func mustPKCS8(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return der
}

func writePEM(path, kind string, der []byte, mode os.FileMode) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), mode)
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	responsePath := fs.String("response", "", "encoded enrollment response")
	rootPath := fs.String("root", "", "synthetic root certificate PEM")
	storePath := fs.String("store", "", "issuer-side enrollment SQLite database")
	audience := fs.String("audience", "", "expected challenge audience")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *responsePath == "" || *rootPath == "" || *storePath == "" || *audience == "" {
		return errors.New("--response, --root, --store and --audience are required")
	}
	response, err := os.ReadFile(*responsePath)
	if err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(*rootPath)
	if err != nil {
		return err
	}
	rootBlock, _ := pem.Decode(rootPEM)
	if rootBlock == nil || rootBlock.Type != "CERTIFICATE" {
		return errors.New("synthetic root file is not a certificate PEM")
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	store, err := lotwenroll.OpenSQLite(*storePath)
	if err != nil {
		return err
	}
	defer store.Close()
	now := time.Now().UTC()
	result := lotwenroll.VerifyEncoded(response, lotwenroll.VerifyConfig{
		Audience: *audience, Roots: roots, Now: now,
		CallsignFromCert: lotwenroll.CallsignFromCertificate,
		CertificateStatus: func(*x509.Certificate) lotwenroll.StatusEvidence {
			return lotwenroll.StatusEvidence{Status: lotwenroll.StatusGood, Source: "synthetic-demo-only", ObservedAt: now}
		},
		MaxStatusAge: time.Hour, Store: store,
		AllowedPurposes: []string{lotwenroll.PurposeChallengeResponse, lotwenroll.PurposeContentSignature},
	})
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if !result.Accepted {
		return fmt.Errorf("synthetic enrollment rejected: %s", result.Reason)
	}
	return nil
}

type rejectStore struct{}

func (rejectStore) Issue([]byte, string, string, string, int64) error { return nil }
func (rejectStore) Complete([]byte, lotwenroll.Binding, int64) (bool, error) {
	return false, nil
}

func negatives(args []string) error {
	fs := flag.NewFlagSet("negatives", flag.ContinueOnError)
	responsePath := fs.String("response", "", "encoded valid enrollment response")
	rootPath := fs.String("root", "", "synthetic root certificate PEM")
	expiredPath := fs.String("expired-leaf", "", "expired synthetic callsign certificate PEM")
	audience := fs.String("audience", "", "expected challenge audience")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *responsePath == "" || *rootPath == "" || *expiredPath == "" || *audience == "" {
		return errors.New("--response, --root, --expired-leaf and --audience are required")
	}
	encoded, err := os.ReadFile(*responsePath)
	if err != nil {
		return err
	}
	original, err := lotwenroll.DecodeResponse(encoded)
	if err != nil {
		return err
	}
	rootPEM, err := os.ReadFile(*rootPath)
	if err != nil {
		return err
	}
	rootBlock, _ := pem.Decode(rootPEM)
	if rootBlock == nil || rootBlock.Type != "CERTIFICATE" {
		return errors.New("synthetic root file is not a certificate PEM")
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	now := time.Now().UTC()
	base := lotwenroll.VerifyConfig{
		Audience: *audience, Roots: roots, Now: now,
		CallsignFromCert: lotwenroll.CallsignFromCertificate,
		CertificateStatus: func(*x509.Certificate) lotwenroll.StatusEvidence {
			return lotwenroll.StatusEvidence{Status: lotwenroll.StatusGood, Source: "synthetic-demo-only", ObservedAt: now}
		},
		MaxStatusAge: time.Hour, Store: rejectStore{},
		AllowedPurposes: []string{lotwenroll.PurposeChallengeResponse, lotwenroll.PurposeContentSignature},
	}
	check := func(name, want string, response lotwenroll.Response, config lotwenroll.VerifyConfig) error {
		encodedResponse, err := lotwenroll.EncodeResponse(response)
		if err != nil {
			return fmt.Errorf("%s fixture: %w", name, err)
		}
		result := lotwenroll.VerifyEncoded(encodedResponse, config)
		if result.Accepted || !contains(result.Reason, want) {
			return fmt.Errorf("%s expected rejection containing %q; got accepted=%t reason=%q", name, want, result.Accepted, result.Reason)
		}
		fmt.Printf("EXPECTED_REJECTION %s: %s\n", name, result.Reason)
		return nil
	}
	clone := func() lotwenroll.Response {
		copy := original
		copy.Challenge = append([]byte(nil), original.Challenge...)
		copy.Chain = make([][]byte, len(original.Chain))
		for i := range original.Chain {
			copy.Chain[i] = append([]byte(nil), original.Chain[i]...)
		}
		copy.PublicKey = append([]byte(nil), original.PublicKey...)
		copy.TQSL = append([]byte(nil), original.TQSL...)
		copy.Ed25519 = append([]byte(nil), original.Ed25519...)
		return copy
	}
	if err := check("wrong-audience", "audience mismatch", clone(), withAudience(base, "different-audience")); err != nil {
		return err
	}
	wrongKey := clone()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	wrongKey.PublicKey = public
	if err := check("wrong-key", "fingerprint or challenge signature", wrongKey, base); err != nil {
		return err
	}
	wrongCall := clone()
	challenge, err := lotwenroll.Decode(wrongCall.Challenge)
	if err != nil {
		return err
	}
	challenge.Callsign = "K7WRONG"
	wrongCall.Challenge, err = lotwenroll.Encode(challenge)
	if err != nil {
		return err
	}
	if err := check("wrong-callsign", "certificate callsign does not match", wrongCall, base); err != nil {
		return err
	}
	changed := clone()
	challenge, err = lotwenroll.Decode(changed.Challenge)
	if err != nil {
		return err
	}
	challenge.Nonce[0] ^= 0xff
	changed.Challenge, err = lotwenroll.Encode(challenge)
	if err != nil {
		return err
	}
	if err := check("changed-challenge", "TQSL RSA-SHA1 challenge signature is invalid", changed, base); err != nil {
		return err
	}
	expired := clone()
	challenge, err = lotwenroll.Decode(expired.Challenge)
	if err != nil {
		return err
	}
	challenge.IssuedAt = now.Add(-10 * time.Minute).Unix()
	challenge.ExpiresAt = now.Add(-5 * time.Minute).Unix()
	expired.Challenge, err = lotwenroll.Encode(challenge)
	if err != nil {
		return err
	}
	if err := check("expired-challenge", "not currently valid", expired, base); err != nil {
		return err
	}
	expiredCertPEM, err := os.ReadFile(*expiredPath)
	if err != nil {
		return err
	}
	expiredBlock, _ := pem.Decode(expiredCertPEM)
	if expiredBlock == nil || expiredBlock.Type != "CERTIFICATE" {
		return errors.New("expired leaf file is not a certificate PEM")
	}
	expiredCert := clone()
	expiredCert.Chain[0] = expiredBlock.Bytes
	if err := check("expired-certificate", "certificate chain validation failed", expiredCert, base); err != nil {
		return err
	}
	invalidChain := clone()
	invalidChain.Chain[0] = []byte("invalid-certificate-der")
	if err := check("invalid-chain", "malformed certificate chain", invalidChain, base); err != nil {
		return err
	}
	for _, status := range []lotwenroll.Status{lotwenroll.StatusRevoked, lotwenroll.StatusUnknown} {
		config := base
		config.CertificateStatus = func(*x509.Certificate) lotwenroll.StatusEvidence {
			return lotwenroll.StatusEvidence{Status: status, Source: "synthetic-demo-only", ObservedAt: now}
		}
		if err := check(string(status)+"-status", "not known good", clone(), config); err != nil {
			return err
		}
	}
	stale := base
	stale.CertificateStatus = func(*x509.Certificate) lotwenroll.StatusEvidence {
		return lotwenroll.StatusEvidence{Status: lotwenroll.StatusGood, Source: "synthetic-demo-only", ObservedAt: now.Add(-2 * time.Hour)}
	}
	if err := check("stale-status", "stale", clone(), stale); err != nil {
		return err
	}
	return nil
}

func withAudience(config lotwenroll.VerifyConfig, audience string) lotwenroll.VerifyConfig {
	config.Audience = audience
	return config
}

func contains(value, substring string) bool {
	return strings.Contains(value, substring)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "enrollment-demo:", err)
	os.Exit(1)
}
