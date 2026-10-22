package lotwenroll

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type orderedChainSigner struct{ signed bool }

func (s *orderedChainSigner) SignEnrollmentChallenge([]byte) ([]byte, error) {
	s.signed = true
	return []byte("synthetic-signature"), nil
}

func (s *orderedChainSigner) EnrollmentCertificateChain() ([][]byte, error) {
	if !s.signed {
		return nil, errors.New("chain requested before signing")
	}
	return [][]byte{{1, 2, 3}}, nil
}

func TestRespondObtainsCertificateChainAfterSigning(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	_, request, err := New("demo-verifier", "N0CALL", public, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	signer := &orderedChainSigner{}
	response, err := Respond(request, private, signer, nil)
	if err != nil {
		t.Fatalf("response failed because chain was requested before signing: %v", err)
	}
	if !signer.signed || len(response.Chain) != 1 || !bytes.Equal(response.Chain[0], []byte{1, 2, 3}) {
		t.Fatalf("signing or post-sign chain retrieval did not complete: signed=%t chain=%d", signer.signed, len(response.Chain))
	}
}

func testHelperOutput(t *testing.T, signature, certificate []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	out.WriteString(tqslHelperMagic)
	write := func(b []byte) {
		if err := binary.Write(&out, binary.LittleEndian, uint32(len(b))); err != nil {
			t.Fatal(err)
		}
		out.Write(b)
	}
	write(signature)
	if err := binary.Write(&out, binary.LittleEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
	return out.Bytes()
}

func TestTQSLHelperSignerProtocol(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(19), Subject: pkix.Name{CommonName: "ARAP helper test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	wantSignature := []byte("synthetic-tqsl-signature")
	encoded := testHelperOutput(t, wantSignature, der)
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "helper-output")
	if err := os.WriteFile(outputPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(dir, "fake-helper")
	script := "#!/bin/sh\ncat >/dev/null\ncat " + outputPath + "\n"
	if err := os.WriteFile(helperPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	signer := &TQSLHelperSigner{Path: helperPath, Callsign: "N0CALL", Passphrase: []byte("test password")}
	gotSignature, err := signer.SignEnrollmentChallenge([]byte("challenge bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSignature, wantSignature) {
		t.Fatalf("signature = %q, want %q", gotSignature, wantSignature)
	}
	chain, err := signer.EnrollmentCertificateChain()
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 || !bytes.Equal(chain[0], der) {
		t.Fatalf("unexpected chain: %d certificate(s)", len(chain))
	}
}

func TestDecodeTQSLHelperRejectsMalformedOutput(t *testing.T) {
	for name, input := range map[string][]byte{
		"wrong header":    []byte("not an ARAP helper response"),
		"empty signature": append([]byte(tqslHelperMagic), 0, 0, 0, 0),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeTQSLHelperOutput(input); err == nil {
				t.Fatal("malformed helper output was accepted")
			}
		})
	}
}
