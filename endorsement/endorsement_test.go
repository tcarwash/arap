package endorsement

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tcarwash/arap/protocol"
)

func makeSigner(t *testing.T, call string) *protocol.Ed25519Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := protocol.NewEd25519Signer(call, private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func issueLink(t *testing.T, signer *protocol.Ed25519Signer, subject string, key ed25519.PublicKey, purposes []string, depth uint8, now time.Time) []byte {
	t.Helper()
	proof, _, err := Issue(signer, subject, key, purposes, depth, now, now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestVerifyAttenuatedDelegationChain(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	root := makeSigner(t, "K1ROOT")
	delegate := makeSigner(t, "K2DELEG")
	subject := makeSigner(t, "K3SUBJ")
	rootPurposes := []string{Purpose, protocol.PurposeContent, PurposeChallengeResponse}
	first := issueLink(t, root, delegate.Callsign(), delegate.PublicKey().(ed25519.PublicKey), []string{Purpose, protocol.PurposeContent}, 1, now)
	second := issueLink(t, delegate, subject.Callsign(), subject.PublicKey().(ed25519.PublicKey), []string{protocol.PurposeContent}, 0, now)
	chain := [][]byte{first, second}
	anchor := Anchor{Callsign: root.Callsign(), PublicKey: root.PublicKey().(ed25519.PublicKey), Purposes: rootPurposes, MaxDelegationDepth: 2}

	accepted := Verify(chain, VerifyConfig{Anchors: []Anchor{anchor}, Subject: subject.Callsign(), SubjectKey: subject.PublicKey().(ed25519.PublicKey), Purpose: protocol.PurposeContent, Now: now})
	if !accepted.Accepted || accepted.ChainDepth != 2 || accepted.Subject != subject.Callsign() {
		t.Fatalf("valid attenuated chain rejected: %+v", accepted)
	}
	wrongPurpose := Verify(chain, VerifyConfig{Anchors: []Anchor{anchor}, Subject: subject.Callsign(), SubjectKey: subject.PublicKey().(ed25519.PublicKey), Purpose: PurposeChallengeResponse, Now: now})
	if wrongPurpose.Accepted || wrongPurpose.Reason != "purpose_not_authorized" {
		t.Fatalf("unexpected purpose accepted: %+v", wrongPurpose)
	}
	wrongRoot := anchor
	wrongRoot.PublicKey = makeSigner(t, "K4ROOT").PublicKey().(ed25519.PublicKey)
	untrusted := Verify(chain, VerifyConfig{Anchors: []Anchor{wrongRoot}, Subject: subject.Callsign(), SubjectKey: subject.PublicKey().(ed25519.PublicKey), Purpose: protocol.PurposeContent, Now: now})
	if untrusted.Accepted || untrusted.Reason != "untrusted_root" {
		t.Fatalf("untrusted root accepted: %+v", untrusted)
	}
	disabledRoot := anchor
	disabledRoot.Disabled = true
	disabled := Verify(chain, VerifyConfig{Anchors: []Anchor{disabledRoot}, Subject: subject.Callsign(), SubjectKey: subject.PublicKey().(ed25519.PublicKey), Purpose: protocol.PurposeContent, Now: now})
	if disabled.Accepted || disabled.Reason != "root_disabled" {
		t.Fatalf("disabled root accepted: %+v", disabled)
	}
	disabled = Verify(chain, VerifyConfig{Anchors: []Anchor{anchor}, Subject: subject.Callsign(), SubjectKey: subject.PublicKey().(ed25519.PublicKey), Purpose: protocol.PurposeContent, Now: now, Disabled: func(call, _ string) bool { return call == subject.Callsign() }})
	if disabled.Accepted || disabled.Reason != "subject_disabled" {
		t.Fatalf("disabled subject accepted: %+v", disabled)
	}
}

func TestVerifyRejectsPurposeAndDepthEscalation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	root := makeSigner(t, "K1ROOT")
	delegate := makeSigner(t, "K2DELEG")
	subject := makeSigner(t, "K3SUBJ")
	first := issueLink(t, root, delegate.Callsign(), delegate.PublicKey().(ed25519.PublicKey), []string{Purpose, protocol.PurposeContent}, 1, now)
	escalating := issueLink(t, delegate, subject.Callsign(), subject.PublicKey().(ed25519.PublicKey), []string{Purpose, PurposeChallengeResponse}, 0, now)
	anchor := Anchor{Callsign: root.Callsign(), PublicKey: root.PublicKey().(ed25519.PublicKey), Purposes: []string{Purpose, protocol.PurposeContent}, MaxDelegationDepth: 2}
	result := Verify([][]byte{first, escalating}, VerifyConfig{Anchors: []Anchor{anchor}, Subject: subject.Callsign(), SubjectKey: subject.PublicKey().(ed25519.PublicKey), Purpose: PurposeChallengeResponse, Now: now})
	if result.Accepted || result.Reason != "purpose_escalation" {
		t.Fatalf("purpose escalation accepted: %+v", result)
	}

	depthEscalation := issueLink(t, root, delegate.Callsign(), delegate.PublicKey().(ed25519.PublicKey), []string{Purpose, protocol.PurposeContent}, 2, now)
	result = Verify([][]byte{depthEscalation}, VerifyConfig{Anchors: []Anchor{anchor}, Subject: delegate.Callsign(), SubjectKey: delegate.PublicKey().(ed25519.PublicKey), Purpose: protocol.PurposeContent, Now: now})
	if result.Accepted || result.Reason != "delegation_depth_escalation" {
		t.Fatalf("depth escalation accepted: %+v", result)
	}
}

func TestVerifyRejectsExpiredAndCyclicChain(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	root := makeSigner(t, "K1ROOT")
	anchor := Anchor{Callsign: root.Callsign(), PublicKey: root.PublicKey().(ed25519.PublicKey), Purposes: []string{Purpose, protocol.PurposeContent}, MaxDelegationDepth: 2}
	leaf := makeSigner(t, "K2LEAF")
	expired, _, err := Issue(root, leaf.Callsign(), leaf.PublicKey().(ed25519.PublicKey), []string{protocol.PurposeContent}, 0, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	result := Verify([][]byte{expired}, VerifyConfig{Anchors: []Anchor{anchor}, Subject: leaf.Callsign(), SubjectKey: leaf.PublicKey().(ed25519.PublicKey), Purpose: protocol.PurposeContent, Now: now})
	if result.Accepted || result.Reason != "expired" {
		t.Fatalf("expired endorsement accepted: %+v", result)
	}

	cycleFirst := issueLink(t, root, leaf.Callsign(), leaf.PublicKey().(ed25519.PublicKey), []string{Purpose, protocol.PurposeContent}, 1, now)
	cycleSecond := issueLink(t, leaf, root.Callsign(), root.PublicKey().(ed25519.PublicKey), []string{protocol.PurposeContent}, 0, now)
	result = Verify([][]byte{cycleFirst, cycleSecond}, VerifyConfig{Anchors: []Anchor{anchor}, Subject: root.Callsign(), SubjectKey: root.PublicKey().(ed25519.PublicKey), Purpose: protocol.PurposeContent, Now: now})
	if result.Accepted || result.Reason != "delegation_cycle" {
		t.Fatalf("cyclic endorsement accepted: %+v", result)
	}
}

func TestIssueRejectsInvalidPurposeAndDepth(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	issuer := makeSigner(t, "K1ROOT")
	subject := makeSigner(t, "K2LEAF")
	if _, _, err := Issue(issuer, subject.Callsign(), subject.PublicKey().(ed25519.PublicKey), []string{"unknown-purpose"}, 0, now, now.Add(time.Hour)); err == nil {
		t.Fatal("unsupported purpose accepted")
	}
	if _, _, err := Issue(issuer, subject.Callsign(), subject.PublicKey().(ed25519.PublicKey), []string{protocol.PurposeContent}, MaxChainDepth+1, now, now.Add(time.Hour)); err == nil {
		t.Fatal("excessive delegation depth accepted")
	}
	if _, _, err := Issue(issuer, subject.Callsign(), subject.PublicKey().(ed25519.PublicKey), []string{protocol.PurposeContent}, 1, now, now.Add(time.Hour)); err == nil {
		t.Fatal("delegation depth without delegation purpose accepted")
	}
	if _, _, err := Issue(issuer, issuer.Callsign(), issuer.PublicKey().(ed25519.PublicKey), []string{protocol.PurposeContent}, 0, now, now.Add(time.Hour)); err == nil {
		t.Fatal("self endorsement accepted")
	}
}

func TestPythonEndorsementVector(t *testing.T) {
	base := filepath.Join("..", "test-vectors", "key-endorsement-v1")
	rootKey := readEd25519Public(t, filepath.Join(base, "root-public.pem"))
	subjectKey := readEd25519Public(t, filepath.Join(base, "subject-public.pem"))
	first, err := os.ReadFile(filepath.Join(base, "root-to-delegate.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(base, "delegate-to-subject.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{first, second}
	encoded, err := os.ReadFile(filepath.Join(base, "chain.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	localEncoding, err := EncodeChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(localEncoding, encoded) {
		t.Fatal("Go chain encoding differs from independent Python vector")
	}
	decoded, err := DecodeChain(encoded)
	if err != nil || len(decoded) != len(chain) {
		t.Fatalf("decode chain: links=%d err=%v", len(decoded), err)
	}
	result := VerifyEncoded(encoded, VerifyConfig{
		Anchors: []Anchor{{Callsign: "K1ROOT", PublicKey: rootKey, Purposes: []string{Purpose, protocol.PurposeContent}, MaxDelegationDepth: 2}},
		Subject: "K3SUBJ", SubjectKey: subjectKey, Purpose: protocol.PurposeContent, Now: time.Unix(1_800_000_001, 0),
	})
	if !result.Accepted {
		t.Fatalf("Python endorsement vector rejected: %+v", result)
	}
}

func readEd25519Public(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("invalid public key PEM: %s", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is not Ed25519: %s", path)
	}
	return key
}
