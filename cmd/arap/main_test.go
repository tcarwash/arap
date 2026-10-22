package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tcarwash/arap/challenge"
	"github.com/tcarwash/arap/endorsement"
	"github.com/tcarwash/arap/identity"
	"github.com/tcarwash/arap/keyserver"
	"github.com/tcarwash/arap/lotwenroll"
	"github.com/tcarwash/arap/protocol"
	"github.com/tcarwash/arap/reference"
	_ "modernc.org/sqlite"
)

const mainTestUploadToken = "0123456789abcdef0123456789abcdef"

func TestEndorsementCLIChainPackAppendAndVerify(t *testing.T) {
	dir := t.TempDir()
	makeKey := func(name string, fill byte) (string, string, ed25519.PublicKey) {
		privatePath, publicPath := filepath.Join(dir, name+"-private.pem"), filepath.Join(dir, name+"-public.pem")
		private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
		if err := identity.WriteKeyPair(privatePath, publicPath, private); err != nil {
			t.Fatal(err)
		}
		return privatePath, publicPath, private.Public().(ed25519.PublicKey)
	}
	rootPrivate, rootPublicPath, _ := makeKey("root", 0x31)
	delegatePrivate, delegatePublicPath, _ := makeKey("delegate", 0x42)
	_, subjectPublicPath, _ := makeKey("subject", 0x53)
	rootLink, delegateLink := filepath.Join(dir, "root.cose"), filepath.Join(dir, "delegate.cose")
	call := func(args ...string) int {
		code, err := run(args)
		if err != nil {
			t.Fatalf("run %v: code=%d err=%v", args, code, err)
		}
		return code
	}
	call("endorsement", "issue", "--key", rootPrivate, "--callsign", "K7ABC", "--subject", "AG7SU", "--subject-public-key", delegatePublicPath,
		"--purpose", protocol.PurposeContent, "--purpose", endorsement.Purpose, "--max-delegation-depth", "1", "--out", rootLink)
	call("endorsement", "issue", "--key", delegatePrivate, "--callsign", "AG7SU", "--subject", "W1XYZ", "--subject-public-key", subjectPublicPath,
		"--purpose", protocol.PurposeContent, "--max-delegation-depth", "0", "--out", delegateLink)
	firstChain, finalChain := filepath.Join(dir, "first.chain"), filepath.Join(dir, "final.chain")
	call("endorsement", "pack", "--link", rootLink, "--out", firstChain)
	call("endorsement", "append", "--chain", firstChain, "--link", delegateLink, "--out", finalChain)
	args := []string{"endorsement", "verify", "--chain", finalChain, "--root-callsign", "K7ABC", "--root-public-key", rootPublicPath,
		"--root-purpose", protocol.PurposeContent, "--root-purpose", endorsement.Purpose, "--root-max-delegation-depth", "2",
		"--subject", "W1XYZ", "--subject-public-key", subjectPublicPath, "--purpose", protocol.PurposeContent}
	if code := call(args...); code != 0 {
		t.Fatalf("valid chain returned %d", code)
	}
	args[len(args)-1] = "challenge-response"
	if code := call(args...); code != 1 {
		t.Fatalf("wrong-purpose chain returned %d, want 1", code)
	}
	if code, err := issueEndorsement([]string{"--key", rootPrivate, "--callsign", "K7ABC", "--subject", "AG7SU", "--subject-public-key", delegatePublicPath,
		"--purpose", protocol.PurposeContent, "--max-delegation-depth", "256", "--out", filepath.Join(dir, "bad.cose")}); err == nil || code != 2 {
		t.Fatalf("out-of-range depth: code=%d err=%v, want code 2 and error", code, err)
	}
}

func TestVerifyContentCanUseOnlyExplicitlyEnrolledPurpose(t *testing.T) {
	dir := t.TempDir()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x7a}, ed25519.SeedSize))
	publicPath, privatePath := filepath.Join(dir, "public.pem"), filepath.Join(dir, "private.pem")
	if err := identity.WriteKeyPair(privatePath, publicPath, private); err != nil {
		t.Fatal(err)
	}
	content := []byte("content authorized by explicit enrollment purpose")
	contentPath := filepath.Join(dir, "content.bin")
	if err := os.WriteFile(contentPath, content, 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := protocol.NewEd25519Signer("N0CALL", private)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := protocol.SignContent(signer, bytes.NewReader(content), protocol.ContentMetadata{
		MediaType: "application/octet-stream", Context: "enrollment-content-test/v1",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	proofPath := filepath.Join(dir, "proof.cose")
	if err := os.WriteFile(proofPath, proof, 0600); err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	verify := func(purposes []string) int {
		dbPath := filepath.Join(dir, fmt.Sprintf("enrollment-%s.sqlite", purposes[0]))
		store, err := lotwenroll.OpenSQLite(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		requestHash := sha256.Sum256([]byte("synthetic accepted enrollment" + purposes[0]))
		if err := store.Issue(requestHash[:], "verifier", "N0CALL", hex.EncodeToString(keyID), now.Add(time.Minute).Unix()); err != nil {
			t.Fatal(err)
		}
		certificateHash := sha256.Sum256([]byte("synthetic certificate " + purposes[0]))
		binding := lotwenroll.Binding{Callsign: "N0CALL", KeyID: hex.EncodeToString(keyID),
			PublicKey: private.Public().(ed25519.PublicKey), Purposes: purposes,
			CertificateSHA256: hex.EncodeToString(certificateHash[:]), CertificateIssuer: "CN=test",
			CertificateExpiry: now.Add(24 * time.Hour).Unix(), VerifiedAt: now.Unix(),
			Status: lotwenroll.StatusGood, StatusSource: "synthetic-status", StatusObservedAt: now.Unix()}
		if accepted, err := store.Complete(requestHash[:], binding, now.Unix()); err != nil || !accepted {
			t.Fatalf("seed purpose-scoped enrollment: accepted=%v err=%v", accepted, err)
		}
		code, err := run([]string{"verify-content", "--proof", proofPath, "--input", contentPath,
			"--public-key", publicPath, "--enrollment-store", dbPath,
			"--expect-media-type", "application/octet-stream", "--expect-context", "enrollment-content-test/v1",
			"--expect-callsign", "N0CALL"})
		if err != nil {
			t.Fatalf("verify with purposes %v: code=%d err=%v", purposes, code, err)
		}
		return code
	}
	if code := verify([]string{lotwenroll.PurposeChallengeResponse}); code != 3 {
		t.Fatalf("challenge-only binding content verification code=%d, want incomplete/untrusted (3)", code)
	}
	if code := verify([]string{lotwenroll.PurposeContentSignature}); code != 0 {
		t.Fatalf("content-purpose binding verification code=%d, want accepted (0)", code)
	}
}

func TestChallengeIssueDoesNotRecordWhenRequestOutputAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "challenges.sqlite")
	outPath := filepath.Join(dir, "request.cbor")
	sentinel := []byte("preserve existing output")
	if err := os.WriteFile(outPath, sentinel, 0600); err != nil {
		t.Fatal(err)
	}
	code, err := issueChallenge([]string{
		"--requester", "K7ABC", "--responder", "AG7SU",
		"--store", dbPath, "--out", outPath,
	})
	if err == nil || code != 2 {
		t.Fatalf("issue with existing output: code=%d err=%v, want failure", code, err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil || !bytes.Equal(got, sentinel) {
		t.Fatalf("existing output changed: bytes=%q err=%v", got, err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var records int
	if err := db.QueryRow(`SELECT COUNT(*) FROM challenges`).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if records != 0 {
		t.Fatalf("recorded %d challenge(s) despite failing to publish the request file", records)
	}
}

func TestMutualChallengeCLIFlowBindsSessionAndConsumesPairOnce(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "mutual.sqlite")
	requestAPath := filepath.Join(dir, "request-from-a.cbor")
	requestBPath := filepath.Join(dir, "request-from-b.cbor")
	responseAPath := filepath.Join(dir, "response-from-a.cose")
	responseBPath := filepath.Join(dir, "response-from-b.cose")
	privateAPath, publicAPath := filepath.Join(dir, "a-private.pem"), filepath.Join(dir, "a-public.pem")
	privateBPath, publicBPath := filepath.Join(dir, "b-private.pem"), filepath.Join(dir, "b-public.pem")
	privateA := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	privateB := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, ed25519.SeedSize))
	if err := identity.WriteKeyPair(privateAPath, publicAPath, privateA); err != nil {
		t.Fatal(err)
	}
	if err := identity.WriteKeyPair(privateBPath, publicBPath, privateB); err != nil {
		t.Fatal(err)
	}
	publicA, err := identity.LoadPublic(publicAPath)
	if err != nil {
		t.Fatal(err)
	}
	publicB, err := identity.LoadPublic(publicBPath)
	if err != nil {
		t.Fatal(err)
	}
	keyIDA, err := protocol.KeyID(publicA)
	if err != nil {
		t.Fatal(err)
	}
	keyIDB, err := protocol.KeyID(publicB)
	if err != nil {
		t.Fatal(err)
	}
	trustAPath, trustBPath := filepath.Join(dir, "trust-a.json"), filepath.Join(dir, "trust-b.json")
	if err := identity.SaveTrust(trustAPath, identity.TrustStore{Bindings: []identity.Binding{{Callsign: "K7ABC", KeyID: hex.EncodeToString(keyIDA), Purposes: []string{challenge.ResponsePurpose}}}}); err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveTrust(trustBPath, identity.TrustStore{Bindings: []identity.Binding{{Callsign: "AG7SU", KeyID: hex.EncodeToString(keyIDB), Purposes: []string{challenge.ResponsePurpose}}}}); err != nil {
		t.Fatal(err)
	}
	sessionHex := hex.EncodeToString([]byte("cli-session-channel-binding"))
	code, err := run([]string{"challenge", "mutual-issue",
		"--party-a", "K7ABC", "--party-b", "AG7SU", "--session-binding-hex", sessionHex,
		"--store", dbPath, "--out-from-a", requestAPath, "--out-from-b", requestBPath,
	})
	if err != nil || code != 0 {
		t.Fatalf("mutual issue: code=%d err=%v", code, err)
	}
	code, err = run([]string{"challenge", "respond", "--request", requestAPath, "--key", privateBPath, "--callsign", "AG7SU", "--out", responseBPath})
	if err != nil || code != 0 {
		t.Fatalf("party B response: code=%d err=%v", code, err)
	}
	code, err = run([]string{"challenge", "respond", "--request", requestBPath, "--key", privateAPath, "--callsign", "K7ABC", "--out", responseAPath})
	if err != nil || code != 0 {
		t.Fatalf("party A response: code=%d err=%v", code, err)
	}
	args := []string{
		"--request-from-a", requestAPath, "--response-from-b", responseBPath,
		"--request-from-b", requestBPath, "--response-from-a", responseAPath,
		"--party-a", "K7ABC", "--party-b", "AG7SU", "--party-a-public-key", publicAPath, "--party-b-public-key", publicBPath,
		"--party-a-trust-store", trustAPath, "--party-b-trust-store", trustBPath, "--store", dbPath,
		"--session-binding-hex", hex.EncodeToString([]byte("different-session")),
	}
	code, err = run(append([]string{"challenge", "mutual-verify"}, args...))
	if err != nil || code != 1 {
		t.Fatalf("cross-session mutual verification: code=%d err=%v", code, err)
	}
	args[len(args)-1] = sessionHex
	code, err = run(append([]string{"challenge", "mutual-verify"}, args...))
	if err != nil || code != 0 {
		t.Fatalf("mutual verification: code=%d err=%v", code, err)
	}
	code, err = run(append([]string{"challenge", "mutual-verify"}, args...))
	if err != nil || code != 1 {
		t.Fatalf("mutual pair replay: code=%d err=%v", code, err)
	}
}

func TestEnrollmentIssuePersistsBoundShortLivedChallenge(t *testing.T) {
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(dir, "key.pem")
	if err := identity.WriteKeyPair(filepath.Join(dir, "private.pem"), publicPath, private); err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(dir, "enrollment.sqlite")
	outPath := filepath.Join(dir, "enrollment.cbor")
	var stdout bytes.Buffer
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	code, runErr := enrollmentCommand([]string{"issue", "--audience", "arap.example", "--callsign", "n0call", "--public-key", publicPath, "--store", storePath, "--out", outPath, "--expires-in", "90"})
	_ = writer.Close()
	os.Stdout = oldStdout
	_, _ = stdout.ReadFrom(reader)
	_ = reader.Close()
	if runErr != nil || code != 0 {
		t.Fatalf("enrollment issue returned code=%d err=%v", code, runErr)
	}
	encoded, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	request, err := lotwenroll.Decode(encoded)
	if err != nil {
		t.Fatalf("decode issued challenge: %v", err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	if request.Audience != "arap.example" || request.Callsign != "N0CALL" || !bytes.Equal(request.KeyID[:], keyID) || request.ExpiresAt-request.IssuedAt != 90 {
		t.Fatalf("issued challenge not bound as requested: %+v", request)
	}
	if len(stdout.Bytes()) == 0 {
		t.Fatal("expected machine-readable issue result")
	}
	db, err := sql.Open("sqlite", storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var pending, bindings int
	if err := db.QueryRow(`SELECT COUNT(*) FROM enrollment_challenges WHERE state='pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM enrollment_bindings`).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if pending != 1 || bindings != 0 {
		t.Fatalf("unexpected enrollment state after issue: pending=%d bindings=%d", pending, bindings)
	}
}

func TestEnrollmentIssueCancelsUnpublishedChallenge(t *testing.T) {
	dir := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(dir, "key.pem")
	if err := identity.WriteKeyPair(filepath.Join(dir, "private.pem"), publicPath, private); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "existing.cbor")
	if err := os.WriteFile(outPath, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(dir, "enrollment.sqlite")
	code, err := enrollmentCommand([]string{"issue", "--audience", "arap.example", "--callsign", "N0CALL", "--public-key", publicPath, "--store", storePath, "--out", outPath})
	if err == nil || code != 2 {
		t.Fatalf("issue with existing output: code=%d err=%v, want failure", code, err)
	}
	db, err := sql.Open("sqlite", storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var records int
	if err := db.QueryRow(`SELECT COUNT(*) FROM enrollment_challenges WHERE state='pending'`).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if records != 0 {
		t.Fatalf("left %d pending enrollment challenge(s) after output failed", records)
	}
	got, err := os.ReadFile(outPath)
	if err != nil || string(got) != "keep" {
		t.Fatalf("existing challenge output changed: %q err=%v", got, err)
	}
}

func TestTrustAddSupportsChallengeResponsePurpose(t *testing.T) {
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(dir, "public.pem")
	if err := identity.WriteKeyPair(filepath.Join(dir, "private.pem"), publicPath, key); err != nil {
		t.Fatal(err)
	}
	trustPath := filepath.Join(dir, "trust.json")
	code, err := trustCommand([]string{"add", "--store", trustPath, "--public-key", publicPath, "--callsign", "N0CALL", "--purpose", challenge.ResponsePurpose})
	if err != nil || code != 0 {
		t.Fatalf("trust add returned code=%d err=%v", code, err)
	}
	store, err := identity.LoadTrust(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.KeyID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !store.Allows("N0CALL", fmt.Sprintf("%x", id), challenge.ResponsePurpose) {
		t.Fatal("trust add did not authorize challenge-response")
	}
}

func TestChallengeVerificationUsesFreshLoTWEnrollmentBinding(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(dir, "responder-private.pem")
	publicPath := filepath.Join(dir, "responder-public.pem")
	if err := identity.WriteKeyPair(privatePath, publicPath, private); err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentPath := filepath.Join(dir, "enrollment.sqlite")
	enrollment, err := lotwenroll.OpenSQLite(enrollmentPath)
	if err != nil {
		t.Fatal(err)
	}
	certHash := sha256.Sum256([]byte("synthetic certificate"))
	binding := lotwenroll.Binding{Callsign: "N0CALL", KeyID: fmt.Sprintf("%x", keyID), PublicKey: public, Purposes: []string{challenge.ResponsePurpose}, CertificateSHA256: fmt.Sprintf("%x", certHash), CertificateIssuer: "CN=synthetic root", CertificateExpiry: now.Add(24 * time.Hour).Unix(), VerifiedAt: now.Unix(), Status: lotwenroll.StatusGood, StatusSource: "synthetic test status", StatusObservedAt: now.Unix()}
	enrollmentHash := sha256.Sum256([]byte("synthetic enrollment challenge"))
	if err := enrollment.Issue(enrollmentHash[:], "ARAP", binding.Callsign, binding.KeyID, now.Add(time.Minute).Unix()); err != nil {
		enrollment.Close()
		t.Fatal(err)
	}
	if accepted, err := enrollment.Complete(enrollmentHash[:], binding, now.Unix()); err != nil || !accepted {
		enrollment.Close()
		t.Fatalf("complete enrollment: accepted=%v err=%v", accepted, err)
	}
	if err := enrollment.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := challenge.NewRequest("K7ABC", "N0CALL", challenge.AuthPurpose, nil, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	encodedRequest, err := challenge.EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	challengePath := filepath.Join(dir, "request.cbor")
	proofPath := filepath.Join(dir, "response.cose")
	if err := os.WriteFile(challengePath, encodedRequest, 0600); err != nil {
		t.Fatal(err)
	}
	requestStorePath := filepath.Join(dir, "requester.sqlite")
	requestStore, err := challenge.OpenSQLite(requestStorePath)
	if err != nil {
		t.Fatal(err)
	}
	requestHash := challenge.RequestHash(encodedRequest)
	if err := requestStore.Issue(requestHash[:], request.Requester, request.Responder, request.ExpiresAt); err != nil {
		requestStore.Close()
		t.Fatal(err)
	}
	if err := requestStore.Close(); err != nil {
		t.Fatal(err)
	}
	signer, err := protocol.NewEd25519Signer("N0CALL", private)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := challenge.Respond(signer, encodedRequest, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proofPath, proof, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--request", challengePath, "--response", proofPath, "--public-key", publicPath, "--enrollment-store", enrollmentPath, "--store", requestStorePath, "--requester", "K7ABC"}
	code, err := verifyChallenge(args)
	if err != nil || code != 0 {
		t.Fatalf("enrolled challenge verification: code=%d err=%v", code, err)
	}
	code, err = verifyChallenge(args)
	if err != nil || code != 1 {
		t.Fatalf("enrolled challenge replay: code=%d err=%v, want 1", code, err)
	}
}

func TestChallengeIssueCancelsRecordWhenOutputCannotBePublished(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "challenges.sqlite")
	code, err := issueChallenge([]string{
		"--requester", "K7ABC", "--responder", "AG7SU",
		"--store", dbPath, "--out", dir,
	})
	if err == nil || code != 2 {
		t.Fatalf("issue with directory as output: code=%d err=%v, want failure", code, err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var records int
	if err := db.QueryRow(`SELECT COUNT(*) FROM challenges WHERE state='pending'`).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if records != 0 {
		t.Fatalf("left %d pending challenge(s) after output publication failed", records)
	}
}

func TestChallengeIssueDoesNotPublishRequestWhenStoreWriteFails(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "challenges.sqlite")
	store, err := challenge.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_issue BEFORE INSERT ON challenges BEGIN SELECT RAISE(ABORT, 'forced issue failure'); END`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "request.cbor")
	code, err := issueChallenge([]string{
		"--requester", "K7ABC", "--responder", "AG7SU",
		"--store", dbPath, "--out", outPath,
	})
	if err == nil || code != 2 {
		t.Fatalf("issue with failing store: code=%d err=%v, want failure", code, err)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("unrecorded request file remains: stat error=%v", err)
	}
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var records int
	if err := db.QueryRow(`SELECT COUNT(*) FROM challenges`).Scan(&records); err != nil {
		t.Fatal(err)
	}
	if records != 0 {
		t.Fatalf("recorded %d challenge(s) despite forced store failure", records)
	}
}

func TestVerifyReferenceRunsLocalContentPolicy(t *testing.T) {
	dir := t.TempDir()
	server, err := keyserver.New(filepath.Join(dir, "objects"), mainTestUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	server2, err := keyserver.New(filepath.Join(dir, "objects-2"), mainTestUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	httpServer2 := httptest.NewServer(server2)
	defer httpServer2.Close()
	client, err := reference.New(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := protocol.NewEd25519Signer("AG7SU", private)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("reference-verified content")
	proof, _, err := protocol.SignContent(signer, bytes.NewReader(content), protocol.ContentMetadata{MediaType: "text/plain", Context: "test/reference/v1"}, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	published, err := client.PublishProof(context.Background(), proof, mainTestUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	client2, err := reference.New(httpServer2.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client2.PublishProof(context.Background(), proof, mainTestUploadToken); err != nil {
		t.Fatal(err)
	}
	contentPath := filepath.Join(dir, "content.txt")
	if err := os.WriteFile(contentPath, content, 0600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "public.pem")
	privPath := filepath.Join(dir, "private.pem")
	if err := identity.WriteKeyPair(privPath, keyPath, private); err != nil {
		t.Fatal(err)
	}
	pub, err := identity.LoadPublic(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	trust := identity.TrustStore{Version: 1, Bindings: []identity.Binding{}}
	trust.Add("AG7SU", fmt.Sprintf("%x", keyID), []string{protocol.PurposeContent})
	trustPath := filepath.Join(dir, "trust.json")
	if err := identity.SaveTrust(trustPath, trust); err != nil {
		t.Fatal(err)
	}
	args := []string{"--server", httpServer.URL, "--server", httpServer2.URL, "--reference", published.Token, "--input", contentPath, "--public-key", keyPath, "--trust-store", trustPath, "--expect-media-type", "text/plain", "--expect-context", "test/reference/v1"}
	code, err := verifyReference(args)
	if err != nil || code != 0 {
		t.Fatalf("valid resolved proof rejected: code=%d err=%v", code, err)
	}
	trust.Disable("AG7SU", fmt.Sprintf("%x", keyID))
	if err := identity.SaveTrust(trustPath, trust); err != nil {
		t.Fatal(err)
	}
	code, err = verifyReference(args)
	if err != nil || code != 1 {
		t.Fatalf("disabled key result: code=%d err=%v", code, err)
	}
	trust = identity.TrustStore{Version: 1, Bindings: []identity.Binding{}}
	if err := identity.SaveTrust(trustPath, trust); err != nil {
		t.Fatal(err)
	}
	code, err = verifyReference(args)
	if err != nil || code != 3 {
		t.Fatalf("unknown key result: code=%d err=%v", code, err)
	}
	if err := os.WriteFile(contentPath, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	code, err = verifyReference(args)
	if err != nil || code != 1 {
		t.Fatalf("changed content result: code=%d err=%v", code, err)
	}
}

func TestPublishKeyAcceptsCertificateAndAddressesItsSPKI(t *testing.T) {
	dir := t.TempDir()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "AG7SU test certificate"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(dir, "callsign-certificate.pem")
	if err := os.WriteFile(path, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	server, err := keyserver.New(filepath.Join(dir, "objects"), mainTestUploadToken)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	t.Setenv("ARAP_UPLOAD_TOKEN", mainTestUploadToken)
	if code, err := publishKey([]string{"--server", httpServer.URL, "--public-key", path}); err != nil || code != 0 {
		t.Fatalf("publish-key certificate: code=%d err=%v", code, err)
	}
	public, err := identity.LoadPublicKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.LoadPublic(path); err == nil {
		t.Fatal("non-Ed25519 certificate became an accepted proof-verification key")
	}
	fingerprint, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	client, err := reference.New(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := client.FetchKey(context.Background(), fmt.Sprintf("%x", fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fetched, certificate) {
		t.Fatal("fetched certificate bytes differ from published bytes")
	}
}

func TestPixelQSOCardSignAndVerifyCommands(t *testing.T) {
	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "private.pem")
	publicKeyPath := filepath.Join(dir, "public.pem")
	cardPath := filepath.Join(dir, "card.json")
	proofPath := filepath.Join(dir, "card.cose")
	trustPath := filepath.Join(dir, "trust.json")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.WriteKeyPair(privateKeyPath, publicKeyPath, private); err != nil {
		t.Fatal(err)
	}
	card := `{"format":"pixel-qso-card","version":1,"callsign":"AG7SU","grid":"CN85","card_id":12,"width":2,"height":2,"palette":[[0,0,0],[15,15,15]],"pixels":[0,1,1,0],"base_pixels":[0,0,0,0],"stamp_layers":[]}`
	if err := os.WriteFile(cardPath, []byte(card), 0600); err != nil {
		t.Fatal(err)
	}
	pub, err := identity.LoadPublic(publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	trust := identity.TrustStore{Version: 1, Bindings: []identity.Binding{}}
	trust.Add("AG7SU", fmt.Sprintf("%x", id), []string{protocol.PurposeContent})
	if err := identity.SaveTrust(trustPath, trust); err != nil {
		t.Fatal(err)
	}
	if code, err := signPixelQSO([]string{"--key", privateKeyPath, "--card", cardPath, "--out", proofPath}); err != nil || code != 0 {
		t.Fatalf("sign-pixelqso: code=%d err=%v", code, err)
	}
	verifyArgs := []string{"--card", cardPath, "--proof", proofPath, "--public-key", publicKeyPath, "--trust-store", trustPath}
	if code, err := verifyPixelQSO(verifyArgs); err != nil || code != 0 {
		t.Fatalf("verify-pixelqso rejected signed card: code=%d err=%v", code, err)
	}
	card = strings.Replace(card, `"base_pixels":[0,0,0,0]`, `"base_pixels":[1,1,1,1]`, 1)
	if err := os.WriteFile(cardPath, []byte(card), 0600); err != nil {
		t.Fatal(err)
	}
	if code, err := verifyPixelQSO(verifyArgs); err != nil || code != 0 {
		t.Fatalf("verify-pixelqso should ignore editor-only layer changes: code=%d err=%v", code, err)
	}
	card = strings.Replace(card, `"pixels":[0,1,1,0]`, `"pixels":[0,0,1,0]`, 1)
	if err := os.WriteFile(cardPath, []byte(card), 0600); err != nil {
		t.Fatal(err)
	}
	if code, err := verifyPixelQSO(verifyArgs); err != nil || code != 1 {
		t.Fatalf("verify-pixelqso accepted changed card art: code=%d err=%v", code, err)
	}
}

func TestPixelQSOAnimationCommandsRequireAndValidateFirstFrame(t *testing.T) {
	dir := t.TempDir()
	privateKeyPath := filepath.Join(dir, "private.pem")
	publicKeyPath := filepath.Join(dir, "public.pem")
	cardPath := filepath.Join(dir, "frame-2.json")
	firstPath := filepath.Join(dir, "frame-1.json")
	proofPath := filepath.Join(dir, "frame-2.cose")
	trustPath := filepath.Join(dir, "trust.json")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.WriteKeyPair(privateKeyPath, publicKeyPath, private); err != nil {
		t.Fatal(err)
	}
	vectorDir := filepath.Join("..", "..", "test-vectors", "pixelqso-card-v1")
	first, err := os.ReadFile(filepath.Join(vectorDir, "first-card.json"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(vectorDir, "card.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstPath, first, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cardPath, second, 0600); err != nil {
		t.Fatal(err)
	}
	pub, err := identity.LoadPublic(publicKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	trust := identity.TrustStore{Version: 1, Bindings: []identity.Binding{}}
	trust.Add("AG7SU", fmt.Sprintf("%x", id), []string{protocol.PurposeContent})
	if err := identity.SaveTrust(trustPath, trust); err != nil {
		t.Fatal(err)
	}
	baseArgs := []string{"--key", privateKeyPath, "--card", cardPath, "--out", proofPath}
	if code, err := signPixelQSO(baseArgs); err == nil || code != 2 {
		t.Fatalf("frame 2 was signed without its first card: code=%d err=%v", code, err)
	}
	if code, err := signPixelQSO(append(baseArgs, "--first-card", firstPath)); err != nil || code != 0 {
		t.Fatalf("valid frame pair signing failed: code=%d err=%v", code, err)
	}
	verifyArgs := []string{"--card", cardPath, "--first-card", firstPath, "--proof", proofPath,
		"--public-key", publicKeyPath, "--trust-store", trustPath}
	if code, err := verifyPixelQSO(verifyArgs); err != nil || code != 0 {
		t.Fatalf("valid frame pair verification failed: code=%d err=%v", code, err)
	}
	first = []byte(strings.Replace(string(first), `"pixels": [1, 2, 3, 4]`, `"pixels": [0, 2, 3, 4]`, 1))
	if err := os.WriteFile(firstPath, first, 0600); err != nil {
		t.Fatal(err)
	}
	if code, err := verifyPixelQSO(verifyArgs); err == nil || code != 2 {
		t.Fatalf("frame 2 accepted mismatched first-frame art: code=%d err=%v", code, err)
	}
}
