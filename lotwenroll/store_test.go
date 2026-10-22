package lotwenroll

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tcarwash/arap/challenge"
	"github.com/tcarwash/arap/protocol"
)

func TestSQLiteStoreConsumesAndPersistsBindingAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state ? enrollment.sqlite")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Unix()
	hash := sha256.Sum256([]byte("canonical enrollment challenge"))
	binding := testBinding(t, now)
	if err := store.Issue(hash[:], "ARAP", "N0CALL", binding.KeyID, now+60); err != nil {
		t.Fatal(err)
	}
	wrongBinding := testBinding(t, now)
	if accepted, err := store.Complete(hash[:], wrongBinding, now); err != nil || accepted {
		t.Fatalf("mismatched challenge key completed: accepted=%v err=%v", accepted, err)
	}
	accepted, err := store.Complete(hash[:], binding, now)
	if err != nil || !accepted {
		t.Fatalf("complete: accepted=%v err=%v", accepted, err)
	}
	if accepted, err := store.Complete(hash[:], binding, now); err != nil || accepted {
		t.Fatalf("replay: accepted=%v err=%v", accepted, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	bindings, err := store.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].Callsign != binding.Callsign || bindings[0].KeyID != binding.KeyID || bindings[0].CertificateSHA256 != binding.CertificateSHA256 || bindings[0].StatusSource != binding.StatusSource || bindings[0].Disabled {
		t.Fatalf("binding did not persist: %+v", bindings)
	}
	if got := store.TrustStatus(binding.Callsign, binding.KeyID, "challenge-response", time.Unix(now, 0), time.Hour); got != "trusted" {
		t.Fatalf("fresh enrollment status=%q, want trusted", got)
	}
	if got := store.TrustStatus(binding.Callsign, binding.KeyID, "content-signature", time.Unix(now, 0), time.Hour); got != "untrusted" {
		t.Fatalf("enrollment granted content trust: %q", got)
	}
	if got := store.TrustStatus(binding.Callsign, binding.KeyID, "challenge-response", time.Unix(now+7200, 0), time.Hour); got != "untrusted" {
		t.Fatalf("expired certificate/status remained trusted: %q", got)
	}
	if err := store.Disable(binding.Callsign, binding.KeyID); err != nil {
		t.Fatal(err)
	}
	bindings, err = store.Bindings()
	if err != nil || len(bindings) != 1 || !bindings[0].Disabled {
		t.Fatalf("disable did not persist: bindings=%+v err=%v", bindings, err)
	}
	if got := store.TrustStatus(binding.Callsign, binding.KeyID, "challenge-response", time.Unix(now, 0), time.Hour); got != "disabled" {
		t.Fatalf("disabled enrollment status=%q, want disabled", got)
	}
}

func TestSQLiteStoreCompletionHasSingleWinner(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "enrollment.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Unix()
	hash := sha256.Sum256([]byte("concurrent challenge"))
	binding := testBinding(t, now)
	if err := store.Issue(hash[:], "ARAP", "N0CALL", binding.KeyID, now+60); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := store.Complete(hash[:], binding, now)
			if err != nil {
				t.Errorf("complete: %v", err)
				return
			}
			if ok {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if winners != 1 {
		t.Fatalf("got %d completion winners, want 1", winners)
	}
}

func TestEnrollmentBindingAuthenticatesChallengeResponseOnly(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	certHash := sha256.Sum256([]byte("synthetic LoTW certificate"))
	binding := Binding{
		Callsign: "N0CALL", KeyID: hex.EncodeToString(keyID), PublicKey: public,
		Purposes: []string{"challenge-response"}, CertificateSHA256: hex.EncodeToString(certHash[:]),
		CertificateIssuer: "CN=synthetic root", CertificateExpiry: now.Unix() + 3600,
		VerifiedAt: now.Unix(), Status: StatusGood, StatusSource: "synthetic-status",
		StatusObservedAt: now.Unix(),
	}
	enrollment, err := OpenSQLite(filepath.Join(t.TempDir(), "enrollment.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer enrollment.Close()
	enrollmentHash := sha256.Sum256([]byte("enrollment challenge"))
	if err := enrollment.Issue(enrollmentHash[:], "ARAP", binding.Callsign, binding.KeyID, now.Unix()+60); err != nil {
		t.Fatal(err)
	}
	if ok, err := enrollment.Complete(enrollmentHash[:], binding, now.Unix()); err != nil || !ok {
		t.Fatalf("complete enrollment: accepted=%v err=%v", ok, err)
	}
	requesterDB, err := challenge.OpenSQLite(filepath.Join(t.TempDir(), "challenge.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer requesterDB.Close()
	request, err := challenge.NewRequest("K7ABC", "N0CALL", challenge.AuthPurpose, nil, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	encodedRequest, err := challenge.EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	requestHash := challenge.RequestHash(encodedRequest)
	if err := requesterDB.Issue(requestHash[:], request.Requester, request.Responder, request.ExpiresAt); err != nil {
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
	verifier, err := protocol.NewEd25519Verifier(public)
	if err != nil {
		t.Fatal(err)
	}
	trust := func(call, id, purpose string) string {
		return enrollment.TrustStatus(call, id, purpose, now.Add(2*time.Second), time.Hour)
	}
	result := challenge.VerifyResponseWithTrust(encodedRequest, proof, verifier, trust, requesterDB, "K7ABC", now.Add(2*time.Second))
	if result.OverallPolicy != "accepted" {
		t.Fatalf("enrolled key challenge response was rejected: %+v", result)
	}
	if got := enrollment.TrustStatus("N0CALL", binding.KeyID, "content-signature", now.Add(2*time.Second), time.Hour); got != "untrusted" {
		t.Fatalf("enrollment incorrectly authorized content signing: %q", got)
	}
}

func testBinding(t *testing.T, now int64) Binding {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	certID := sha256.Sum256([]byte("fake certificate"))
	return Binding{
		Callsign: "N0CALL", KeyID: hex.EncodeToString(keyID), PublicKey: public,
		Purposes: []string{"challenge-response"}, CertificateSHA256: hex.EncodeToString(certID[:]),
		CertificateIssuer: "CN=ARAP test root", CertificateExpiry: now + 3600, VerifiedAt: now,
		Status: StatusGood, StatusSource: "synthetic-test-status", StatusObservedAt: now,
	}
}
