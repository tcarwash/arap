package challenge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/tcarwash/arap/protocol"
)

func fixture(t *testing.T) ([]byte, []byte, *protocol.Ed25519Verifier, string, time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	req, err := NewRequest("K7ABC", "AG7SU", AuthPurpose, []byte("session-42"), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	signer, err := protocol.NewEd25519Signer("AG7SU", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := protocol.NewEd25519Verifier(private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := Respond(signer, request, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.KeyID(verifier.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return request, response, verifier, hex.EncodeToString(id), now
}

func openStore(t *testing.T, path string) *SQLiteStore {
	t.Helper()
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func issue(t *testing.T, store Store, request []byte) {
	t.Helper()
	r, err := DecodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	h := RequestHash(request)
	if err := store.Issue(h[:], r.Requester, r.Responder, r.ExpiresAt); err != nil {
		t.Fatal(err)
	}
}

func TestChallengeResponseConsumesOnceAcrossReopen(t *testing.T) {
	request, response, verifier, keyID, now := fixture(t)
	path := filepath.Join(t.TempDir(), "challenges.sqlite")
	store := openStore(t, path)
	issue(t, store, request)
	result := VerifyResponse(request, response, verifier, func(c, id, p string) bool { return c == "AG7SU" && id == keyID && p == ResponsePurpose }, store, "K7ABC", now.Add(2*time.Second))
	if result.OverallPolicy != "accepted" || result.ChallengeFreshness != "valid" {
		t.Fatalf("response not accepted: %#v", result)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openStore(t, path)
	replay := VerifyResponse(request, response, verifier, func(string, string, string) bool { return true }, store, "K7ABC", now.Add(3*time.Second))
	if replay.OverallPolicy != "rejected" || replay.Reason != "challenge_not_pending_or_replayed" {
		t.Fatalf("replay accepted: %#v", replay)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("database mode = %o, want 600", info.Mode().Perm())
	}
}

func TestMutualChallengePairAcceptedAndReplayRejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := openStore(t, filepath.Join(t.TempDir(), "mutual.sqlite"))
	requests, err := NewMutualRequests(store, "K7ABC", "AG7SU", AuthPurpose, []byte("tls-exporter-session-7"), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	privateA := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	privateB := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	signerA, err := protocol.NewEd25519Signer("K7ABC", privateA)
	if err != nil {
		t.Fatal(err)
	}
	signerB, err := protocol.NewEd25519Signer("AG7SU", privateB)
	if err != nil {
		t.Fatal(err)
	}
	verifierA, err := protocol.NewEd25519Verifier(privateA.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	verifierB, err := protocol.NewEd25519Verifier(privateB.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	responseFromA, _, err := Respond(signerA, requests.FromB, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	responseFromB, _, err := Respond(signerB, requests.FromA, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	keyIDA, err := protocol.KeyID(verifierA.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	keyIDB, err := protocol.KeyID(verifierB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	trustA := func(call, id, purpose string) string {
		if call == "K7ABC" && id == hex.EncodeToString(keyIDA) && purpose == ResponsePurpose {
			return "trusted"
		}
		return "untrusted"
	}
	trustB := func(call, id, purpose string) string {
		if call == "AG7SU" && id == hex.EncodeToString(keyIDB) && purpose == ResponsePurpose {
			return "trusted"
		}
		return "untrusted"
	}
	tamperedResponseFromA := append([]byte(nil), responseFromA...)
	tamperedResponseFromA[len(tamperedResponseFromA)-1] ^= 1
	config := MutualVerificationConfig{VerifierA: verifierA, TrustA: trustA, VerifierB: verifierB, TrustB: trustB, Store: store, Session: []byte("tls-exporter-session-7"), Now: now.Add(2 * time.Second)}
	responses := MutualResponses{FromA: tamperedResponseFromA, FromB: responseFromB}
	result := VerifyMutualPair(requests, responses, config)
	if result.Accepted || result.Reason != "party_a_response_invalid_signature_or_envelope" {
		t.Fatalf("invalid responder identity was not rejected before consumption: %+v", result)
	}
	responses.FromA = responseFromA
	config.Session = []byte("different-session")
	wrongSession := VerifyMutualPair(requests, responses, config)
	if wrongSession.Accepted || wrongSession.Reason != "mutual_purpose_or_session_mismatch" {
		t.Fatalf("mutual pair accepted for another session: %+v", wrongSession)
	}
	config.Session = []byte("tls-exporter-session-7")
	result = VerifyMutualPair(requests, responses, config)
	if !result.Accepted || result.PartyA != "K7ABC" || result.PartyB != "AG7SU" {
		t.Fatalf("mutual pair rejected: %+v", result)
	}
	config.Now = now.Add(3 * time.Second)
	replay := VerifyMutualPair(requests, responses, config)
	if replay.Accepted || replay.Reason != "mutual_challenge_pair_not_pending_or_replayed" {
		t.Fatalf("mutual pair replay accepted: %+v", replay)
	}
}

func TestConsumePairRollsBackPartialConsumption(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := openStore(t, filepath.Join(t.TempDir(), "pair-atomic.sqlite"))
	requests, err := NewMutualRequests(store, "K7ABC", "AG7SU", AuthPurpose, []byte("session-atomic"), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	hashA := RequestHash(requests.FromA)
	missing := bytes.Repeat([]byte{0xEE}, sha256.Size)
	consumed, err := store.ConsumePair(hashA[:], missing, now.Add(time.Second).Unix())
	if err != nil || consumed {
		t.Fatalf("pair consumed with one missing challenge: consumed=%v err=%v", consumed, err)
	}
	if consumed, err := store.Consume(hashA[:], now.Add(time.Second).Unix()); err != nil || !consumed {
		t.Fatalf("first challenge was not rolled back: consumed=%v err=%v", consumed, err)
	}
}

func TestConcurrentMutualPairConsumptionHasOneWinner(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store := openStore(t, filepath.Join(t.TempDir(), "pair-concurrent.sqlite"))
	requests, err := NewMutualRequests(store, "K7ABC", "AG7SU", AuthPurpose, []byte("session-concurrent"), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	hashA := RequestHash(requests.FromA)
	hashB := RequestHash(requests.FromB)
	start := make(chan struct{})
	results := make(chan bool, 2)
	errors := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			consumed, err := store.ConsumePair(hashA[:], hashB[:], now.Add(time.Second).Unix())
			if err != nil {
				errors <- err
				return
			}
			results <- consumed
		}()
	}
	close(start)
	twins := 0
	for range 2 {
		select {
		case err := <-errors:
			t.Fatal(err)
		case consumed := <-results:
			if consumed {
				twins++
			}
		}
	}
	if twins != 1 {
		t.Fatalf("successful pair consumptions=%d, want 1", twins)
	}
}

func TestCancelPendingLeavesConsumedChallengeUntouched(t *testing.T) {
	request, _, _, _, now := fixture(t)
	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	h := RequestHash(request)
	store := openStore(t, filepath.Join(t.TempDir(), "db.sqlite"))
	if err := store.Issue(h[:], decoded.Requester, decoded.Responder, decoded.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := store.CancelPending(h[:]); err != nil {
		t.Fatal(err)
	}
	if consumed, err := store.Consume(h[:], now.Unix()); err != nil || consumed {
		t.Fatalf("canceled pending challenge consumed=%v err=%v", consumed, err)
	}
	if err := store.Issue(h[:], decoded.Requester, decoded.Responder, decoded.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if consumed, err := store.Consume(h[:], now.Unix()); err != nil || !consumed {
		t.Fatalf("consume challenge consumed=%v err=%v", consumed, err)
	}
	if err := store.CancelPending(h[:]); err != nil {
		t.Fatal(err)
	}
	if consumed, err := store.Consume(h[:], now.Unix()); err != nil || consumed {
		t.Fatalf("consumed challenge was restored by cancel: consumed=%v err=%v", consumed, err)
	}
}

func TestConcurrentResponseVerificationHasSingleWinner(t *testing.T) {
	request, response, verifier, keyID, now := fixture(t)
	path := filepath.Join(t.TempDir(), "shared.sqlite")
	issuer := openStore(t, path)
	issue(t, issuer, request)
	// Independent handles model separate application processes sharing the DB.
	_ = issuer.Close()
	stores := []*SQLiteStore{openStore(t, path), openStore(t, path)}
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for _, store := range stores {
		wg.Add(1)
		go func(s *SQLiteStore) {
			defer wg.Done()
			result := VerifyResponse(request, response, verifier, func(c, id, p string) bool { return c == "AG7SU" && id == keyID && p == ResponsePurpose }, s, "K7ABC", now.Add(2*time.Second))
			if result.OverallPolicy == "accepted" {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}(store)
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("accepted %d concurrent replays, want exactly one", accepted)
	}
}

func TestSQLiteConsumeHasSingleWinnerAcrossProcesses(t *testing.T) {
	request, _, _, _, _ := fixture(t)
	dir := t.TempDir()
	// A question mark in the database filename checks URI path escaping too.
	dbPath := filepath.Join(dir, "state ? challenge.sqlite")
	store, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	hash := RequestHash(request)
	if err := store.Issue(hash[:], decoded.Requester, decoded.Responder, decoded.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	const workers = 6
	gate := filepath.Join(dir, "consume.gate")
	cmds := make([]*exec.Cmd, workers)
	outputs := make([]bytes.Buffer, workers)
	for i := range cmds {
		cmds[i] = exec.Command(os.Args[0], "-test.v", "-test.run=^TestSQLiteConsumeSubprocessHelper$")
		cmds[i].Env = append(os.Environ(), "ARAP_CONSUME_DB="+dbPath, "ARAP_CONSUME_HASH="+hex.EncodeToString(hash[:]), "ARAP_CONSUME_GATE="+gate, fmt.Sprintf("ARAP_CONSUME_READY=%s.%d", gate, i))
		cmds[i].Stdout = &outputs[i]
		cmds[i].Stderr = &outputs[i]
		if err := cmds[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(15 * time.Second)
	for i := 0; i < workers; i++ {
		ready := fmt.Sprintf("%s.%d", gate, i)
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("subprocess %d did not become ready", i)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := os.WriteFile(gate, []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	winners := 0
	for i, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("subprocess %d failed: %v\n%s", i, err, outputs[i].String())
		}
		if strings.Contains(outputs[i].String(), "ARAP_CONSUME_WINNER") {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("%d processes consumed one challenge, want exactly one", winners)
	}
}

func TestSQLiteConsumeSubprocessHelper(t *testing.T) {
	dbPath := os.Getenv("ARAP_CONSUME_DB")
	if dbPath == "" {
		t.Skip("subprocess helper")
	}
	hash, err := hex.DecodeString(os.Getenv("ARAP_CONSUME_HASH"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.WriteFile(os.Getenv("ARAP_CONSUME_READY"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(os.Getenv("ARAP_CONSUME_GATE")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for process barrier")
		}
		time.Sleep(5 * time.Millisecond)
	}
	consumed, err := store.Consume(hash, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if consumed {
		fmt.Println("ARAP_CONSUME_WINNER")
	} else {
		fmt.Println("ARAP_CONSUME_LOSER")
	}
}

func FuzzDecodeChallengeRequest(f *testing.F) {
	if data, err := os.ReadFile("../test-vectors/challenge-ed25519-v1/request.cbor"); err == nil {
		f.Add(data)
	}
	f.Add([]byte{})
	f.Add([]byte{0xbf, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		_, _ = DecodeRequest(data)
	})
}

func FuzzVerifyChallengeResponse(f *testing.F) {
	now := time.Unix(1_800_000_000, 0).UTC()
	challengeRequest, err := NewRequest("K7ABC", "AG7SU", AuthPurpose, []byte("session-42"), now, time.Minute)
	if err != nil {
		f.Fatal(err)
	}
	request, err := EncodeRequest(challengeRequest)
	if err != nil {
		f.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	signer, err := protocol.NewEd25519Signer("AG7SU", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		f.Fatal(err)
	}
	verifier, err := protocol.NewEd25519Verifier(signer.PublicKey().(ed25519.PublicKey))
	if err != nil {
		f.Fatal(err)
	}
	proof, _, err := Respond(signer, request, now.Add(time.Second))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(request, proof)
	f.Add(request, []byte{})
	f.Add(request, []byte{0xd2, 0x84, 0x43, 0xa1})
	f.Fuzz(func(t *testing.T, encodedRequest, response []byte) {
		if len(encodedRequest) > 4096 || len(response) > protocol.MaxProofSize {
			t.Skip()
		}
		store := &memoryStore{pending: true}
		_ = VerifyResponse(encodedRequest, response, verifier,
			func(string, string, string) bool { return true }, store, "K7ABC", now.Add(2*time.Second))
	})
}

func TestChallengeResponseRejectsMalformedCOSEAndPayloadSchemas(t *testing.T) {
	request, proof, verifier, _, now := fixture(t)
	var tag cbor.Tag
	if err := protocol.DecodeCanonical(proof, &tag); err != nil {
		t.Fatal(err)
	}
	items, ok := tag.Content.([]any)
	if !ok || len(items) != 4 {
		t.Fatalf("fixture COSE shape is invalid: %#v", tag.Content)
	}
	encodeTag := func(content []any) []byte {
		t.Helper()
		encoded, err := protocol.EncodeCanonical(cbor.Tag{Number: 18, Content: content})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	untagged, err := protocol.EncodeCanonical(items)
	if err != nil {
		t.Fatal(err)
	}
	unprotectedItems := append([]any(nil), items...)
	unprotectedItems[1] = map[uint64]any{99: "unexpected"}
	withUnprotected := encodeTag(unprotectedItems)
	noncanonical := append([]byte{0xd2, 0x9f}, proof[2:]...)
	noncanonical = append(noncanonical, 0xff)

	var payload map[uint64]any
	if err := protocol.DecodeCanonical(items[2].([]byte), &payload); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	signer, err := protocol.NewEd25519Signer("AG7SU", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	unknownPayload := make(map[uint64]any, len(payload)+1)
	for key, value := range payload {
		unknownPayload[key] = value
	}
	unknownPayload[8] = "extension"
	unknownPayloadBytes, err := protocol.EncodeCanonical(unknownPayload)
	if err != nil {
		t.Fatal(err)
	}
	unknownFields, err := protocol.SignPayload(signer, unknownPayloadBytes)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		proof []byte
	}{
		{"untagged COSE_Sign1", untagged},
		{"unprotected header", withUnprotected},
		{"noncanonical outer array", noncanonical},
		{"unknown signed payload field", unknownFields},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := VerifyResponse(request, tc.proof, verifier, func(string, string, string) bool { return true },
				&memoryStore{pending: true}, "K7ABC", now.Add(2*time.Second))
			if result.OverallPolicy != "rejected" {
				t.Fatalf("accepted malformed response: %#v", result)
			}
		})
	}
}

func TestUntrustedResponseDoesNotConsumeChallenge(t *testing.T) {
	request, response, verifier, keyID, now := fixture(t)
	store := openStore(t, filepath.Join(t.TempDir(), "db.sqlite"))
	issue(t, store, request)
	disabled := VerifyResponseWithTrust(request, response, verifier, func(string, string, string) string { return "disabled" }, store, "K7ABC", now.Add(2*time.Second))
	if disabled.Reason != "key_disabled" || disabled.CallsignIdentity != "rejected" {
		t.Fatalf("disabled key result: %#v", disabled)
	}
	denied := VerifyResponse(request, response, verifier, func(string, string, string) bool { return false }, store, "K7ABC", now.Add(2*time.Second))
	if denied.OverallPolicy != "rejected" || denied.Reason != "key_not_trusted" {
		t.Fatalf("untrusted response result: %#v", denied)
	}
	accepted := VerifyResponse(request, response, verifier, func(c, id, p string) bool { return c == "AG7SU" && id == keyID && p == ResponsePurpose }, store, "K7ABC", now.Add(2*time.Second))
	if accepted.OverallPolicy != "accepted" {
		t.Fatalf("untrusted response consumed the challenge: %#v", accepted)
	}
}

func TestExpiredChallengeCannotBeConsumed(t *testing.T) {
	request, response, verifier, _, now := fixture(t)
	store := openStore(t, filepath.Join(t.TempDir(), "db.sqlite"))
	issue(t, store, request)
	result := VerifyResponse(request, response, verifier, func(string, string, string) bool { return true }, store, "K7ABC", now.Add(2*time.Minute))
	if result.OverallPolicy != "rejected" || result.Reason != "challenge_expired_or_not_yet_valid" || result.CryptographicSignature != "valid" || result.ChallengeFreshness != "rejected" {
		t.Fatalf("expired challenge accepted: %#v", result)
	}
	corruptBytes := append([]byte(nil), response...)
	corruptBytes[len(corruptBytes)-1] ^= 1
	corrupt := VerifyResponse(request, corruptBytes, verifier, func(string, string, string) bool { return true }, store, "K7ABC", now.Add(2*time.Minute))
	if corrupt.CryptographicSignature != "invalid" || corrupt.ChallengeFreshness != "not_checked" || corrupt.Reason != "invalid_signature_or_envelope" {
		t.Fatalf("corrupt response to expired challenge was not classified as invalid signature: %#v", corrupt)
	}
	fresh := VerifyResponse(request, response, verifier, func(string, string, string) bool { return true }, store, "K7ABC", now.Add(2*time.Second))
	if fresh.OverallPolicy != "accepted" {
		t.Fatalf("expired and invalid responses consumed the outstanding challenge: %#v", fresh)
	}
}

type failingStore struct{}

func (failingStore) Issue([]byte, string, string, int64) error { return nil }
func (failingStore) Consume([]byte, int64) (bool, error)       { return false, os.ErrPermission }

func TestStoreFailureNeverAuthenticates(t *testing.T) {
	request, response, verifier, _, now := fixture(t)
	result := VerifyResponse(request, response, verifier, func(string, string, string) bool { return true }, failingStore{}, "K7ABC", now.Add(2*time.Second))
	if result.OverallPolicy != "rejected" || result.ChallengeFreshness != "unknown" || result.Reason != "challenge_store_error" {
		t.Fatalf("storage failure authenticated: %#v", result)
	}
}

func TestWrongRequesterDoesNotConsumeChallenge(t *testing.T) {
	request, response, verifier, keyID, now := fixture(t)
	store := openStore(t, filepath.Join(t.TempDir(), "audience.sqlite"))
	issue(t, store, request)
	trust := func(c, id, p string) bool { return c == "AG7SU" && id == keyID && p == ResponsePurpose }
	wrong := VerifyResponse(request, response, verifier, trust, store, "W1XYZ", now.Add(2*time.Second))
	if wrong.Reason != "requester_mismatch" {
		t.Fatalf("wrong requester result: %#v", wrong)
	}
	valid := VerifyResponse(request, response, verifier, trust, store, "K7ABC", now.Add(2*time.Second))
	if valid.OverallPolicy != "accepted" {
		t.Fatalf("wrong requester consumed challenge: %#v", valid)
	}
}

func TestResponderKeyMustMatchChallengeAudience(t *testing.T) {
	request, _, _, _, now := fixture(t)
	wrongPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	wrongSigner, err := protocol.NewEd25519Signer("W1XYZ", wrongPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Respond(wrongSigner, request, now.Add(time.Second)); err == nil {
		t.Fatal("signed response with a key whose callsign differs from the requested responder")
	}
}

func TestRequestConstructionRejectsInvalidTimeAndPurpose(t *testing.T) {
	if _, err := NewRequest("K7ABC", "AG7SU", AuthPurpose, nil, time.Unix(-1, 0), time.Minute); err == nil {
		t.Fatal("created a pre-epoch challenge")
	}
	if _, err := NewRequest("K7ABC", "AG7SU", AuthPurpose, nil, time.Unix(1_800_000_000, 0), 500*time.Millisecond); err == nil {
		t.Fatal("created a challenge with zero whole-second lifetime")
	}
	if _, err := NewRequest("K7ABC", "AG7SU", string([]byte{0xff}), nil, time.Unix(1_800_000_000, 0), time.Minute); err == nil {
		t.Fatal("created a challenge with invalid UTF-8 purpose")
	}
}

func TestDecodeRequestRejectsPresentEmptySessionBinding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	request, err := NewRequest("K7ABC", "AG7SU", AuthPurpose, nil, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[uint64]any
	if err := protocol.DecodeCanonical(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	fields[10] = []byte{}
	encoded, err = protocol.EncodeCanonical(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(encoded); err == nil {
		t.Fatal("accepted explicitly empty optional session binding")
	}
}

func TestPythonChallengeVectorMatchesGo(t *testing.T) {
	base := "../test-vectors/challenge-ed25519-v1/"
	request, err := os.ReadFile(base + "request.cbor")
	if err != nil {
		t.Fatal(err)
	}
	wantProof, err := os.ReadFile(base + "response.cose")
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := os.ReadFile(base + "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RequestHash    string          `json:"request_sha256"`
		KeyID          string          `json:"key_id_sha256"`
		NegativeChecks map[string]bool `json:"negative_checks"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"edited_request_binding", "wrong_requester", "corrupt_signature", "expired_request"} {
		if !manifest.NegativeChecks[name] {
			t.Fatalf("independent Python negative check %q did not reject", name)
		}
	}
	req, err := DecodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	requestHash := RequestHash(request)
	if hex.EncodeToString(requestHash[:]) != manifest.RequestHash {
		t.Fatal("request hash differs from Python manifest")
	}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	signer, err := protocol.NewEd25519Signer("AG7SU", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := Respond(signer, request, time.Unix(req.IssuedAt+1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(proof, wantProof) {
		t.Fatalf("Go challenge COSE bytes differ from Python vector\n got %x\nwant %x", proof, wantProof)
	}
	verifier, err := protocol.NewEd25519Verifier(signer.PublicKey().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{pending: true}
	result := VerifyResponse(request, wantProof, verifier, func(call, id, purpose string) bool {
		return call == "AG7SU" && id == manifest.KeyID && purpose == ResponsePurpose
	}, store, "K7ABC", time.Unix(req.IssuedAt+2, 0))
	if result.OverallPolicy != "accepted" {
		t.Fatalf("Python challenge vector rejected: %#v", result)
	}
}

type memoryStore struct{ pending bool }

func (m *memoryStore) Issue([]byte, string, string, int64) error { m.pending = true; return nil }
func (m *memoryStore) Consume([]byte, int64) (bool, error) {
	if !m.pending {
		return false, nil
	}
	m.pending = false
	return true, nil
}

func TestChallengeRequestAndResponseBindEveryField(t *testing.T) {
	request, response, verifier, keyID, now := fixture(t)
	decoded, err := DecodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded.Session = []byte("different-session")
	altered, err := EncodeRequest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	store := openStore(t, filepath.Join(t.TempDir(), "db.sqlite"))
	issue(t, store, altered)
	result := VerifyResponse(altered, response, verifier, func(string, string, string) bool { return true }, store, "K7ABC", now.Add(2*time.Second))
	if result.OverallPolicy != "rejected" || result.Reason != "request_hash_mismatch" {
		t.Fatalf("altered request accepted: %#v", result)
	}
	// A request byte change is itself rejected unless it remains canonical and valid.
	bad := append([]byte(nil), request...)
	bad[len(bad)-1] ^= 1
	if bytes.Equal(bad, request) {
		t.Fatal("fixture mutation did not change bytes")
	}
	if _, err := DecodeRequest(bad); err == nil { // Some byte flips remain valid; they must still change the request digest.
		if RequestHash(bad) == RequestHash(request) {
			t.Fatal("hash did not change")
		}
	}
	_ = keyID
}
