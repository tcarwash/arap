// Package challenge implements ARAP's request-bound, single-use station challenge profile.
package challenge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/tcarwash/arap/protocol"
)

const (
	RequestPurpose  = "challenge-request"
	ResponsePurpose = "challenge-response"
	AuthPurpose     = "station-auth"
	DefaultLifetime = 120 * time.Second
	MaxLifetime     = 10 * time.Minute
	MaxFutureSkew   = 30 * time.Second
)

type Request struct {
	Requester string
	Responder string
	Nonce     []byte
	IssuedAt  int64
	ExpiresAt int64
	Purpose   string
	Session   []byte
}

type ResponseClaims struct {
	Requester      string `json:"requester"`
	Responder      string `json:"responder"`
	Purpose        string `json:"purpose"`
	RequestHash    string `json:"request_sha256"`
	ExpiresAt      int64  `json:"expires_at"`
	SessionBinding string `json:"session_binding_sha256,omitempty"`
}

type Result struct {
	CryptographicSignature string          `json:"cryptographic_signature"`
	CallsignIdentity       string          `json:"callsign_identity"`
	ChallengeFreshness     string          `json:"challenge_freshness"`
	OverallPolicy          string          `json:"overall_policy"`
	Reason                 string          `json:"reason,omitempty"`
	Claims                 *ResponseClaims `json:"claims,omitempty"`
}

type TrustFunc func(callsign, keyID, purpose string) bool
type TrustDecisionFunc func(callsign, keyID, purpose string) string

type Store interface {
	Issue(requestHash []byte, requester, responder string, expiresAt int64) error
	Consume(requestHash []byte, now int64) (bool, error)
}

// LifecycleStore is the complete storage contract for an application that
// issues requests. Implementations must make Issue unique by request hash,
// Consume atomic and single-use, CancelPending conditional on pending state,
// and PruneExpired safe to call concurrently. A verifier can use Store when
// it does not own issuance or cleanup.
type LifecycleStore interface {
	Store
	CancelPending(requestHash []byte) error
	PruneExpired(now int64) error
}

// PairStore adds atomic issuance rollback and one-transaction consumption for
// coordinated mutual authentication.
type PairStore interface {
	Store
	CancelPending(requestHash []byte) error
	ConsumePair(firstHash, secondHash []byte, now int64) (bool, error)
}

type MutualRequests struct {
	// FromA is a request from party A that party B must answer.
	FromA []byte
	// FromB is a request from party B that party A must answer.
	FromB []byte
}

// MutualResponses contains each party's response to the request addressed to
// it: FromA answers MutualRequests.FromB, and FromB answers MutualRequests.FromA.
type MutualResponses struct {
	FromA []byte
	FromB []byte
}

type MutualVerificationConfig struct {
	VerifierA protocol.Verifier
	TrustA    TrustDecisionFunc
	VerifierB protocol.Verifier
	TrustB    TrustDecisionFunc
	Store     PairStore
	Session   []byte
	Now       time.Time
}

type MutualResult struct {
	Accepted       bool   `json:"accepted"`
	PartyA         string `json:"party_a,omitempty"`
	PartyB         string `json:"party_b,omitempty"`
	Purpose        string `json:"purpose,omitempty"`
	SessionBinding string `json:"session_binding_sha256,omitempty"`
	Reason         string `json:"reason,omitempty"`
	ResponseA      Result `json:"response_from_a"`
	ResponseB      Result `json:"response_from_b"`
}

func NewRequest(requester, responder, purpose string, session []byte, now time.Time, lifetime time.Duration) (Request, error) {
	requester, err := protocol.NormalizeCallsign(requester)
	if err != nil {
		return Request{}, fmt.Errorf("requester: %w", err)
	}
	responder, err = protocol.NormalizeCallsign(responder)
	if err != nil {
		return Request{}, fmt.Errorf("responder: %w", err)
	}
	if requester == responder {
		return Request{}, errors.New("requester and responder must differ")
	}
	if purpose == "" || len(purpose) > 64 || !utf8.ValidString(purpose) {
		return Request{}, errors.New("purpose must be 1..64 valid UTF-8 bytes")
	}
	if lifetime <= 0 {
		lifetime = DefaultLifetime
	}
	if lifetime > MaxLifetime {
		return Request{}, fmt.Errorf("challenge lifetime exceeds %s", MaxLifetime)
	}
	if len(session) > 128 {
		return Request{}, errors.New("session binding exceeds 128 bytes")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Request{}, err
	}
	issued := now.UTC().Unix()
	expires := now.UTC().Add(lifetime).Unix()
	if issued < 0 || expires <= issued {
		return Request{}, errors.New("challenge time bounds must span at least one non-negative Unix second")
	}
	return Request{Requester: requester, Responder: responder, Nonce: nonce, IssuedAt: issued, ExpiresAt: expires, Purpose: purpose, Session: append([]byte(nil), session...)}, nil
}

// NewMutualRequests creates and records two inverse challenges with the same
// purpose, validity window, and non-empty application session binding. The
// caller should use a unique binding for the session (for example, an
// application channel-binding value), not a reusable room or account name.
func NewMutualRequests(store PairStore, partyA, partyB, purpose string, session []byte, now time.Time, lifetime time.Duration) (MutualRequests, error) {
	if store == nil || len(session) == 0 {
		return MutualRequests{}, errors.New("pair store and non-empty session binding are required")
	}
	requestA, err := NewRequest(partyA, partyB, purpose, session, now, lifetime)
	if err != nil {
		return MutualRequests{}, err
	}
	requestB, err := NewRequest(partyB, partyA, purpose, session, now, lifetime)
	if err != nil {
		return MutualRequests{}, err
	}
	encodedA, err := EncodeRequest(requestA)
	if err != nil {
		return MutualRequests{}, err
	}
	encodedB, err := EncodeRequest(requestB)
	if err != nil {
		return MutualRequests{}, err
	}
	hashA := RequestHash(encodedA)
	if err := store.Issue(hashA[:], requestA.Requester, requestA.Responder, requestA.ExpiresAt); err != nil {
		return MutualRequests{}, fmt.Errorf("record party A challenge: %w", err)
	}
	hashB := RequestHash(encodedB)
	if err := store.Issue(hashB[:], requestB.Requester, requestB.Responder, requestB.ExpiresAt); err != nil {
		if cancelErr := store.CancelPending(hashA[:]); cancelErr != nil {
			return MutualRequests{}, fmt.Errorf("record party B challenge: %w (also failed to cancel party A challenge: %v)", err, cancelErr)
		}
		return MutualRequests{}, fmt.Errorf("record party B challenge: %w", err)
	}
	return MutualRequests{FromA: encodedA, FromB: encodedB}, nil
}

func EncodeRequest(r Request) ([]byte, error) {
	if err := validateRequest(r); err != nil {
		return nil, err
	}
	m := map[uint64]any{1: protocol.Profile, 2: protocol.Version, 3: RequestPurpose, 4: r.Requester, 5: r.Responder, 6: r.Nonce, 7: r.IssuedAt, 8: r.ExpiresAt, 9: r.Purpose}
	if len(r.Session) != 0 {
		m[10] = r.Session
	}
	return protocol.EncodeCanonical(m)
}

func DecodeRequest(data []byte) (Request, error) {
	if len(data) == 0 || len(data) > 4096 {
		return Request{}, errors.New("challenge request must be 1..4096 bytes")
	}
	var m map[uint64]any
	if err := protocol.DecodeCanonical(data, &m); err != nil {
		return Request{}, fmt.Errorf("invalid challenge request CBOR: %w", err)
	}
	if len(m) < 9 || len(m) > 10 {
		return Request{}, errors.New("invalid challenge request fields")
	}
	for k := range m {
		if k < 1 || k > 10 {
			return Request{}, fmt.Errorf("unknown challenge request label %d", k)
		}
	}
	text := func(k uint64) (string, error) {
		v, ok := m[k].(string)
		if !ok {
			return "", fmt.Errorf("label %d must be text", k)
		}
		return v, nil
	}
	bytesAt := func(k uint64) ([]byte, error) {
		v, ok := m[k].([]byte)
		if !ok {
			return nil, fmt.Errorf("label %d must be bytes", k)
		}
		return v, nil
	}
	uintAt := func(k uint64) (int64, error) {
		switch v := m[k].(type) {
		case uint64:
			if v > 1<<63-1 {
				return 0, fmt.Errorf("label %d out of range", k)
			}
			return int64(v), nil
		case int64:
			if v < 0 {
				return 0, fmt.Errorf("label %d negative", k)
			}
			return v, nil
		default:
			return 0, fmt.Errorf("label %d must be integer", k)
		}
	}
	profile, err := text(1)
	if err != nil || profile != protocol.Profile {
		return Request{}, errors.New("invalid challenge profile")
	}
	version, err := uintAt(2)
	if err != nil || uint64(version) != protocol.Version {
		return Request{}, errors.New("unsupported challenge version")
	}
	kind, err := text(3)
	if err != nil || kind != RequestPurpose {
		return Request{}, errors.New("invalid challenge request purpose")
	}
	req, err := text(4)
	if err != nil {
		return Request{}, err
	}
	resp, err := text(5)
	if err != nil {
		return Request{}, err
	}
	nonce, err := bytesAt(6)
	if err != nil {
		return Request{}, err
	}
	issued, err := uintAt(7)
	if err != nil {
		return Request{}, err
	}
	expires, err := uintAt(8)
	if err != nil {
		return Request{}, err
	}
	purpose, err := text(9)
	if err != nil {
		return Request{}, err
	}
	var session []byte
	if _, exists := m[10]; exists {
		session, err = bytesAt(10)
		if err != nil {
			return Request{}, err
		}
		if len(session) == 0 {
			return Request{}, errors.New("session binding must contain 1..128 bytes when present")
		}
	}
	r := Request{Requester: req, Responder: resp, Nonce: nonce, IssuedAt: issued, ExpiresAt: expires, Purpose: purpose, Session: session}
	if err := validateRequest(r); err != nil {
		return Request{}, err
	}
	return r, nil
}

func validateRequest(r Request) error {
	req, err := protocol.NormalizeCallsign(r.Requester)
	if err != nil || req != r.Requester {
		return errors.New("requester callsign is not normalized")
	}
	resp, err := protocol.NormalizeCallsign(r.Responder)
	if err != nil || resp != r.Responder {
		return errors.New("responder callsign is not normalized")
	}
	if req == resp {
		return errors.New("requester and responder must differ")
	}
	if len(r.Nonce) != 16 {
		return errors.New("challenge nonce must be 16 bytes")
	}
	if r.IssuedAt < 0 || r.ExpiresAt <= r.IssuedAt || r.ExpiresAt-r.IssuedAt > int64(MaxLifetime/time.Second) {
		return errors.New("invalid challenge time bounds")
	}
	if r.Purpose == "" || len(r.Purpose) > 64 || !utf8.ValidString(r.Purpose) {
		return errors.New("invalid challenge purpose")
	}
	if len(r.Session) > 128 {
		return errors.New("session binding exceeds 128 bytes")
	}
	return nil
}

func RequestHash(encoded []byte) [32]byte { return sha256.Sum256(encoded) }

// IssueRequest creates, encodes, and records a challenge before returning its
// bytes. The caller can then publish them over its own transport. If publishing
// fails, call CancelRequest; cancellation never removes a consumed challenge.
func IssueRequest(store LifecycleStore, requester, responder, purpose string, session []byte, now time.Time, lifetime time.Duration) ([]byte, error) {
	if store == nil {
		return nil, errors.New("challenge lifecycle store is required")
	}
	request, err := NewRequest(requester, responder, purpose, session, now, lifetime)
	if err != nil {
		return nil, err
	}
	encoded, err := EncodeRequest(request)
	if err != nil {
		return nil, err
	}
	hash := RequestHash(encoded)
	if err := store.PruneExpired(now.UTC().Unix()); err != nil {
		return nil, fmt.Errorf("prune expired challenges: %w", err)
	}
	if err := store.Issue(hash[:], request.Requester, request.Responder, request.ExpiresAt); err != nil {
		return nil, err
	}
	return encoded, nil
}

// CancelRequest removes a pending issued request after publication fails.
func CancelRequest(store LifecycleStore, encoded []byte) error {
	if store == nil {
		return errors.New("challenge lifecycle store is required")
	}
	if _, err := DecodeRequest(encoded); err != nil {
		return err
	}
	hash := RequestHash(encoded)
	return store.CancelPending(hash[:])
}

func Respond(signer protocol.Signer, encodedRequest []byte, now time.Time) ([]byte, ResponseClaims, error) {
	if signer == nil {
		return nil, ResponseClaims{}, errors.New("signer is required")
	}
	r, err := DecodeRequest(encodedRequest)
	if err != nil {
		return nil, ResponseClaims{}, err
	}
	if signerCall, err := protocol.NormalizeCallsign(signer.Callsign()); err != nil || signerCall != r.Responder {
		return nil, ResponseClaims{}, errors.New("signing key callsign does not match challenge responder")
	}
	if now.UTC().Unix() < r.IssuedAt-int64(MaxFutureSkew/time.Second) || now.UTC().Unix() >= r.ExpiresAt {
		return nil, ResponseClaims{}, errors.New("challenge is not currently valid")
	}
	h := RequestHash(encodedRequest)
	subject := map[uint64]any{1: h[:], 2: r.Nonce, 3: r.Requester, 4: r.Responder, 5: r.Purpose, 6: r.ExpiresAt}
	claims := ResponseClaims{Requester: r.Requester, Responder: r.Responder, Purpose: r.Purpose, RequestHash: hex.EncodeToString(h[:]), ExpiresAt: r.ExpiresAt}
	if len(r.Session) != 0 {
		subject[7] = r.Session
		sh := sha256.Sum256(r.Session)
		claims.SessionBinding = hex.EncodeToString(sh[:])
	}
	payload, err := protocol.EncodeCanonical(map[uint64]any{1: protocol.Profile, 2: protocol.Version, 3: ResponsePurpose, 4: r.Responder, 5: now.UTC().Unix(), 6: r.ExpiresAt, 7: subject})
	if err != nil {
		return nil, ResponseClaims{}, err
	}
	proof, err := protocol.SignPayload(signer, payload)
	return proof, claims, err
}

func VerifyResponse(encodedRequest, proof []byte, verifier protocol.Verifier, trust TrustFunc, store Store, expectedRequester string, now time.Time) Result {
	var decision TrustDecisionFunc
	if trust != nil {
		decision = func(c, k, p string) string {
			if trust(c, k, p) {
				return "trusted"
			}
			return "untrusted"
		}
	}
	return VerifyResponseWithTrust(encodedRequest, proof, verifier, decision, store, expectedRequester, now)
}

func VerifyResponseWithTrust(encodedRequest, proof []byte, verifier protocol.Verifier, trust TrustDecisionFunc, store Store, expectedRequester string, now time.Time) Result {
	return verifyResponse(encodedRequest, proof, verifier, trust, store, expectedRequester, now, true)
}

func verifyResponse(encodedRequest, proof []byte, verifier protocol.Verifier, trust TrustDecisionFunc, store Store, expectedRequester string, now time.Time, consume bool) Result {
	result := Result{CryptographicSignature: "not_checked", CallsignIdentity: "not_checked", ChallengeFreshness: "not_checked", OverallPolicy: "rejected"}
	fail := func(reason string) Result { result.Reason = reason; return result }
	if (consume && store == nil) || verifier == nil || trust == nil {
		return fail("missing_verifier_trust_or_store")
	}
	r, err := DecodeRequest(encodedRequest)
	if err != nil {
		return fail("invalid_request")
	}
	requester, err := protocol.NormalizeCallsign(expectedRequester)
	if err != nil || requester != r.Requester {
		return fail("requester_mismatch")
	}
	current := now.UTC().Unix()
	payloadBytes, kid, err := protocol.VerifyPayload(proof, verifier)
	if err != nil {
		result.CryptographicSignature = "invalid"
		return fail("invalid_signature_or_envelope")
	}
	result.CryptographicSignature = "valid"
	if current < r.IssuedAt-int64(MaxFutureSkew/time.Second) || current >= r.ExpiresAt {
		result.ChallengeFreshness = "rejected"
		return fail("challenge_expired_or_not_yet_valid")
	}
	var payload map[uint64]any
	if err := protocol.DecodeCanonical(payloadBytes, &payload); err != nil {
		return fail("malformed_response_payload")
	}
	if len(payload) != 7 {
		return fail("response_payload_fields")
	}
	for k := range payload {
		if k < 1 || k > 7 {
			return fail("response_payload_fields")
		}
	}
	if payload[1] != protocol.Profile || payload[2] != protocol.Version || payload[3] != ResponsePurpose {
		return fail("response_profile_or_purpose")
	}
	responder, ok := payload[4].(string)
	if !ok || responder != r.Responder {
		return fail("responder_mismatch")
	}
	created, ok := integer(payload[5])
	if !ok || created < r.IssuedAt-int64(MaxFutureSkew/time.Second) || created > current+int64(MaxFutureSkew/time.Second) || created >= r.ExpiresAt {
		return fail("response_creation_time")
	}
	expires, ok := integer(payload[6])
	if !ok || expires != r.ExpiresAt || current >= expires {
		result.ChallengeFreshness = "rejected"
		return fail("response_expiry")
	}
	subject, ok := payload[7].(map[uint64]any)
	if !ok {
		return fail("response_subject")
	}
	wantLabels := 6
	if len(r.Session) > 0 {
		wantLabels = 7
	}
	if len(subject) != wantLabels {
		return fail("response_subject_fields")
	}
	h := RequestHash(encodedRequest)
	requestHash, ok := subject[1].([]byte)
	if !ok || !equal(requestHash, h[:]) {
		return fail("request_hash_mismatch")
	}
	nonce, ok := subject[2].([]byte)
	if !ok || !equal(nonce, r.Nonce) {
		return fail("nonce_mismatch")
	}
	if subject[3] != r.Requester || subject[4] != r.Responder || subject[5] != r.Purpose {
		return fail("challenge_binding_mismatch")
	}
	subjectExpiry, ok := integer(subject[6])
	if !ok || subjectExpiry != r.ExpiresAt {
		return fail("challenge_expiry_mismatch")
	}
	if len(r.Session) > 0 {
		session, ok := subject[7].([]byte)
		if !ok || !equal(session, r.Session) {
			return fail("session_binding_mismatch")
		}
	} else if _, ok := subject[7]; ok {
		return fail("unexpected_session_binding")
	}
	trustStatus := trust(responder, hex.EncodeToString(kid), ResponsePurpose)
	if trustStatus == "disabled" {
		result.CallsignIdentity = "rejected"
		return fail("key_disabled")
	}
	if trustStatus != "trusted" {
		result.CallsignIdentity = "untrusted"
		return fail("key_not_trusted")
	}
	result.CallsignIdentity = "trusted"
	result.ChallengeFreshness = "valid"
	claims := ResponseClaims{Requester: r.Requester, Responder: r.Responder, Purpose: r.Purpose, RequestHash: hex.EncodeToString(h[:]), ExpiresAt: r.ExpiresAt}
	if len(r.Session) > 0 {
		sh := sha256.Sum256(r.Session)
		claims.SessionBinding = hex.EncodeToString(sh[:])
	}
	result.Claims = &claims
	if !consume {
		result.OverallPolicy = "accepted"
		return result
	}
	consumed, err := store.Consume(h[:], current)
	if err != nil {
		result.ChallengeFreshness = "unknown"
		return fail("challenge_store_error")
	}
	if !consumed {
		result.ChallengeFreshness = "rejected"
		return fail("challenge_not_pending_or_replayed")
	}
	result.OverallPolicy = "accepted"
	return result
}

// VerifyMutualPair accepts a coordinated exchange only when both parties
// answer their fresh inverse challenges for the same session, purpose, and
// validity window. The PairStore must consume both pending challenges in one
// atomic operation. Requests and proofs are public bytes suitable for any
// application transport.
func VerifyMutualPair(requests MutualRequests, responses MutualResponses, config MutualVerificationConfig) MutualResult {
	result := MutualResult{ResponseA: Result{OverallPolicy: "rejected"}, ResponseB: Result{OverallPolicy: "rejected"}}
	fail := func(reason string) MutualResult { result.Reason = reason; return result }
	if config.Store == nil || len(config.Session) == 0 {
		return fail("missing_pair_store")
	}
	a, errA := DecodeRequest(requests.FromA)
	b, errB := DecodeRequest(requests.FromB)
	if errA != nil || errB != nil {
		return fail("invalid_mutual_request")
	}
	if a.Requester != b.Responder || a.Responder != b.Requester {
		return fail("requests_are_not_inverse")
	}
	if a.Purpose != b.Purpose || len(a.Session) == 0 || !equal(a.Session, b.Session) || !equal(a.Session, config.Session) {
		return fail("mutual_purpose_or_session_mismatch")
	}
	if a.IssuedAt != b.IssuedAt || a.ExpiresAt != b.ExpiresAt || equal(a.Nonce, b.Nonce) {
		return fail("requests_are_not_one_fresh_pair")
	}
	result.PartyA, result.PartyB, result.Purpose = a.Requester, a.Responder, a.Purpose
	sessionHash := sha256.Sum256(a.Session)
	result.SessionBinding = hex.EncodeToString(sessionHash[:])
	result.ResponseB = verifyResponse(requests.FromA, responses.FromB, config.VerifierB, config.TrustB, nil, a.Requester, config.Now, false)
	if result.ResponseB.OverallPolicy != "accepted" {
		return fail("party_b_response_" + result.ResponseB.Reason)
	}
	result.ResponseA = verifyResponse(requests.FromB, responses.FromA, config.VerifierA, config.TrustA, nil, b.Requester, config.Now, false)
	if result.ResponseA.OverallPolicy != "accepted" {
		return fail("party_a_response_" + result.ResponseA.Reason)
	}
	hashA := RequestHash(requests.FromA)
	hashB := RequestHash(requests.FromB)
	consumed, err := config.Store.ConsumePair(hashA[:], hashB[:], config.Now.UTC().Unix())
	if err != nil {
		result.ResponseA.ChallengeFreshness = "unknown"
		result.ResponseB.ChallengeFreshness = "unknown"
		return fail("mutual_challenge_store_error")
	}
	if !consumed {
		result.ResponseA.ChallengeFreshness = "rejected"
		result.ResponseB.ChallengeFreshness = "rejected"
		result.ResponseA.OverallPolicy = "rejected"
		result.ResponseB.OverallPolicy = "rejected"
		return fail("mutual_challenge_pair_not_pending_or_replayed")
	}
	result.Accepted = true
	return result
}

func integer(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n <= 1<<63-1 {
			return int64(n), true
		}
	case int64:
		if n >= 0 {
			return n, true
		}
	}
	return 0, false
}
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}
