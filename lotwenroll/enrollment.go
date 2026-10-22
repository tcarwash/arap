// Package lotwenroll implements the verifier side of ARAP's experimental
// LoTW-backed key-enrollment assertion. It is separate from ARAP proof signing.
package lotwenroll

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/tcarwash/arap/protocol"
)

const (
	Profile                  = "ARAP-LoTW-enrollment"
	Version                  = 1
	VersionPurposes          = 2
	Purpose                  = "bind-ed25519-key"
	PurposeChallengeResponse = "challenge-response"
	PurposeContentSignature  = protocol.PurposeContent
	MaxLifetime              = 5 * time.Minute
	MaxChainBytes            = 64 * 1024
	MaxResponse              = 128 * 1024
)

// Challenge binds a callsign certificate to one Ed25519 SPKI for one verifier.
// Its exact canonical CBOR encoding is signed by both keys.
type Challenge struct {
	Version   uint64
	Audience  string
	Callsign  string
	KeyID     [32]byte
	Nonce     [32]byte
	IssuedAt  int64
	ExpiresAt int64
	Purposes  []string
}

type Response struct {
	Challenge []byte   `json:"challenge_cbor"`
	Chain     [][]byte `json:"certificate_chain_der"` // leaf first, then intermediates
	PublicKey []byte   `json:"ed25519_public_key"`
	TQSL      []byte   `json:"tqsl_signature"`
	Ed25519   []byte   `json:"ed25519_signature"`
}

// TQSLSigner is implemented by the local TQSL adapter. Implementations must
// sign exactly the supplied bytes and must never export the station private key.
type TQSLSigner interface {
	SignEnrollmentChallenge([]byte) ([]byte, error)
}

// TQSLChainProvider returns the selected callsign certificate followed by its
// issuing certificates. The root is omitted because the verifier supplies its
// own trust anchors.
type TQSLChainProvider interface {
	EnrollmentCertificateChain() ([][]byte, error)
}

type Status string

const (
	StatusGood    Status = "good"
	StatusRevoked Status = "revoked"
	StatusInvalid Status = "invalid"
	StatusUnknown Status = "unknown"
)

// StatusEvidence must be backed by a verifier-approved source with a timestamp.
// TQSL's local cached status API has no freshness timestamp and cannot safely
// populate this structure as current evidence.
type StatusEvidence struct {
	Status     Status
	Source     string
	ObservedAt time.Time
}

// Binding is the durable result of an accepted enrollment. PublicKey is the
// raw Ed25519 key; private key material is never stored here.
type Binding struct {
	Callsign          string   `json:"callsign"`
	KeyID             string   `json:"key_id_sha256"`
	PublicKey         []byte   `json:"ed25519_public_key"`
	Purposes          []string `json:"purposes"`
	CertificateSHA256 string   `json:"certificate_sha256"`
	CertificateIssuer string   `json:"certificate_issuer"`
	CertificateExpiry int64    `json:"certificate_expires_at"`
	VerifiedAt        int64    `json:"verified_at"`
	Status            Status   `json:"certificate_status"`
	StatusSource      string   `json:"status_source"`
	StatusObservedAt  int64    `json:"status_observed_at"`
	Disabled          bool     `json:"disabled,omitempty"`
}

// Store atomically consumes a challenge while persisting its verified binding.
// Keeping these operations together prevents accepted nonces without records
// and records without accepted nonces.
type Store interface {
	Issue(hash []byte, requester, responder, keyID string, expiresAt int64) error
	Complete(hash []byte, binding Binding, now int64) (bool, error)
}

type VerifyConfig struct {
	Audience          string
	Roots             *x509.CertPool
	Now               time.Time
	CallsignFromCert  func(*x509.Certificate) (string, error)
	CertificateStatus func(*x509.Certificate) StatusEvidence
	MaxStatusAge      time.Duration
	Store             Store
	// AllowedPurposes is verifier policy for version 2 enrollment challenges.
	// An empty value preserves the version 1 challenge-response-only policy.
	AllowedPurposes []string
	// EnableLegacyRSASHA1 is retained for source compatibility and ignored.
	// TQSL's supported RSA/SHA-1 is accepted only for enrollment assertions;
	// it is never used by ARAP content or challenge signatures.
	// Deprecated: callers do not need to set this field.
	EnableLegacyRSASHA1 bool
}

type Verification struct {
	Accepted               bool     `json:"accepted"`
	Callsign               string   `json:"callsign,omitempty"`
	KeyID                  string   `json:"key_id_sha256,omitempty"`
	Purposes               []string `json:"purposes,omitempty"`
	CertificateStatus      Status   `json:"certificate_status"`
	StatusSource           string   `json:"status_source,omitempty"`
	StatusObservedAt       int64    `json:"status_observed_at,omitempty"`
	CertificateIssuer      string   `json:"certificate_issuer,omitempty"`
	CertificateFingerprint string   `json:"certificate_sha256,omitempty"`
	CertificateExpiry      int64    `json:"certificate_expires_at,omitempty"`
	LegacySignatureValid   bool     `json:"legacy_rsa_sha1_signature_valid"`
	Reason                 string   `json:"reason,omitempty"`
}

func New(audience, callsign string, public ed25519.PublicKey, now time.Time, lifetime time.Duration) (Challenge, []byte, error) {
	return newChallenge(audience, callsign, public, now, lifetime, Version, []string{PurposeChallengeResponse})
}

// NewWithPurposes issues a version 2 enrollment challenge with explicit,
// verifier-selected key purposes. Version 1 challenges remain challenge-only.
func NewWithPurposes(audience, callsign string, public ed25519.PublicKey, purposes []string, now time.Time, lifetime time.Duration) (Challenge, []byte, error) {
	purposes, err := normalizeEnrollmentPurposes(purposes)
	if err != nil {
		return Challenge{}, nil, err
	}
	return newChallenge(audience, callsign, public, now, lifetime, VersionPurposes, purposes)
}

func newChallenge(audience, callsign string, public ed25519.PublicKey, now time.Time, lifetime time.Duration, version uint64, purposes []string) (Challenge, []byte, error) {
	if audience == "" || len(audience) > 256 {
		return Challenge{}, nil, errors.New("audience must be 1..256 bytes")
	}
	call, err := protocol.NormalizeCallsign(callsign)
	if err != nil {
		return Challenge{}, nil, fmt.Errorf("callsign: %w", err)
	}
	if len(public) != ed25519.PublicKeySize {
		return Challenge{}, nil, errors.New("Ed25519 public key has invalid size")
	}
	if lifetime <= 0 {
		lifetime = 2 * time.Minute
	}
	if lifetime > MaxLifetime {
		return Challenge{}, nil, fmt.Errorf("enrollment challenge lifetime exceeds %s", MaxLifetime)
	}
	keyID, err := protocol.KeyID(public)
	if err != nil {
		return Challenge{}, nil, err
	}
	var keyIDArray [32]byte
	copy(keyIDArray[:], keyID)
	c := Challenge{Version: version, Audience: audience, Callsign: call, KeyID: keyIDArray, IssuedAt: now.UTC().Unix(), ExpiresAt: now.UTC().Add(lifetime).Unix(), Purposes: purposes}
	if c.IssuedAt < 0 || c.ExpiresAt <= c.IssuedAt {
		return Challenge{}, nil, errors.New("invalid challenge time interval")
	}
	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return Challenge{}, nil, err
	}
	b, err := Encode(c)
	return c, b, err
}

func Encode(c Challenge) ([]byte, error) {
	if c.Version == 0 {
		c.Version = Version
	}
	if c.Purposes == nil && c.Version == Version {
		c.Purposes = []string{PurposeChallengeResponse}
	}
	if err := validate(c); err != nil {
		return nil, err
	}
	fields := map[uint64]any{1: Profile, 2: c.Version, 3: Purpose, 4: c.Audience, 5: c.Callsign, 6: c.KeyID[:], 7: c.Nonce[:], 8: c.IssuedAt, 9: c.ExpiresAt}
	if c.Version == VersionPurposes {
		purposes := make([]any, len(c.Purposes))
		for i, purpose := range c.Purposes {
			purposes[i] = purpose
		}
		fields[10] = purposes
	}
	return protocol.EncodeCanonical(fields)
}

func Decode(data []byte) (Challenge, error) {
	var c Challenge
	if len(data) == 0 || len(data) > 4096 {
		return c, errors.New("enrollment challenge must be 1..4096 bytes")
	}
	var m map[uint64]any
	if err := protocol.DecodeCanonical(data, &m); err != nil {
		return c, fmt.Errorf("decode enrollment challenge: %w", err)
	}
	version, ok := m[2].(uint64)
	if !ok || (version != Version && version != VersionPurposes) {
		return c, errors.New("unsupported enrollment challenge version")
	}
	if (version == Version && len(m) != 9) || (version == VersionPurposes && len(m) != 10) {
		return c, errors.New("enrollment challenge has unexpected fields")
	}
	for _, k := range []uint64{1, 3, 4, 5} {
		if _, ok := m[k].(string); !ok {
			return c, fmt.Errorf("enrollment challenge label %d must be text", k)
		}
	}
	if m[1] != Profile || m[3] != Purpose {
		return c, errors.New("unsupported enrollment challenge profile")
	}
	c.Version = version
	if version == Version {
		c.Purposes = []string{PurposeChallengeResponse}
	} else {
		items, ok := m[10].([]any)
		if !ok {
			return c, errors.New("enrollment purposes must be an array")
		}
		for _, item := range items {
			purpose, ok := item.(string)
			if !ok {
				return c, errors.New("enrollment purpose must be text")
			}
			c.Purposes = append(c.Purposes, purpose)
		}
	}
	if c.Audience, ok = m[4].(string); !ok {
		return c, errors.New("challenge audience must be text")
	}
	if c.Callsign, ok = m[5].(string); !ok {
		return c, errors.New("challenge callsign must be text")
	}
	keyID, ok := m[6].([]byte)
	if !ok || len(keyID) != len(c.KeyID) {
		return c, errors.New("challenge key fingerprint must be 32 bytes")
	}
	copy(c.KeyID[:], keyID)
	nonce, ok := m[7].([]byte)
	if !ok || len(nonce) != len(c.Nonce) {
		return c, errors.New("challenge nonce must be 32 bytes")
	}
	copy(c.Nonce[:], nonce)
	c.IssuedAt, ok = asInt(m[8])
	if !ok {
		return c, errors.New("challenge issued_at must be an integer")
	}
	c.ExpiresAt, ok = asInt(m[9])
	if !ok {
		return c, errors.New("challenge expires_at must be an integer")
	}
	if err := validate(c); err != nil {
		return Challenge{}, err
	}
	return c, nil
}

func Respond(encoded []byte, key ed25519.PrivateKey, signer TQSLSigner, chain [][]byte) (Response, error) {
	challenge, err := Decode(encoded)
	if err != nil {
		return Response{}, err
	}
	if len(key) != ed25519.PrivateKeySize || signer == nil {
		return Response{}, errors.New("Ed25519 key and TQSL signer are required")
	}
	keyID, err := protocol.KeyID(key.Public().(ed25519.PublicKey))
	if err != nil || !bytes.Equal(keyID, challenge.KeyID[:]) {
		return Response{}, errors.New("Ed25519 private key does not match the enrollment challenge")
	}
	tqslSig, err := signer.SignEnrollmentChallenge(append([]byte(nil), encoded...))
	if err != nil {
		return Response{}, fmt.Errorf("TQSL challenge signing failed: %w", err)
	}
	if len(chain) == 0 {
		provider, ok := signer.(TQSLChainProvider)
		if !ok {
			return Response{}, errors.New("certificate chain is required")
		}
		chain, err = provider.EnrollmentCertificateChain()
		if err != nil {
			return Response{}, fmt.Errorf("load TQSL certificate chain: %w", err)
		}
	}
	if len(chain) == 0 || len(chain) > 8 {
		return Response{}, errors.New("certificate chain must contain 1..8 certificates")
	}
	var size int
	copyChain := make([][]byte, len(chain))
	for i, der := range chain {
		size += len(der)
		if len(der) == 0 || size > MaxChainBytes {
			return Response{}, errors.New("certificate chain is empty or too large")
		}
		copyChain[i] = append([]byte(nil), der...)
	}
	return Response{Challenge: append([]byte(nil), encoded...), Chain: copyChain, PublicKey: append([]byte(nil), key.Public().(ed25519.PublicKey)...), TQSL: tqslSig, Ed25519: ed25519.Sign(key, encoded)}, nil
}

// EncodeResponse serializes the enrollment response as deterministic CBOR.
func EncodeResponse(r Response) ([]byte, error) {
	if _, err := Decode(r.Challenge); err != nil {
		return nil, err
	}
	if len(r.Chain) == 0 || len(r.Chain) > 8 || len(r.PublicKey) != ed25519.PublicKeySize || len(r.TQSL) == 0 || len(r.TQSL) > 1024 || len(r.Ed25519) != ed25519.SignatureSize {
		return nil, errors.New("invalid enrollment response fields")
	}
	var size int
	chain := make([]any, len(r.Chain))
	for i, der := range r.Chain {
		size += len(der)
		if len(der) == 0 || size > MaxChainBytes {
			return nil, errors.New("certificate chain is empty or too large")
		}
		chain[i] = der
	}
	encoded, err := protocol.EncodeCanonical(map[uint64]any{1: r.Challenge, 2: chain, 3: r.PublicKey, 4: r.TQSL, 5: r.Ed25519})
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxResponse {
		return nil, errors.New("enrollment response exceeds size limit")
	}
	return encoded, nil
}

// DecodeResponse enforces deterministic CBOR, exact labels, and bounded input.
func DecodeResponse(data []byte) (Response, error) {
	var r Response
	if len(data) == 0 || len(data) > MaxResponse {
		return r, errors.New("enrollment response is empty or too large")
	}
	var m map[uint64]any
	if err := protocol.DecodeCanonical(data, &m); err != nil {
		return r, fmt.Errorf("decode enrollment response: %w", err)
	}
	if len(m) != 5 {
		return r, errors.New("enrollment response has unexpected fields")
	}
	var ok bool
	if r.Challenge, ok = m[1].([]byte); !ok {
		return Response{}, errors.New("response challenge must be a byte string")
	}
	if _, err := Decode(r.Challenge); err != nil {
		return Response{}, fmt.Errorf("invalid response challenge: %w", err)
	}
	items, ok := m[2].([]any)
	if !ok || len(items) == 0 || len(items) > 8 {
		return Response{}, errors.New("response certificate chain must contain 1..8 certificates")
	}
	var chainSize int
	for _, item := range items {
		der, ok := item.([]byte)
		if !ok || len(der) == 0 {
			return Response{}, errors.New("certificate chain entries must be nonempty byte strings")
		}
		chainSize += len(der)
		if chainSize > MaxChainBytes {
			return Response{}, errors.New("certificate chain exceeds size limit")
		}
		r.Chain = append(r.Chain, append([]byte(nil), der...))
	}
	if r.PublicKey, ok = m[3].([]byte); !ok || len(r.PublicKey) != ed25519.PublicKeySize {
		return Response{}, errors.New("response Ed25519 public key must be 32 bytes")
	}
	if r.TQSL, ok = m[4].([]byte); !ok || len(r.TQSL) == 0 || len(r.TQSL) > 1024 {
		return Response{}, errors.New("response TQSL signature must be 1..1024 bytes")
	}
	if r.Ed25519, ok = m[5].([]byte); !ok || len(r.Ed25519) != ed25519.SignatureSize {
		return Response{}, errors.New("response Ed25519 signature must be 64 bytes")
	}
	return r, nil
}

func Verify(response Response, config VerifyConfig) Verification {
	result := Verification{CertificateStatus: StatusUnknown}
	fail := func(reason string) Verification { result.Reason = reason; return result }
	if config.Roots == nil || config.Store == nil {
		return fail("verifier roots and enrollment store are required")
	}
	now := config.Now
	if now.IsZero() {
		now = time.Now()
	}
	c, err := Decode(response.Challenge)
	if err != nil {
		return fail(err.Error())
	}
	allowedPurposes := config.AllowedPurposes
	if len(allowedPurposes) == 0 {
		allowedPurposes = []string{PurposeChallengeResponse}
	}
	allowedPurposes, err = normalizeEnrollmentPurposes(allowedPurposes)
	if err != nil {
		return fail("invalid verifier enrollment-purpose policy")
	}
	for _, purpose := range c.Purposes {
		if !containsEnrollmentPurpose(allowedPurposes, purpose) {
			return fail("enrollment purpose is not allowed by verifier policy")
		}
	}
	if c.Audience != config.Audience {
		return fail("challenge audience mismatch")
	}
	if now.UTC().Unix() < c.IssuedAt-30 || now.UTC().Unix() >= c.ExpiresAt {
		return fail("challenge is not currently valid")
	}
	if len(response.Chain) == 0 || len(response.Chain) > 8 {
		return fail("certificate chain must contain 1..8 certificates")
	}
	intermediates := x509.NewCertPool()
	var leaf *x509.Certificate
	chainSize := 0
	for i, der := range response.Chain {
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
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: config.Roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil || len(chains) == 0 {
		return fail("callsign certificate chain validation failed")
	}
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fail("callsign certificate does not permit digital signatures")
	}
	callsignFromCert := config.CallsignFromCert
	if callsignFromCert == nil {
		callsignFromCert = CallsignFromCertificate
	}
	call, err := callsignFromCert(leaf)
	if err != nil {
		return fail("cannot extract callsign from certificate")
	}
	call, err = protocol.NormalizeCallsign(call)
	if err != nil || call != c.Callsign {
		return fail("certificate callsign does not match challenge")
	}
	result.Callsign = call
	result.KeyID = hex.EncodeToString(c.KeyID[:])
	result.CertificateIssuer = leaf.Issuer.String()
	certFingerprint := sha256.Sum256(leaf.Raw)
	result.CertificateFingerprint = hex.EncodeToString(certFingerprint[:])
	result.CertificateExpiry = leaf.NotAfter.UTC().Unix()
	status := StatusEvidence{Status: StatusUnknown}
	if config.CertificateStatus != nil {
		status = config.CertificateStatus(leaf)
	}
	result.CertificateStatus = status.Status
	result.StatusSource = status.Source
	if !status.ObservedAt.IsZero() {
		result.StatusObservedAt = status.ObservedAt.UTC().Unix()
	}
	if status.Status != StatusGood || status.Source == "" || status.ObservedAt.IsZero() {
		return fail("certificate status is not known good with timestamped evidence")
	}
	if config.MaxStatusAge <= 0 {
		return fail("maximum certificate-status evidence age is not configured")
	}
	statusAge := now.Sub(status.ObservedAt)
	if statusAge < 0 || statusAge > config.MaxStatusAge {
		return fail("certificate-status evidence is future-dated or stale")
	}
	rsaKey, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok || rsaKey.N.BitLen() < 1024 {
		return fail("TQSL enrollment certificate must contain an RSA key of at least 1024 bits")
	}
	digest := sha1.Sum(response.Challenge)
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA1, digest[:], response.TQSL); err != nil {
		return fail("TQSL RSA-SHA1 challenge signature is invalid")
	}
	result.LegacySignatureValid = true
	if len(response.Ed25519) != ed25519.SignatureSize {
		return fail("ARAP Ed25519 enrollment signature has invalid size")
	}
	public := ed25519.PublicKey(response.PublicKey)
	if len(public) != ed25519.PublicKeySize {
		return fail("ARAP Ed25519 public key has invalid size")
	}
	id, err := protocol.KeyID(public)
	if err != nil || len(id) != len(c.KeyID) || !equal(id, c.KeyID[:]) || len(response.Ed25519) != ed25519.SignatureSize || !ed25519.Verify(public, response.Challenge, response.Ed25519) {
		return fail("ARAP Ed25519 key fingerprint or challenge signature is invalid")
	}
	hash := sha256.Sum256(response.Challenge)
	binding := Binding{
		Callsign: call, KeyID: hex.EncodeToString(c.KeyID[:]), PublicKey: append([]byte(nil), public...),
		Purposes: append([]string(nil), c.Purposes...), CertificateSHA256: result.CertificateFingerprint,
		CertificateIssuer: result.CertificateIssuer, CertificateExpiry: result.CertificateExpiry,
		VerifiedAt: now.UTC().Unix(), Status: status.Status, StatusSource: status.Source,
		StatusObservedAt: status.ObservedAt.UTC().Unix(),
	}
	accepted, err := config.Store.Complete(hash[:], binding, now.UTC().Unix())
	if err != nil || !accepted {
		return fail("enrollment challenge is unknown, expired, consumed or unavailable")
	}
	result.Accepted = true
	result.Purposes = append([]string(nil), binding.Purposes...)
	result.Reason = "enrollment signatures verified; certificate status accepted by configured policy"
	return result
}

func VerifyEncoded(encoded []byte, config VerifyConfig) Verification {
	response, err := DecodeResponse(encoded)
	if err != nil {
		return Verification{CertificateStatus: StatusUnknown, Reason: err.Error()}
	}
	return Verify(response, config)
}

func Issue(encoded []byte, store Store) error {
	if store == nil {
		return errors.New("challenge replay store is required")
	}
	c, err := Decode(encoded)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(encoded)
	return store.Issue(hash[:], "ARAP", c.Callsign, hex.EncodeToString(c.KeyID[:]), c.ExpiresAt)
}

func validate(c Challenge) error {
	if c.Version == 0 {
		c.Version = Version
	}
	if c.Audience == "" || len(c.Audience) > 256 {
		return errors.New("challenge audience must be 1..256 bytes")
	}
	call, err := protocol.NormalizeCallsign(c.Callsign)
	if err != nil || call != c.Callsign {
		return errors.New("challenge callsign is not normalized")
	}
	if c.IssuedAt < 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > int64(MaxLifetime/time.Second) {
		return errors.New("invalid enrollment challenge time bounds")
	}
	if c.KeyID == ([32]byte{}) || c.Nonce == ([32]byte{}) {
		return errors.New("challenge key fingerprint and nonce must be nonzero")
	}
	if c.Version == Version {
		if len(c.Purposes) != 1 || c.Purposes[0] != PurposeChallengeResponse {
			return errors.New("version 1 enrollment challenges authorize only challenge-response")
		}
	} else if c.Version == VersionPurposes {
		normalized, err := normalizeEnrollmentPurposes(c.Purposes)
		if err != nil || !equalStringLists(normalized, c.Purposes) {
			return errors.New("version 2 enrollment purposes must be valid, unique and sorted")
		}
	} else {
		return errors.New("unsupported enrollment challenge version")
	}
	return nil
}

func normalizeEnrollmentPurposes(purposes []string) ([]string, error) {
	if len(purposes) == 0 || len(purposes) > 2 {
		return nil, errors.New("enrollment requires one or more supported purposes")
	}
	result := append([]string(nil), purposes...)
	sort.Strings(result)
	for i, purpose := range result {
		if purpose != PurposeChallengeResponse && purpose != PurposeContentSignature {
			return nil, fmt.Errorf("unsupported enrollment purpose %q", purpose)
		}
		if i > 0 && purpose == result[i-1] {
			return nil, errors.New("enrollment purposes must be unique")
		}
	}
	return result, nil
}

func containsEnrollmentPurpose(purposes []string, target string) bool {
	for _, purpose := range purposes {
		if purpose == target {
			return true
		}
	}
	return false
}

func equalStringLists(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var mismatch byte
	for i := range a {
		mismatch |= a[i] ^ b[i]
	}
	return mismatch == 0
}
