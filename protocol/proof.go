package protocol

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

const (
	AlgorithmEd25519 int64 = -19
	ContentType            = "application/vnd.arap.proof+cbor"
	Profile                = "ARAP"
	Version                = uint64(1)
	PurposeContent         = "content-signature"
	MaxProofSize           = 64 * 1024
)

type Signer interface {
	Callsign() string
	Algorithm() int64
	PublicKey() crypto.PublicKey
	Sign(message []byte) ([]byte, error)
}

type Verifier interface {
	Algorithm() int64
	PublicKey() crypto.PublicKey
	Verify(message, signature []byte) error
}

type Ed25519Signer struct {
	call    string
	private ed25519.PrivateKey
}
type Ed25519Verifier struct{ public ed25519.PublicKey }

func GenerateEd25519(callsign string) (*Ed25519Signer, error) {
	call, err := NormalizeCallsign(callsign)
	if err != nil {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519Signer{call: call, private: private}, nil
}
func NewEd25519Signer(callsign string, private ed25519.PrivateKey) (*Ed25519Signer, error) {
	call, err := NormalizeCallsign(callsign)
	if err != nil {
		return nil, err
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length")
	}
	return &Ed25519Signer{call: call, private: append(ed25519.PrivateKey(nil), private...)}, nil
}
func NewEd25519Verifier(public ed25519.PublicKey) (*Ed25519Verifier, error) {
	if len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length")
	}
	return &Ed25519Verifier{public: append(ed25519.PublicKey(nil), public...)}, nil
}
func (s *Ed25519Signer) Callsign() string                { return s.call }
func (s *Ed25519Signer) Algorithm() int64                { return AlgorithmEd25519 }
func (s *Ed25519Signer) PublicKey() crypto.PublicKey     { return s.private.Public().(ed25519.PublicKey) }
func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.private, msg), nil }
func (v *Ed25519Verifier) Algorithm() int64              { return AlgorithmEd25519 }
func (v *Ed25519Verifier) PublicKey() crypto.PublicKey   { return v.public }
func (v *Ed25519Verifier) Verify(msg, sig []byte) error {
	if !ed25519.Verify(v.public, msg, sig) {
		return fmt.Errorf("invalid Ed25519 signature")
	}
	return nil
}

func NormalizeCallsign(call string) (string, error) {
	call = strings.Trim(call, " ")
	if len(call) < 3 || len(call) > 20 {
		return "", fmt.Errorf("callsign must contain 3..20 ASCII bytes")
	}
	normalized := []byte(call)
	letters, digits := false, false
	for i := range normalized {
		if normalized[i] >= 'a' && normalized[i] <= 'z' {
			normalized[i] -= 'a' - 'A'
		}
		c := normalized[i]
		switch {
		case c >= 'A' && c <= 'Z':
			letters = true
		case c >= '0' && c <= '9':
			digits = true
		case c == '/':
			if i == 0 || i == len(call)-1 || call[i-1] == '/' {
				return "", fmt.Errorf("invalid callsign slash placement")
			}
		default:
			return "", fmt.Errorf("callsign must contain only ASCII letters, digits and slash")
		}
	}
	if !letters || !digits {
		return "", fmt.Errorf("callsign must include a letter and a digit")
	}
	return string(normalized), nil
}

func KeyID(key crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(der)
	return h[:], nil
}

type ContentMetadata struct {
	MediaType        string
	Canonicalization string
	Context          string
	ContentID        string
	NotAfter         *time.Time
}

type ContentClaims struct {
	Callsign         string `json:"signer"`
	Created          int64  `json:"created"`
	NotAfter         *int64 `json:"not_after,omitempty"`
	MediaType        string `json:"media_type"`
	Canonicalization string `json:"canonicalization"`
	Digest           string `json:"content_digest_sha256"`
	Size             uint64 `json:"content_size"`
	Context          string `json:"context"`
	ContentID        string `json:"content_id,omitempty"`
	Algorithm        int64  `json:"cose_algorithm"`
	KeyID            string `json:"key_id_sha256"`
}

func SignContent(signer Signer, content io.Reader, meta ContentMetadata, now time.Time) ([]byte, ContentClaims, error) {
	if signer == nil || content == nil {
		return nil, ContentClaims{}, fmt.Errorf("signer and content are required")
	}
	call, err := NormalizeCallsign(signer.Callsign())
	if err != nil {
		return nil, ContentClaims{}, err
	}
	if meta.MediaType == "" || len(meta.MediaType) > 128 || !utf8.ValidString(meta.MediaType) {
		return nil, ContentClaims{}, fmt.Errorf("media type must be 1..128 valid UTF-8 bytes")
	}
	canonical := meta.Canonicalization
	if canonical == "" {
		canonical = "identity-v1"
	}
	if canonical != "identity-v1" {
		return nil, ContentClaims{}, fmt.Errorf("unsupported canonicalization %q", canonical)
	}
	if meta.Context == "" || len(meta.Context) > 128 || !utf8.ValidString(meta.Context) {
		return nil, ContentClaims{}, fmt.Errorf("context must be 1..128 valid UTF-8 bytes")
	}
	if len(meta.ContentID) > 256 || !utf8.ValidString(meta.ContentID) {
		return nil, ContentClaims{}, fmt.Errorf("content id must be at most 256 valid UTF-8 bytes")
	}
	public, keyID, err := signingKeyID(signer)
	if err != nil {
		return nil, ContentClaims{}, err
	}
	digest, size, err := hashReader(content)
	if err != nil {
		return nil, ContentClaims{}, err
	}
	created := now.UTC().Unix()
	if created < 0 {
		return nil, ContentClaims{}, fmt.Errorf("created timestamp must be non-negative")
	}
	payload := map[uint64]any{
		1: Profile, 2: Version, 3: PurposeContent, 4: call, 5: created,
		7: map[uint64]any{1: meta.MediaType, 2: canonical, 3: "sha-256", 4: digest[:], 5: size, 7: meta.Context},
	}
	if meta.ContentID != "" {
		payload[7].(map[uint64]any)[6] = meta.ContentID
	}
	if meta.NotAfter != nil {
		until := meta.NotAfter.UTC().Unix()
		if until <= created {
			return nil, ContentClaims{}, fmt.Errorf("not_after must be later than created")
		}
		payload[6] = until
	}
	payloadBytes, err := marshal(payload)
	if err != nil {
		return nil, ContentClaims{}, err
	}
	protected, err := marshal(map[uint64]any{1: AlgorithmEd25519, 3: ContentType, 4: keyID})
	if err != nil {
		return nil, ContentClaims{}, err
	}
	toSign, err := marshal([]any{"Signature1", protected, []byte{}, payloadBytes})
	if err != nil {
		return nil, ContentClaims{}, err
	}
	sig, err := signEd25519(signer, public, toSign)
	if err != nil {
		return nil, ContentClaims{}, err
	}
	proof, err := marshalProof(protected, payloadBytes, sig)
	if err != nil {
		return nil, ContentClaims{}, err
	}
	claims := ContentClaims{Callsign: call, Created: created, MediaType: meta.MediaType, Canonicalization: canonical, Digest: fmt.Sprintf("%x", digest), Size: size, Context: meta.Context, ContentID: meta.ContentID, Algorithm: signer.Algorithm(), KeyID: fmt.Sprintf("%x", keyID)}
	if v, ok := payload[6].(int64); ok {
		claims.NotAfter = &v
	}
	return proof, claims, nil
}

// SignPayload wraps a profile-specific canonical CBOR payload in the ARAP
// COSE_Sign1 envelope. The caller owns payload schema and purpose validation.
func SignPayload(signer Signer, payload []byte) ([]byte, error) {
	if signer == nil || len(payload) == 0 || len(payload) > MaxProofSize {
		return nil, fmt.Errorf("signer and bounded payload are required")
	}
	public, keyID, err := signingKeyID(signer)
	if err != nil {
		return nil, err
	}
	var decoded any
	if err := DecodeCanonical(payload, &decoded); err != nil {
		return nil, fmt.Errorf("payload must be canonical CBOR: %w", err)
	}
	protected, err := marshal(map[uint64]any{1: AlgorithmEd25519, 3: ContentType, 4: keyID})
	if err != nil {
		return nil, err
	}
	toSign, err := marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nil, err
	}
	sig, err := signEd25519(signer, public, toSign)
	if err != nil {
		return nil, err
	}
	return marshalProof(protected, payload, sig)
}

func signingKeyID(signer Signer) (ed25519.PublicKey, []byte, error) {
	if signer.Algorithm() != AlgorithmEd25519 {
		return nil, nil, fmt.Errorf("unsupported COSE algorithm %d", signer.Algorithm())
	}
	public, ok := signer.PublicKey().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("Ed25519 signer must provide a 32-byte public key")
	}
	public = append(ed25519.PublicKey(nil), public...)
	keyID, err := KeyID(public)
	if err != nil {
		return nil, nil, err
	}
	return public, keyID, nil
}

func signEd25519(signer Signer, public ed25519.PublicKey, message []byte) ([]byte, error) {
	signature, err := signer.Sign(message)
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(public, message, signature) {
		return nil, fmt.Errorf("signer returned an invalid Ed25519 signature")
	}
	return signature, nil
}

func marshalProof(protected, payload, signature []byte) ([]byte, error) {
	proof, err := marshal(cborTag18([]any{protected, map[uint64]any{}, payload, signature}))
	if err != nil {
		return nil, err
	}
	if len(proof) > MaxProofSize {
		return nil, fmt.Errorf("encoded COSE proof exceeds %d byte limit", MaxProofSize)
	}
	return proof, nil
}

// VerifyPayload verifies an ARAP COSE_Sign1 envelope and returns its original
// canonical payload and key identifier. Purpose-specific checks belong to the
// calling profile and must not be inferred from this operation alone.
func VerifyPayload(proof []byte, verifier Verifier) ([]byte, []byte, error) {
	if len(proof) == 0 || len(proof) > MaxProofSize || verifier == nil {
		return nil, nil, fmt.Errorf("bounded proof and verifier are required")
	}
	var tag cbor.Tag
	if err := unmarshal(proof, &tag); err != nil || tag.Number != 18 {
		return nil, nil, fmt.Errorf("invalid COSE_Sign1 tag")
	}
	if err := requireCanonical(proof, tag); err != nil {
		return nil, nil, fmt.Errorf("non-deterministic COSE_Sign1: %w", err)
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return nil, nil, fmt.Errorf("invalid COSE_Sign1 shape")
	}
	protected, ok := arr[0].([]byte)
	if !ok || len(protected) == 0 {
		return nil, nil, fmt.Errorf("invalid protected headers")
	}
	unprotected, err := uintMap(arr[1], "unprotected headers")
	if err != nil || len(unprotected) != 0 {
		return nil, nil, fmt.Errorf("unprotected headers are forbidden")
	}
	payload, ok := arr[2].([]byte)
	if !ok || len(payload) == 0 || len(payload) > MaxProofSize {
		return nil, nil, fmt.Errorf("invalid embedded payload")
	}
	signature, ok := arr[3].([]byte)
	if !ok || len(signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("invalid signature size")
	}
	var headers map[uint64]any
	if err := unmarshal(protected, &headers); err != nil || requireCanonical(protected, headers) != nil {
		return nil, nil, fmt.Errorf("invalid protected headers encoding")
	}
	if err := exactLabels(headers, []uint64{1, 3, 4}); err != nil {
		return nil, nil, fmt.Errorf("invalid protected header set")
	}
	alg, err := getInt(headers, 1, "algorithm")
	if err != nil || alg != AlgorithmEd25519 || verifier.Algorithm() != alg {
		return nil, nil, fmt.Errorf("unsupported or mismatched algorithm")
	}
	ct, err := getText(headers, 3, "content type", 128)
	if err != nil || ct != ContentType {
		return nil, nil, fmt.Errorf("invalid content type")
	}
	kid, err := getBytes(headers, 4, "key id", 32)
	if err != nil {
		return nil, nil, err
	}
	pubID, err := KeyID(verifier.PublicKey())
	if err != nil || !bytes.Equal(kid, pubID) {
		return nil, nil, fmt.Errorf("key identifier mismatch")
	}
	var decoded any
	if err := DecodeCanonical(payload, &decoded); err != nil {
		return nil, nil, fmt.Errorf("invalid payload encoding: %w", err)
	}
	toVerify, err := marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		return nil, nil, err
	}
	if err := verifier.Verify(toVerify, signature); err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), payload...), append([]byte(nil), kid...), nil
}

// InspectProof parses a canonical proof envelope without authenticating it.
// Returned claims are untrusted input and must never be used as an acceptance
// decision. Signature verification requires VerifyPayload or a purpose verifier.
func InspectProof(proof []byte) (map[uint64]any, any, error) {
	if len(proof) == 0 || len(proof) > MaxProofSize {
		return nil, nil, fmt.Errorf("proof size is invalid")
	}
	var tag cbor.Tag
	if err := unmarshal(proof, &tag); err != nil || tag.Number != 18 {
		return nil, nil, fmt.Errorf("invalid COSE_Sign1 tag")
	}
	if err := requireCanonical(proof, tag); err != nil {
		return nil, nil, fmt.Errorf("non-deterministic COSE_Sign1: %w", err)
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return nil, nil, fmt.Errorf("invalid COSE_Sign1 shape")
	}
	protected, ok := arr[0].([]byte)
	if !ok || len(protected) == 0 {
		return nil, nil, fmt.Errorf("invalid protected headers")
	}
	unprotected, err := uintMap(arr[1], "unprotected headers")
	if err != nil || len(unprotected) != 0 {
		return nil, nil, fmt.Errorf("unprotected headers are forbidden")
	}
	payload, ok := arr[2].([]byte)
	if !ok || len(payload) == 0 {
		return nil, nil, fmt.Errorf("embedded payload is required")
	}
	signature, ok := arr[3].([]byte)
	if !ok || len(signature) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("invalid signature size")
	}
	var headers map[uint64]any
	if err := DecodeCanonical(protected, &headers); err != nil {
		return nil, nil, fmt.Errorf("invalid protected headers: %w", err)
	}
	if err := exactLabels(headers, []uint64{1, 3, 4}); err != nil {
		return nil, nil, fmt.Errorf("invalid protected header set")
	}
	alg, err := getInt(headers, 1, "algorithm")
	if err != nil || alg != AlgorithmEd25519 {
		return nil, nil, fmt.Errorf("unsupported algorithm")
	}
	ct, err := getText(headers, 3, "content type", 128)
	if err != nil || ct != ContentType {
		return nil, nil, fmt.Errorf("invalid content type")
	}
	if _, err := getBytes(headers, 4, "key id", 32); err != nil {
		return nil, nil, err
	}
	var claims any
	if err := DecodeCanonical(payload, &claims); err != nil {
		return nil, nil, fmt.Errorf("invalid payload: %w", err)
	}
	return headers, claims, nil
}

func cborTag18(content any) any { return cbor.Tag{Number: 18, Content: content} }

func hashReader(r io.Reader) ([32]byte, uint64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return [32]byte{}, 0, err
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, uint64(n), nil
}
