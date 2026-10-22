package protocol

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// MaxFutureClockSkew bounds how far ahead a signed created time may be from
// the verifier's clock. created remains a signer assertion, not a timestamp.
const MaxFutureClockSkew = 5 * time.Minute

type Expected struct {
	Purpose          string
	MediaType        string
	Canonicalization string
	Context          string
	Callsign         string
}

type VerifyResult struct {
	CryptographicSignature string `json:"cryptographic_signature"`
	ContentIntegrity       string `json:"content_integrity"`
	CallsignIdentity       string `json:"callsign_identity"`
	OverallPolicy          string `json:"overall_policy"`
	Reason                 string `json:"reason,omitempty"`
	// Claims are populated only after the COSE signature has been verified.
	// This proves the claims are bound to the signing key; it does not establish
	// that the key is trusted or authorized for the callsign.
	Claims *ContentClaims `json:"claims,omitempty"`
}

func VerifyContent(proof []byte, content io.Reader, verifier Verifier, expected Expected, trust func(callsign, keyID, purpose string) bool, now time.Time) VerifyResult {
	var decision func(string, string, string) string
	if trust != nil {
		decision = func(c, k, p string) string {
			if trust(c, k, p) {
				return "trusted"
			}
			return "untrusted"
		}
	}
	return VerifyContentWithTrust(proof, content, verifier, expected, decision, now)
}

func VerifyContentWithTrust(proof []byte, content io.Reader, verifier Verifier, expected Expected, trust func(callsign, keyID, purpose string) string, now time.Time) VerifyResult {
	result := VerifyResult{CryptographicSignature: "not_checked", ContentIntegrity: "not_checked", CallsignIdentity: "not_checked", OverallPolicy: "rejected"}
	fail := func(reason string) VerifyResult { result.Reason = reason; return result }
	if len(proof) == 0 || len(proof) > MaxProofSize {
		return fail("proof_size")
	}
	if content == nil || verifier == nil {
		return fail("missing_content_or_key")
	}
	if expected.Purpose == "" || expected.MediaType == "" || expected.Canonicalization == "" || expected.Context == "" {
		return fail("expected_purpose_type_canonicalization_context_required")
	}
	var tag cbor.Tag
	if err := unmarshal(proof, &tag); err != nil {
		return fail("malformed_cbor")
	}
	if tag.Number != 18 {
		return fail("wrong_cose_tag")
	}
	if err := requireCanonical(proof, tag); err != nil {
		return fail("non_deterministic_cose")
	}
	arr, ok := tag.Content.([]any)
	if !ok || len(arr) != 4 {
		return fail("invalid_cose_sign1_shape")
	}
	protected, ok := arr[0].([]byte)
	if !ok || len(protected) == 0 {
		return fail("invalid_protected_headers")
	}
	unprotected, err := uintMap(arr[1], "unprotected headers")
	if err != nil || len(unprotected) != 0 {
		return fail("unprotected_headers_forbidden")
	}
	payloadBytes, ok := arr[2].([]byte)
	if !ok {
		return fail("detached_payload_forbidden")
	}
	signature, ok := arr[3].([]byte)
	if !ok || len(signature) != ed25519.SignatureSize {
		return fail("invalid_signature_value")
	}
	var headers map[uint64]any
	if err := unmarshal(protected, &headers); err != nil {
		return fail("malformed_protected_headers")
	}
	if err := requireCanonical(protected, headers); err != nil {
		return fail("non_deterministic_protected_headers")
	}
	if err := exactLabels(headers, []uint64{1, 3, 4}); err != nil {
		return fail("protected_header_set")
	}
	alg, err := getInt(headers, 1, "algorithm")
	if err != nil {
		return fail("invalid_algorithm")
	}
	if alg != AlgorithmEd25519 || verifier.Algorithm() != alg {
		return fail("unsupported_or_mismatched_algorithm")
	}
	contentType, err := getText(headers, 3, "content type", 128)
	if err != nil || contentType != ContentType {
		return fail("content_type")
	}
	kid, err := getBytes(headers, 4, "key id", 32)
	if err != nil {
		return fail("key_id")
	}
	pubID, err := KeyID(verifier.PublicKey())
	if err != nil || !bytes.Equal(kid, pubID) {
		return fail("key_mismatch")
	}
	var payload map[uint64]any
	if err := unmarshal(payloadBytes, &payload); err != nil {
		return fail("malformed_payload")
	}
	if err := requireCanonical(payloadBytes, payload); err != nil {
		return fail("non_deterministic_payload")
	}
	if err := exactLabels(payload, []uint64{1, 2, 3, 4, 5, 7}, 6); err != nil {
		return fail("payload_fields")
	}
	profile, err := getText(payload, 1, "profile", 16)
	if err != nil || profile != Profile {
		return fail("profile")
	}
	version, err := getUint(payload, 2, "version")
	if err != nil || version != Version {
		return fail("version")
	}
	purpose, err := getText(payload, 3, "purpose", 64)
	if err != nil {
		return fail("purpose")
	}
	callsign, err := getText(payload, 4, "signer", 20)
	if err != nil {
		return fail("signer")
	}
	normalized, err := NormalizeCallsign(callsign)
	if err != nil || normalized != callsign {
		return fail("signer_normalization")
	}
	created, err := getInt(payload, 5, "created")
	if err != nil || created < 0 {
		return fail("created")
	}
	var notAfter *int64
	if value, present := payload[6]; present {
		parsed, ok := value.(uint64)
		if !ok || parsed > uint64(^uint64(0)>>1) {
			return fail("not_after")
		}
		t := int64(parsed)
		if t <= created {
			return fail("not_after")
		}
		notAfter = &t
	}
	subject, err := uintMap(payload[7], "content subject")
	if err != nil {
		return fail("subject")
	}
	if err := exactLabels(subject, []uint64{1, 2, 3, 4, 5, 7}, 6); err != nil {
		return fail("subject_fields")
	}
	mediaType, err := getText(subject, 1, "media type", 128)
	if err != nil {
		return fail("media_type")
	}
	canonical, err := getText(subject, 2, "canonicalization", 128)
	if err != nil || canonical != "identity-v1" {
		return fail("canonicalization")
	}
	digestAlg, err := getText(subject, 3, "digest algorithm", 16)
	if err != nil || digestAlg != "sha-256" {
		return fail("digest_algorithm")
	}
	digest, err := getBytes(subject, 4, "content digest", 32)
	if err != nil {
		return fail("content_digest")
	}
	size, err := getUint(subject, 5, "content size")
	if err != nil {
		return fail("content_size")
	}
	ctx, err := getText(subject, 7, "context", 128)
	if err != nil {
		return fail("context")
	}
	contentID := ""
	if value, present := subject[6]; present {
		id, ok := value.(string)
		if !ok || len(id) == 0 || len(id) > 256 {
			return fail("content_id")
		}
		contentID = id
	}
	claims := &ContentClaims{Callsign: callsign, Created: created, NotAfter: notAfter, MediaType: mediaType, Canonicalization: canonical, Digest: fmt.Sprintf("%x", digest), Size: size, Context: ctx, ContentID: contentID, Algorithm: alg, KeyID: fmt.Sprintf("%x", kid)}
	if purpose != PurposeContent || expected.Purpose != PurposeContent || purpose != expected.Purpose {
		return fail("purpose_mismatch")
	}
	if mediaType != expected.MediaType || canonical != expected.Canonicalization || ctx != expected.Context {
		return fail("content_expectation_mismatch")
	}
	if expected.Callsign != "" {
		expectedCall, normErr := NormalizeCallsign(expected.Callsign)
		if normErr != nil || expectedCall != callsign {
			return fail("signer_mismatch")
		}
	}
	nowUnix := now.UTC().Unix()
	if nowUnix < 0 || nowUnix >= 1<<63-1 {
		return fail("clock_out_of_range")
	}
	toVerify, err := marshal([]any{"Signature1", protected, []byte{}, payloadBytes})
	if err != nil {
		return fail("signature_input")
	}
	if err := verifier.Verify(toVerify, signature); err != nil {
		result.CryptographicSignature = "invalid"
		result.CallsignIdentity = "untrusted"
		return fail("invalid_signature")
	}
	result.CryptographicSignature = "valid"
	result.Claims = claims
	if created > nowUnix && created-nowUnix > int64(MaxFutureClockSkew/time.Second) {
		result.CallsignIdentity = "rejected"
		return fail("created_in_future")
	}
	if notAfter != nil && nowUnix >= *notAfter {
		result.CallsignIdentity = "rejected"
		return fail("expired")
	}
	contentDigest, contentSize, err := hashReader(content)
	if err != nil {
		result.ContentIntegrity = "unknown"
		result.CallsignIdentity = "not_checked"
		return fail("content_read_error")
	}
	if contentSize != size || !bytes.Equal(contentDigest[:], digest) {
		result.ContentIntegrity = "invalid"
		result.CallsignIdentity = "not_checked"
		return fail("content_mismatch")
	}
	result.ContentIntegrity = "valid"
	trustStatus := "untrusted"
	if trust != nil {
		trustStatus = trust(callsign, fmt.Sprintf("%x", kid), purpose)
	}
	if trustStatus == "trusted" {
		result.CallsignIdentity = "trusted"
	} else if trustStatus == "disabled" {
		result.CallsignIdentity = "rejected"
		return fail("key_disabled")
	} else {
		result.CallsignIdentity = "untrusted"
	}
	if trustStatus != "trusted" {
		result.OverallPolicy = "incomplete"
		result.Reason = "key_not_trusted"
		return result
	}
	result.OverallPolicy = "accepted"
	return result
}
