package protocol

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type signerOverride struct {
	Signer
	algorithm int64
	public    crypto.PublicKey
	signature []byte
}

func (s signerOverride) Algorithm() int64            { return s.algorithm }
func (s signerOverride) PublicKey() crypto.PublicKey { return s.public }
func (s signerOverride) Sign([]byte) ([]byte, error) { return s.signature, nil }

func testIdentity(t *testing.T) (*Ed25519Signer, *Ed25519Verifier, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	signer, err := NewEd25519Signer("ag7su", private)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEd25519Verifier(private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	id, err := KeyID(verifier.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier, hex.EncodeToString(id)
}

func TestContentSignVerifyAndTrust(t *testing.T) {
	signer, verifier, keyID := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	content := []byte("ARAP test card")
	proof, claims, err := SignContent(signer, bytes.NewReader(content), ContentMetadata{MediaType: "application/octet-stream", Context: "test/card/v1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Callsign != "AG7SU" || claims.Size != uint64(len(content)) {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	expected := Expected{Purpose: PurposeContent, MediaType: "application/octet-stream", Canonicalization: "identity-v1", Context: "test/card/v1"}
	trust := func(call, id, purpose string) bool {
		return call == "AG7SU" && id == keyID && purpose == PurposeContent
	}
	result := VerifyContent(proof, bytes.NewReader(content), verifier, expected, trust, now.Add(time.Second))
	if result.OverallPolicy != "accepted" || result.CryptographicSignature != "valid" || result.ContentIntegrity != "valid" {
		t.Fatalf("unexpected result: %#v", result)
	}
	result = VerifyContent(proof, bytes.NewReader(content), verifier, expected, nil, now)
	if result.OverallPolicy != "incomplete" || result.CallsignIdentity != "untrusted" {
		t.Fatalf("unknown trust was not distinguished: %#v", result)
	}
	disabled := VerifyContentWithTrust(proof, bytes.NewReader(content), verifier, expected, func(string, string, string) string { return "disabled" }, now)
	if disabled.OverallPolicy != "rejected" || disabled.CallsignIdentity != "rejected" || disabled.Reason != "key_disabled" {
		t.Fatalf("disabled key was not distinguished: %#v", disabled)
	}
}

func TestDecodeCanonicalArrayElementLimit(t *testing.T) {
	for _, count := range []int{16, 17} {
		values := make([]any, count)
		for i := range values {
			values[i] = uint64(i)
		}
		encoded, err := EncodeCanonical(values)
		if err != nil {
			t.Fatal(err)
		}
		var decoded []any
		err = DecodeCanonical(encoded, &decoded)
		if count == 16 && err != nil {
			t.Fatalf("rejected array at configured limit: %v", err)
		}
		if count == 17 && err == nil {
			t.Fatal("accepted array above configured element limit")
		}
	}
}

func TestSignPayloadRejectsOversizedEncodedEnvelope(t *testing.T) {
	signer, _, _ := testIdentity(t)
	payload, err := EncodeCanonical(map[uint64]any{1: bytes.Repeat([]byte{0x41}, MaxProofSize-16)})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > MaxProofSize {
		t.Fatalf("test payload size=%d exceeds input limit", len(payload))
	}
	proof, err := SignPayload(signer, payload)
	if err == nil {
		t.Fatalf("accepted payload whose encoded COSE envelope size=%d exceeds limit %d", len(proof), MaxProofSize)
	}
}

func TestSigningRejectsInvalidEd25519Providers(t *testing.T) {
	base, _, _ := testIdentity(t)
	public := base.PublicKey().(ed25519.PublicKey)
	validPayload, err := EncodeCanonical(map[uint64]any{1: "test"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		algorithm int64
		public    crypto.PublicKey
		signature []byte
	}{
		{name: "wrong algorithm", algorithm: -37, public: public, signature: make([]byte, ed25519.SignatureSize)},
		{name: "wrong public key type", algorithm: AlgorithmEd25519, public: []byte("not ed25519"), signature: make([]byte, ed25519.SignatureSize)},
		{name: "short signature", algorithm: AlgorithmEd25519, public: public, signature: make([]byte, ed25519.SignatureSize-1)},
		{name: "invalid signature", algorithm: AlgorithmEd25519, public: public, signature: make([]byte, ed25519.SignatureSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := signerOverride{Signer: base, algorithm: tc.algorithm, public: tc.public, signature: tc.signature}
			if _, _, err := SignContent(provider, strings.NewReader("test"), ContentMetadata{MediaType: "text/plain", Context: "test/v1"}, time.Unix(1_800_000_000, 0)); err == nil {
				t.Fatal("content signer accepted invalid Ed25519 provider output")
			}
			if _, err := SignPayload(provider, validPayload); err == nil {
				t.Fatal("payload signer accepted invalid Ed25519 provider output")
			}
		})
	}
}

func TestCallsignNormalizationRejectsNonASCIICaseMappings(t *testing.T) {
	call, err := NormalizeCallsign(" ag7su ")
	if err != nil || call != "AG7SU" {
		t.Fatalf("ASCII callsign normalization=(%q,%v)", call, err)
	}
	for _, invalid := range []string{"ſ1u", "AG\u00a07SU", "AG7SU\n"} {
		if normalized, err := NormalizeCallsign(invalid); err == nil {
			t.Errorf("accepted non-ASCII/control callsign %q as %q", invalid, normalized)
		}
	}
}

func TestSignContentRejectsOutOfProfileTimestampAndInvalidUTF8(t *testing.T) {
	signer, _, _ := testIdentity(t)
	beforeEpoch := time.Unix(-1, 0)
	if _, _, err := SignContent(signer, strings.NewReader("x"), ContentMetadata{MediaType: "text/plain", Context: "test/v1"}, beforeEpoch); err == nil {
		t.Fatal("signed a negative created timestamp")
	}
	now := time.Unix(1_800_000_000, 0)
	for _, meta := range []ContentMetadata{
		{MediaType: string([]byte{0xff}), Context: "test/v1"},
		{MediaType: "text/plain", Context: string([]byte{0xff})},
		{MediaType: "text/plain", Context: "test/v1", ContentID: string([]byte{0xff})},
	} {
		if _, _, err := SignContent(signer, strings.NewReader("x"), meta, now); err == nil {
			t.Errorf("signed metadata containing invalid UTF-8: %#v", meta)
		}
	}
}

func TestContentVerificationRejectsChangedBytesAndContext(t *testing.T) {
	signer, verifier, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	proof, _, err := SignContent(signer, strings.NewReader("original"), ContentMetadata{MediaType: "text/plain", Context: "test/v1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	trusted := func(string, string, string) bool { return true }
	expected := Expected{Purpose: PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "test/v1"}
	missingCanonicalization := expected
	missingCanonicalization.Canonicalization = ""
	result := VerifyContent(proof, strings.NewReader("original"), verifier, missingCanonicalization, trusted, now)
	if result.Reason != "expected_purpose_type_canonicalization_context_required" {
		t.Fatalf("missing canonicalization expectation was not rejected: %#v", result)
	}
	result = VerifyContent(proof, strings.NewReader("modified"), verifier, expected, trusted, now)
	if result.OverallPolicy != "rejected" || result.ContentIntegrity != "invalid" {
		t.Fatalf("modified content accepted: %#v", result)
	}
	expected.Context = "other/v1"
	result = VerifyContent(proof, strings.NewReader("original"), verifier, expected, trusted, now)
	if result.Reason != "content_expectation_mismatch" {
		t.Fatalf("wrong context not rejected: %#v", result)
	}
	expected.Context = "test/v1"
	expected.Canonicalization = "other-v1"
	result = VerifyContent(proof, strings.NewReader("original"), verifier, expected, trusted, now)
	if result.Reason != "content_expectation_mismatch" {
		t.Fatalf("wrong canonicalization not rejected: %#v", result)
	}
}

func TestExpiredContentProofRejected(t *testing.T) {
	signer, verifier, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	until := now.Add(time.Minute)
	proof, _, err := SignContent(signer, strings.NewReader("x"), ContentMetadata{MediaType: "text/plain", Context: "test/v1", NotAfter: &until}, now)
	if err != nil {
		t.Fatal(err)
	}
	result := VerifyContent(proof, strings.NewReader("x"), verifier, Expected{Purpose: PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "test/v1"}, func(string, string, string) bool { return true }, until)
	if result.OverallPolicy != "rejected" || result.Reason != "expired" ||
		result.CryptographicSignature != "valid" || result.ContentIntegrity != "not_checked" ||
		result.CallsignIdentity != "rejected" {
		t.Fatalf("expired proof accepted: %#v", result)
	}
	var envelope cbor.Tag
	if err := unmarshal(proof, &envelope); err != nil {
		t.Fatal(err)
	}
	items := envelope.Content.([]any)
	signature := append([]byte(nil), items[3].([]byte)...)
	signature[0] ^= 0x01
	items[3] = signature
	tampered, err := marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	result = VerifyContent(tampered, strings.NewReader("x"), verifier, Expected{Purpose: PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "test/v1"}, func(string, string, string) bool { return true }, until)
	if result.OverallPolicy != "rejected" || result.Reason != "invalid_signature" || result.CryptographicSignature != "invalid" {
		t.Fatalf("tampered expired proof was misclassified: %#v", result)
	}
	if err := unmarshal(proof, &envelope); err != nil {
		t.Fatal(err)
	}
	items = envelope.Content.([]any)
	var payload map[uint64]any
	if err := unmarshal(items[2].([]byte), &payload); err != nil {
		t.Fatal(err)
	}
	payload[6] = uint64(until.Unix() - 1)
	items[2], err = marshal(payload) // Keep the old signature to model an unauthenticated expiry edit.
	if err != nil {
		t.Fatal(err)
	}
	tampered, err = marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	result = VerifyContent(tampered, strings.NewReader("x"), verifier, Expected{Purpose: PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "test/v1"}, func(string, string, string) bool { return true }, until)
	if result.OverallPolicy != "rejected" || result.Reason != "invalid_signature" || result.CryptographicSignature != "invalid" {
		t.Fatalf("unauthenticated expiry claim was misclassified: %#v", result)
	}
}

func TestContentProofEnforcesMaximumFutureClockSkew(t *testing.T) {
	signer, verifier, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	expected := Expected{Purpose: PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "future/v1"}
	trusted := func(string, string, string) bool { return true }
	for _, tc := range []struct {
		name     string
		ahead    time.Duration
		accepted bool
		reason   string
	}{
		{name: "at skew limit", ahead: MaxFutureClockSkew, accepted: true},
		{name: "over skew limit", ahead: MaxFutureClockSkew + time.Second, reason: "created_in_future"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof, _, err := SignContent(signer, strings.NewReader("future proof"), ContentMetadata{MediaType: "text/plain", Context: "future/v1"}, now.Add(tc.ahead))
			if err != nil {
				t.Fatal(err)
			}
			result := VerifyContent(proof, strings.NewReader("future proof"), verifier, expected, trusted, now)
			if tc.accepted {
				if result.OverallPolicy != "accepted" || result.CryptographicSignature != "valid" {
					t.Fatalf("proof at skew boundary rejected: %#v", result)
				}
			} else if result.OverallPolicy != "rejected" || result.CryptographicSignature != "valid" || result.Reason != tc.reason {
				t.Fatalf("proof beyond skew boundary result=%#v", result)
			}
		})
	}
}

func TestPythonVectorMatchesGoEncoding(t *testing.T) {
	base := "../test-vectors/content-ed25519-v1/"
	seedHex, err := os.ReadFile(base + "test-seed.hex")
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	signer, err := NewEd25519Signer("AG7SU", private)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(base + "content.bin")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(base + "proof.cbor")
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := SignContent(signer, bytes.NewReader(content), ContentMetadata{MediaType: "application/octet-stream", Context: "arap/interoperability/v1"}, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Go COSE bytes differ from independent Python vector\n got %x\nwant %x", got, want)
	}
	manifestBytes, err := os.ReadFile(base + "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		NegativeChecks map[string]bool `json:"negative_checks"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"modified_content", "wrong_context", "untrusted_key", "wrong_public_key", "corrupt_signature", "unknown_signed_label", "future_created", "expired_content", "null_expiry", "empty_content_id"} {
		if !manifest.NegativeChecks[name] {
			t.Fatalf("independent Python negative check %q did not reject", name)
		}
	}
}

func TestInspectProofDoesNotAuthenticateClaims(t *testing.T) {
	signer, _, _ := testIdentity(t)
	proof, _, err := SignContent(signer, strings.NewReader("inspect me"), ContentMetadata{MediaType: "text/plain", Context: "inspect/v1"}, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	proof[len(proof)-1] ^= 1 // Keep the envelope canonical but make the signature invalid.
	headers, payload, err := InspectProof(proof)
	if err != nil {
		t.Fatalf("inspection should parse without signature verification: %v", err)
	}
	if headers[1] != AlgorithmEd25519 {
		t.Fatalf("unexpected headers: %#v", headers)
	}
	claims, ok := payload.(map[uint64]any)
	if !ok || claims[3] != PurposeContent {
		t.Fatalf("unexpected untrusted claims: %#v", payload)
	}
}

func TestVerifyContentReturnsOnlyAuthenticatedClaims(t *testing.T) {
	signer, verifier, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	content := []byte("claims need a valid signature")
	proof, _, err := SignContent(signer, bytes.NewReader(content), ContentMetadata{MediaType: "text/plain", Context: "claims/v1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	expected := Expected{Purpose: PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "claims/v1"}
	trusted := func(string, string, string) bool { return true }

	valid := VerifyContent(proof, bytes.NewReader(content), verifier, expected, trusted, now)
	if valid.CryptographicSignature != "valid" || valid.Claims == nil || valid.Claims.Callsign != signer.Callsign() {
		t.Fatalf("valid signature did not expose authenticated claims: %#v", valid)
	}

	var envelope cbor.Tag
	if err := unmarshal(proof, &envelope); err != nil {
		t.Fatal(err)
	}
	items := envelope.Content.([]any)
	signature := append([]byte(nil), items[3].([]byte)...)
	signature[0] ^= 1
	items[3] = signature
	invalidProof, err := marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	invalid := VerifyContent(invalidProof, bytes.NewReader(content), verifier, expected, trusted, now)
	if invalid.CryptographicSignature != "invalid" || invalid.Claims != nil {
		t.Fatalf("invalid signature exposed unauthenticated claims: %#v", invalid)
	}

	wrongExpectation := expected
	wrongExpectation.Context = "other/v1"
	unmatched := VerifyContent(proof, bytes.NewReader(content), verifier, wrongExpectation, trusted, now)
	if unmatched.CryptographicSignature != "not_checked" || unmatched.Claims != nil {
		t.Fatalf("unchecked proof exposed claims: %#v", unmatched)
	}
}

func TestMalformedCOSEAndCBORAreRejected(t *testing.T) {
	signer, verifier, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	content := []byte("strict parser")
	proof, _, err := SignContent(signer, bytes.NewReader(content), ContentMetadata{MediaType: "text/plain", Context: "strict/v1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	expected := Expected{Purpose: PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "strict/v1"}
	mutate := func(change func([]any)) []byte {
		var tag cbor.Tag
		if err := unmarshal(proof, &tag); err != nil {
			t.Fatal(err)
		}
		arr := tag.Content.([]any)
		change(arr)
		out, err := marshal(cborTag18(arr))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	unsupported := mutate(func(arr []any) {
		protected := arr[0].([]byte)
		var h map[uint64]any
		if err := unmarshal(protected, &h); err != nil {
			t.Fatal(err)
		}
		h[1] = int64(-8)
		encoded, err := marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		arr[0] = encoded
	})
	wrongKID := mutate(func(arr []any) {
		protected := arr[0].([]byte)
		var h map[uint64]any
		if err := unmarshal(protected, &h); err != nil {
			t.Fatal(err)
		}
		h[4] = bytes.Repeat([]byte{0}, 32)
		encoded, err := marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		arr[0] = encoded
	})
	shortKID := mutate(func(arr []any) {
		protected := arr[0].([]byte)
		var h map[uint64]any
		if err := unmarshal(protected, &h); err != nil {
			t.Fatal(err)
		}
		h[4] = []byte{1}
		encoded, err := marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		arr[0] = encoded
	})
	extraHeader := mutate(func(arr []any) {
		protected := arr[0].([]byte)
		var h map[uint64]any
		if err := unmarshal(protected, &h); err != nil {
			t.Fatal(err)
		}
		h[5] = "extra"
		encoded, err := marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		arr[0] = encoded
	})
	wrongContentType := mutate(func(arr []any) {
		protected := arr[0].([]byte)
		var h map[uint64]any
		if err := unmarshal(protected, &h); err != nil {
			t.Fatal(err)
		}
		h[3] = "application/cbor"
		encoded, err := marshal(h)
		if err != nil {
			t.Fatal(err)
		}
		arr[0] = encoded
	})
	noncanonicalHeader := mutate(func(arr []any) {
		protected := append([]byte(nil), arr[0].([]byte)...)
		if len(protected) < 3 || protected[2] != 0x32 { // -19 encoded in one byte
			t.Fatalf("unexpected protected header encoding: %x", protected)
		}
		protected = append(protected[:2], append([]byte{0x38, 0x12}, protected[3:]...)...)
		arr[0] = protected
	})
	noncanonicalPayload := mutate(func(arr []any) {
		payload := arr[2].([]byte)
		needle := []byte{0x05, 0x1a, 0x6b, 0x49, 0xd2, 0x00} // label 5, uint32(created)
		index := bytes.Index(payload, needle)
		if index < 0 {
			t.Fatalf("created integer encoding not found in payload: %x", payload)
		}
		longForm := []byte{0x05, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x6b, 0x49, 0xd2, 0x00}
		payload = append(append(append([]byte(nil), payload[:index]...), longForm...), payload[index+len(needle):]...)
		arr[2] = payload
	})
	nonemptyUnprotected := mutate(func(arr []any) { arr[1] = map[uint64]any{5: "extra"} })
	detachedPayload := mutate(func(arr []any) { arr[2] = nil })
	badShape, err := marshal(cborTag18([]any{}))
	if err != nil {
		t.Fatal(err)
	}
	duplicateHeader := mutate(func(arr []any) { arr[0] = []byte{0xa2, 0x01, 0x32, 0x01, 0x32} })
	wrongTag := mutate(func(arr []any) {})
	var tag cbor.Tag
	if err := unmarshal(wrongTag, &tag); err != nil {
		t.Fatal(err)
	}
	tag.Number = 17
	wrongTag, err = marshal(tag)
	if err != nil {
		t.Fatal(err)
	}
	badSignature := append([]byte(nil), proof...)
	badSignature[len(badSignature)-1] ^= 0x80
	badSignatureLength := mutate(func(arr []any) { arr[3] = []byte{1} })
	cases := []struct {
		name   string
		proof  []byte
		reason string
	}{
		{name: "trailing item", proof: append(append([]byte(nil), proof...), 0), reason: "malformed_cbor"},
		{name: "wrong tag", proof: wrongTag, reason: "wrong_cose_tag"},
		{name: "wrong envelope shape", proof: badShape, reason: "invalid_cose_sign1_shape"},
		{name: "nonempty unprotected headers", proof: nonemptyUnprotected, reason: "unprotected_headers_forbidden"},
		{name: "detached payload", proof: detachedPayload, reason: "detached_payload_forbidden"},
		{name: "duplicate protected label", proof: duplicateHeader, reason: "malformed_protected_headers"},
		{name: "extra protected label", proof: extraHeader, reason: "protected_header_set"},
		{name: "wrong content type", proof: wrongContentType, reason: "content_type"},
		{name: "noncanonical protected headers", proof: noncanonicalHeader, reason: "non_deterministic_protected_headers"},
		{name: "noncanonical payload", proof: noncanonicalPayload, reason: "non_deterministic_payload"},
		{name: "short key id", proof: shortKID, reason: "key_id"},
		{name: "unsupported algorithm", proof: unsupported, reason: "unsupported_or_mismatched_algorithm"},
		{name: "wrong key id", proof: wrongKID, reason: "key_mismatch"},
		{name: "invalid signature", proof: badSignature, reason: "invalid_signature"},
		{name: "invalid signature length", proof: badSignatureLength, reason: "invalid_signature_value"},
		{name: "oversized proof", proof: bytes.Repeat([]byte{0}, MaxProofSize+1), reason: "proof_size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := VerifyContent(tc.proof, bytes.NewReader(content), verifier, expected, func(string, string, string) bool { return true }, now)
			if result.OverallPolicy != "rejected" || result.Reason != tc.reason {
				t.Fatalf("result=%#v, want reason %q", result, tc.reason)
			}
		})
	}
}

func TestCorrectlySignedInvalidPayloadSchemasAreRejected(t *testing.T) {
	signer, verifier, _ := testIdentity(t)
	now := time.Unix(1_800_000_000, 0)
	content := []byte("signed invalid schema")
	valid, _, err := SignContent(signer, bytes.NewReader(content), ContentMetadata{MediaType: "text/plain", Context: "schema/v1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	var envelope cbor.Tag
	if err := unmarshal(valid, &envelope); err != nil {
		t.Fatal(err)
	}
	validPayload := envelope.Content.([]any)[2].([]byte)
	expected := Expected{Purpose: PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "schema/v1"}
	cases := []struct {
		name   string
		mutate func(map[uint64]any)
		reason string
	}{
		{name: "unknown top-level label", mutate: func(m map[uint64]any) { m[8] = "extension" }, reason: "payload_fields"},
		{name: "wrong profile", mutate: func(m map[uint64]any) { m[1] = "OTHER" }, reason: "profile"},
		{name: "unsupported version", mutate: func(m map[uint64]any) { m[2] = uint64(2) }, reason: "version"},
		{name: "unsupported purpose", mutate: func(m map[uint64]any) { m[3] = "authentication" }, reason: "purpose_mismatch"},
		{name: "lowercase signer", mutate: func(m map[uint64]any) { m[4] = "ag7su" }, reason: "signer_normalization"},
		{name: "boolean timestamp", mutate: func(m map[uint64]any) { m[5] = true }, reason: "created"},
		{name: "negative timestamp", mutate: func(m map[uint64]any) { m[5] = int64(-1) }, reason: "created"},
		{name: "not after equal to created", mutate: func(m map[uint64]any) { m[6] = uint64(1_800_000_000) }, reason: "not_after"},
		{name: "unknown subject label", mutate: func(m map[uint64]any) { subject := m[7].(map[uint64]any); subject[8] = uint64(1) }, reason: "subject_fields"},
		{name: "negative content size", mutate: func(m map[uint64]any) { m[7].(map[uint64]any)[5] = int64(-1) }, reason: "content_size"},
		{name: "short content digest", mutate: func(m map[uint64]any) { m[7].(map[uint64]any)[4] = bytes.Repeat([]byte{1}, 31) }, reason: "content_digest"},
		{name: "invalid content id", mutate: func(m map[uint64]any) { m[7].(map[uint64]any)[6] = "" }, reason: "content_id"},
		{name: "oversized media type", mutate: func(m map[uint64]any) { m[7].(map[uint64]any)[1] = strings.Repeat("x", 129) }, reason: "media_type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var payload map[uint64]any
			if err := unmarshal(validPayload, &payload); err != nil {
				t.Fatal(err)
			}
			tc.mutate(payload)
			encoded, err := marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := SignPayload(signer, encoded)
			if err != nil {
				t.Fatal(err)
			}
			result := VerifyContent(proof, bytes.NewReader(content), verifier, expected, func(string, string, string) bool { return true }, now)
			if result.OverallPolicy != "rejected" || result.Reason != tc.reason {
				t.Fatalf("signed invalid schema accepted or misclassified: %#v", result)
			}
		})
	}
	t.Run("duplicate payload label", func(t *testing.T) {
		if len(validPayload) == 0 || validPayload[0] != 0xa6 {
			t.Fatalf("unexpected test payload map prefix: %x", validPayload[:1])
		}
		duplicate := append([]byte{0xa7}, validPayload[1:]...)
		duplicate = append(duplicate, []byte{0x01, 0x64, 'A', 'R', 'A', 'P'}...)
		var env cbor.Tag
		if err := unmarshal(valid, &env); err != nil {
			t.Fatal(err)
		}
		protected := env.Content.([]any)[0].([]byte)
		toSign, err := marshal([]any{"Signature1", protected, []byte{}, duplicate})
		if err != nil {
			t.Fatal(err)
		}
		signature, err := signer.Sign(toSign)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := marshal(cborTag18([]any{protected, map[uint64]any{}, duplicate, signature}))
		if err != nil {
			t.Fatal(err)
		}
		result := VerifyContent(proof, bytes.NewReader(content), verifier, expected, func(string, string, string) bool { return true }, now)
		if result.OverallPolicy != "rejected" || result.Reason != "malformed_payload" {
			t.Fatalf("duplicate signed payload label result=%#v", result)
		}
	})
}

func FuzzVerifyContentProofParser(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	signer, _ := NewEd25519Signer("AG7SU", private)
	verifier, _ := NewEd25519Verifier(private.Public().(ed25519.PublicKey))
	valid, _, err := SignContent(signer, strings.NewReader("fuzz seed"), ContentMetadata{MediaType: "text/plain", Context: "fuzz/v1"}, time.Unix(1_800_000_000, 0))
	if err == nil {
		f.Add(valid)
	}
	f.Add([]byte{})
	f.Add([]byte{0xd2, 0x80})
	f.Fuzz(func(t *testing.T, proof []byte) {
		if len(proof) > MaxProofSize+1 {
			return
		}
		VerifyContent(proof, strings.NewReader("fuzz seed"), verifier, Expected{Purpose: PurposeContent, MediaType: "text/plain", Canonicalization: "identity-v1", Context: "fuzz/v1"}, func(string, string, string) bool { return true }, time.Unix(1_800_000_001, 0))
	})
}
