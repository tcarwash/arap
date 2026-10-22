package lotwenroll

import (
	"bytes"
	"os"
	"reflect"
	"testing"
)

func TestEnrollmentChallengeGoldenVector(t *testing.T) {
	var keyID, nonce [32]byte
	for i := range keyID {
		keyID[i] = byte(i + 1)
		nonce[i] = byte(i + 33)
	}
	challenge := Challenge{
		Version:  Version,
		Audience: "https://verifier.example", Callsign: "N0CALL", KeyID: keyID, Nonce: nonce,
		IssuedAt: 1800000000, ExpiresAt: 1800000060, Purposes: []string{PurposeChallengeResponse},
	}
	encoded, err := Encode(challenge)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../test-vectors/lotw-enrollment-v1/challenge.cbor")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, fixture) {
		t.Fatal("enrollment challenge differs from the canonical golden vector")
	}
	decoded, err := Decode(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, challenge) {
		t.Fatalf("decoded challenge differs from vector claims: %+v", decoded)
	}
}

func TestEnrollmentPurposeChallengeGoldenVector(t *testing.T) {
	var keyID, nonce [32]byte
	for i := range keyID {
		keyID[i] = byte(i + 1)
		nonce[i] = byte(i + 33)
	}
	challenge := Challenge{
		Version: VersionPurposes, Audience: "https://verifier.example", Callsign: "N0CALL",
		KeyID: keyID, Nonce: nonce, IssuedAt: 1800000000, ExpiresAt: 1800000060,
		Purposes: []string{PurposeChallengeResponse, PurposeContentSignature},
	}
	encoded, err := Encode(challenge)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../test-vectors/lotw-enrollment-v2/challenge.cbor")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, fixture) {
		t.Fatal("version 2 enrollment challenge differs from Python-generated vector")
	}
	decoded, err := Decode(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, challenge) {
		t.Fatalf("decoded version 2 challenge differs: %+v", decoded)
	}
}

func TestEnrollmentResponseShapeGoldenVector(t *testing.T) {
	challenge, err := os.ReadFile("../test-vectors/lotw-enrollment-v1/challenge.cbor")
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../test-vectors/lotw-enrollment-v1/response-shape.cbor")
	if err != nil {
		t.Fatal(err)
	}
	response := Response{Challenge: challenge, Chain: [][]byte{{0x30, 0x03, 0x02, 0x01, 0x01}}, PublicKey: make([]byte, 32), TQSL: make([]byte, 128), Ed25519: make([]byte, 64)}
	for i := range response.PublicKey {
		response.PublicKey[i] = byte(i)
	}
	for i := range response.TQSL {
		response.TQSL[i] = byte(i + 1)
	}
	for i := range response.Ed25519 {
		response.Ed25519[i] = byte(255 - i)
	}
	encoded, err := EncodeResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, fixture) {
		t.Fatal("encoded response differs from the deterministic shape vector")
	}
	if _, err := DecodeResponse(fixture); err != nil {
		t.Fatalf("decode response shape vector: %v", err)
	}
}
