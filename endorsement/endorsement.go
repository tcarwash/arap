// Package endorsement issues and verifies purpose-scoped delegations between
// ARAP Ed25519 keys. Verification is offline and starts from caller-supplied
// trust anchors; an endorsement never creates trust in its own issuer.
package endorsement

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/tcarwash/arap/protocol"
)

const (
	Purpose                  = "key-endorsement"
	ChainProfile             = "ARAP-key-endorsement-chain"
	ChainVersion             = 1
	PurposeContentSignature  = protocol.PurposeContent
	PurposeChallengeResponse = "challenge-response"
	MaxChainDepth            = 8
	MaxChainBytes            = 512 * 1024
	MaxLifetime              = 365 * 24 * time.Hour
	MaxFutureSkew            = 5 * time.Minute
)

var allowedPurposes = map[string]bool{
	PurposeContentSignature:  true,
	PurposeChallengeResponse: true,
	Purpose:                  true,
}

// Endorsement is an issuer's signed authorization of one subject key.
// MaxDelegationDepth limits how many additional endorsements the subject may
// issue beneath this statement. A value of zero grants use but no delegation.
type Endorsement struct {
	Issuer             string
	Subject            string
	SubjectPublicKey   ed25519.PublicKey
	Purposes           []string
	Created            int64
	NotAfter           int64
	MaxDelegationDepth uint8
}

// Anchor is application-owned trust. Purposes are the maximum authority the
// root may delegate, and MaxDelegationDepth bounds the complete chain below it.
type Anchor struct {
	Callsign           string
	PublicKey          ed25519.PublicKey
	Purposes           []string
	MaxDelegationDepth uint8
	Disabled           bool
}

type VerifyConfig struct {
	Anchors    []Anchor
	Subject    string
	SubjectKey ed25519.PublicKey
	Purpose    string
	Now        time.Time
	Disabled   func(callsign, keyID string) bool
}

type Result struct {
	Accepted           bool     `json:"accepted"`
	Issuer             string   `json:"issuer,omitempty"`
	Subject            string   `json:"subject,omitempty"`
	SubjectKeyID       string   `json:"subject_key_id_sha256,omitempty"`
	Purposes           []string `json:"purposes,omitempty"`
	ChainDepth         int      `json:"chain_depth"`
	MaxDelegationDepth uint8    `json:"max_delegation_depth,omitempty"`
	Reason             string   `json:"reason,omitempty"`
}

// Issue creates a signed key endorsement. Expiry and delegation are bounded
// before any payload is signed.
func Issue(signer protocol.Signer, subject string, subjectKey ed25519.PublicKey, purposes []string, maxDelegationDepth uint8, now time.Time, notAfter time.Time) ([]byte, Endorsement, error) {
	if signer == nil || len(subjectKey) != ed25519.PublicKeySize {
		return nil, Endorsement{}, errors.New("signer and Ed25519 subject key are required")
	}
	issuer, err := protocol.NormalizeCallsign(signer.Callsign())
	if err != nil {
		return nil, Endorsement{}, fmt.Errorf("issuer callsign: %w", err)
	}
	subject, err = protocol.NormalizeCallsign(subject)
	if err != nil {
		return nil, Endorsement{}, fmt.Errorf("subject callsign: %w", err)
	}
	if maxDelegationDepth > MaxChainDepth {
		return nil, Endorsement{}, fmt.Errorf("delegation depth exceeds %d", MaxChainDepth)
	}
	issuerKeyID, err := protocol.KeyID(signer.PublicKey())
	if err != nil {
		return nil, Endorsement{}, fmt.Errorf("issuer public key: %w", err)
	}
	subjectKeyID, err := protocol.KeyID(subjectKey)
	if err != nil || bytes.Equal(issuerKeyID, subjectKeyID) {
		return nil, Endorsement{}, errors.New("an endorsement must delegate to a different key")
	}
	purposes, err = normalizePurposes(purposes)
	if err != nil {
		return nil, Endorsement{}, err
	}
	if maxDelegationDepth > 0 && !contains(purposes, Purpose) {
		return nil, Endorsement{}, errors.New("delegation depth requires the key-endorsement purpose")
	}
	created := now.UTC().Unix()
	expires := notAfter.UTC().Unix()
	if created < 0 || expires <= created || expires-created > int64(MaxLifetime/time.Second) {
		return nil, Endorsement{}, errors.New("endorsement validity must be positive and no longer than one year")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(subjectKey)
	if err != nil {
		return nil, Endorsement{}, fmt.Errorf("encode subject public key: %w", err)
	}
	payload, err := protocol.EncodeCanonical(map[uint64]any{
		1: protocol.Profile,
		2: protocol.Version,
		3: Purpose,
		4: issuer,
		5: created,
		6: expires,
		7: map[uint64]any{1: subject, 2: publicDER, 3: purposes},
		8: uint64(maxDelegationDepth),
	})
	if err != nil {
		return nil, Endorsement{}, err
	}
	proof, err := protocol.SignPayload(signer, payload)
	if err != nil {
		return nil, Endorsement{}, err
	}
	return proof, Endorsement{Issuer: issuer, Subject: subject, SubjectPublicKey: append(ed25519.PublicKey(nil), subjectKey...), Purposes: purposes, Created: created, NotAfter: expires, MaxDelegationDepth: maxDelegationDepth}, nil
}

// EncodeChain serializes an ordered root-to-subject chain for storage or
// transport. This packages public signed statements only; it contains no
// trust decision or private key material.
func EncodeChain(chain [][]byte) ([]byte, error) {
	if len(chain) == 0 || len(chain) > MaxChainDepth {
		return nil, errors.New("endorsement chain must contain 1..8 links")
	}
	links := make([]any, len(chain))
	total := 0
	for i, proof := range chain {
		if len(proof) == 0 || len(proof) > protocol.MaxProofSize {
			return nil, fmt.Errorf("endorsement chain link %d has invalid size", i)
		}
		total += len(proof)
		if total > MaxChainBytes {
			return nil, errors.New("endorsement chain exceeds size limit")
		}
		links[i] = append([]byte(nil), proof...)
	}
	encoded, err := protocol.EncodeCanonical(map[uint64]any{1: ChainProfile, 2: uint64(ChainVersion), 3: links})
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxChainBytes {
		return nil, errors.New("encoded endorsement chain exceeds size limit")
	}
	return encoded, nil
}

// DecodeChain parses the bounded canonical chain container. Signature and
// trust checks are performed separately by Verify or VerifyEncoded.
func DecodeChain(encoded []byte) ([][]byte, error) {
	if len(encoded) == 0 || len(encoded) > MaxChainBytes {
		return nil, errors.New("encoded endorsement chain has invalid size")
	}
	var fields map[uint64]any
	if err := protocol.DecodeCanonical(encoded, &fields); err != nil {
		return nil, fmt.Errorf("invalid endorsement chain encoding: %w", err)
	}
	if len(fields) != 3 {
		return nil, errors.New("endorsement chain has invalid fields")
	}
	profile, ok := fields[1].(string)
	version, versionOK := uintValue(fields[2])
	values, linksOK := fields[3].([]any)
	if !ok || profile != ChainProfile || !versionOK || version != ChainVersion || !linksOK || len(values) == 0 || len(values) > MaxChainDepth {
		return nil, errors.New("unsupported endorsement chain profile or version")
	}
	chain := make([][]byte, len(values))
	total := 0
	for i, value := range values {
		proof, ok := value.([]byte)
		if !ok || len(proof) == 0 || len(proof) > protocol.MaxProofSize {
			return nil, fmt.Errorf("endorsement chain link %d has invalid type or size", i)
		}
		total += len(proof)
		if total > MaxChainBytes {
			return nil, errors.New("endorsement chain exceeds size limit")
		}
		chain[i] = append([]byte(nil), proof...)
	}
	return chain, nil
}

// VerifyEncoded decodes a portable chain bundle and applies the same explicit
// trust and purpose policy as Verify.
func VerifyEncoded(encoded []byte, config VerifyConfig) Result {
	chain, err := DecodeChain(encoded)
	if err != nil {
		return Result{Reason: "invalid_chain_encoding"}
	}
	return Verify(chain, config)
}

// Verify checks a root-to-subject proof chain against application-supplied
// anchors. Every link attenuates purpose and delegation authority. The last
// link must match the requested subject callsign and public key.
func Verify(chain [][]byte, config VerifyConfig) Result {
	result := Result{ChainDepth: len(chain)}
	fail := func(reason string) Result { result.Reason = reason; return result }
	if len(chain) == 0 || len(chain) > MaxChainDepth {
		return fail("chain_depth")
	}
	if len(config.SubjectKey) != ed25519.PublicKeySize || config.Purpose == "" || !allowedPurposes[config.Purpose] {
		return fail("invalid_expectation")
	}
	wantSubject, err := protocol.NormalizeCallsign(config.Subject)
	if err != nil {
		return fail("invalid_expected_subject")
	}
	wantKeyID, err := protocol.KeyID(config.SubjectKey)
	if err != nil {
		return fail("invalid_expected_key")
	}
	now := config.Now.UTC().Unix()
	if now < 0 {
		return fail("clock_out_of_range")
	}

	type authority struct {
		call     string
		key      ed25519.PublicKey
		purposes map[string]bool
		depth    uint8
	}
	var current authority
	anchorFound := false
	anchorDisabled := false
	for _, anchor := range config.Anchors {
		if len(anchor.PublicKey) != ed25519.PublicKeySize || anchor.MaxDelegationDepth > MaxChainDepth {
			continue
		}
		call, callErr := protocol.NormalizeCallsign(anchor.Callsign)
		id, idErr := protocol.KeyID(anchor.PublicKey)
		if callErr != nil || call != anchor.Callsign || idErr != nil || !bytes.Equal(id, firstIssuerKeyID(chain[0])) {
			continue
		}
		if anchor.Disabled {
			anchorDisabled = true
			continue
		}
		purposes := make(map[string]bool, len(anchor.Purposes))
		valid := true
		for _, purpose := range anchor.Purposes {
			if !allowedPurposes[purpose] || purposes[purpose] {
				valid = false
				break
			}
			purposes[purpose] = true
		}
		if !valid || !purposes[Purpose] {
			continue
		}
		current = authority{call: call, key: append(ed25519.PublicKey(nil), anchor.PublicKey...), purposes: purposes, depth: anchor.MaxDelegationDepth}
		anchorFound = true
		break
	}
	if !anchorFound {
		if anchorDisabled {
			return fail("root_disabled")
		}
		return fail("untrusted_root")
	}
	seenKeys := map[string]bool{}
	rootID, _ := protocol.KeyID(current.key)
	rootIDHex := hex.EncodeToString(rootID)
	if config.Disabled != nil && config.Disabled(current.call, rootIDHex) {
		return fail("root_disabled")
	}
	seenKeys[rootIDHex] = true
	currentVerifier, _ := protocol.NewEd25519Verifier(current.key)

	for i, proof := range chain {
		if current.depth == 0 {
			return fail("delegation_depth_exceeded")
		}
		payloadBytes, keyID, verifyErr := protocol.VerifyPayload(proof, currentVerifier)
		if verifyErr != nil {
			return fail("invalid_signature_or_envelope")
		}
		// VerifyPayload already checks the protected key id against the supplied
		// verifier key; retain this explicit comparison as a local invariant.
		if !bytes.Equal(keyID, mustKeyID(current.key)) {
			return fail("issuer_key_mismatch")
		}
		statement, parseErr := decode(payloadBytes)
		if parseErr != nil {
			return fail("invalid_endorsement_payload")
		}
		if statement.Issuer != current.call {
			return fail("issuer_callsign_mismatch")
		}
		if statement.Created > now && statement.Created-now > int64(MaxFutureSkew/time.Second) {
			return fail("issued_in_future")
		}
		if now >= statement.NotAfter {
			return fail("expired")
		}
		if statement.NotAfter <= statement.Created || statement.NotAfter-statement.Created > int64(MaxLifetime/time.Second) {
			return fail("invalid_validity")
		}
		if !isSubset(statement.Purposes, current.purposes) {
			return fail("purpose_escalation")
		}
		if statement.MaxDelegationDepth >= current.depth || statement.MaxDelegationDepth > MaxChainDepth {
			return fail("delegation_depth_escalation")
		}
		if statement.MaxDelegationDepth > 0 && !contains(statement.Purposes, Purpose) {
			return fail("delegation_without_purpose")
		}
		subjectID, idErr := protocol.KeyID(statement.SubjectPublicKey)
		if idErr != nil {
			return fail("invalid_subject_key")
		}
		subjectHex := hex.EncodeToString(subjectID)
		if seenKeys[subjectHex] {
			return fail("delegation_cycle")
		}
		if config.Disabled != nil && config.Disabled(statement.Subject, subjectHex) {
			return fail("subject_disabled")
		}
		seenKeys[subjectHex] = true
		if i == len(chain)-1 {
			if statement.Subject != wantSubject || !bytes.Equal(subjectID, wantKeyID) {
				return fail("subject_mismatch")
			}
			if !contains(statement.Purposes, config.Purpose) {
				return fail("purpose_not_authorized")
			}
			result.Accepted = true
			result.Issuer = statement.Issuer
			result.Subject = statement.Subject
			result.SubjectKeyID = subjectHex
			result.Purposes = append([]string(nil), statement.Purposes...)
			result.MaxDelegationDepth = statement.MaxDelegationDepth
			return result
		}
		current = authority{call: statement.Subject, key: statement.SubjectPublicKey, purposes: set(statement.Purposes), depth: statement.MaxDelegationDepth}
		currentVerifier, _ = protocol.NewEd25519Verifier(current.key)
	}
	return fail("incomplete_chain")
}

func decode(payload []byte) (Endorsement, error) {
	var fields map[uint64]any
	if err := protocol.DecodeCanonical(payload, &fields); err != nil || len(fields) != 8 {
		return Endorsement{}, errors.New("invalid fields")
	}
	for label := range fields {
		if label < 1 || label > 8 {
			return Endorsement{}, errors.New("unknown field")
		}
	}
	profile, ok1 := fields[1].(string)
	version, ok2 := uintValue(fields[2])
	purpose, ok3 := fields[3].(string)
	issuer, ok4 := fields[4].(string)
	created, ok5 := intValue(fields[5])
	expires, ok6 := intValue(fields[6])
	subjectMap, ok7 := fields[7].(map[uint64]any)
	depth, ok8 := uintValue(fields[8])
	if !ok1 || profile != protocol.Profile || !ok2 || version != protocol.Version || !ok3 || purpose != Purpose || !ok4 || !ok5 || !ok6 || !ok7 || !ok8 || depth > MaxChainDepth || len(subjectMap) != 3 {
		return Endorsement{}, errors.New("invalid values")
	}
	for label := range subjectMap {
		if label < 1 || label > 3 {
			return Endorsement{}, errors.New("unknown subject field")
		}
	}
	subject, ok := subjectMap[1].(string)
	if !ok {
		return Endorsement{}, errors.New("invalid subject callsign")
	}
	publicDER, ok := subjectMap[2].([]byte)
	if !ok {
		return Endorsement{}, errors.New("invalid public key")
	}
	publicKeyAny, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return Endorsement{}, err
	}
	publicKey, ok := publicKeyAny.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return Endorsement{}, errors.New("subject key must be Ed25519")
	}
	canonicalPublicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !bytes.Equal(canonicalPublicDER, publicDER) {
		return Endorsement{}, errors.New("subject public key must use canonical DER")
	}
	purposes, err := stringList(subjectMap[3])
	if err != nil {
		return Endorsement{}, err
	}
	issuerNorm, err := protocol.NormalizeCallsign(issuer)
	if err != nil || issuerNorm != issuer {
		return Endorsement{}, errors.New("issuer callsign is not normalized")
	}
	subjectNorm, err := protocol.NormalizeCallsign(subject)
	if err != nil || subjectNorm != subject {
		return Endorsement{}, errors.New("subject callsign is not normalized")
	}
	return Endorsement{Issuer: issuer, Subject: subject, SubjectPublicKey: append(ed25519.PublicKey(nil), publicKey...), Purposes: purposes, Created: created, NotAfter: expires, MaxDelegationDepth: uint8(depth)}, nil
}

func normalizePurposes(purposes []string) ([]string, error) {
	if len(purposes) == 0 || len(purposes) > len(allowedPurposes) {
		return nil, errors.New("endorsement requires 1..3 purposes")
	}
	result := append([]string(nil), purposes...)
	sort.Strings(result)
	for i, purpose := range result {
		if !allowedPurposes[purpose] || (i > 0 && result[i-1] == purpose) {
			return nil, fmt.Errorf("invalid or duplicate endorsement purpose %q", purpose)
		}
	}
	return result, nil
}

func stringList(value any) ([]string, error) {
	var list []string
	switch values := value.(type) {
	case []string:
		list = append(list, values...)
	case []any:
		for _, value := range values {
			item, ok := value.(string)
			if !ok {
				return nil, errors.New("invalid purpose list")
			}
			list = append(list, item)
		}
	default:
		return nil, errors.New("invalid purpose list")
	}
	normalized, err := normalizePurposes(list)
	if err != nil || !equalStrings(list, normalized) {
		return nil, errors.New("purpose list must be sorted, unique, and supported")
	}
	return normalized, nil
}

func uintValue(value any) (uint64, bool) {
	switch value := value.(type) {
	case uint64:
		return value, true
	case int64:
		if value >= 0 {
			return uint64(value), true
		}
	}
	return 0, false
}

func intValue(value any) (int64, bool) {
	switch value := value.(type) {
	case uint64:
		if value <= 1<<63-1 {
			return int64(value), true
		}
	case int64:
		if value >= 0 {
			return value, true
		}
	}
	return 0, false
}

func isSubset(child []string, parent map[string]bool) bool {
	for _, purpose := range child {
		if !parent[purpose] {
			return false
		}
	}
	return true
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func set(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustKeyID(key ed25519.PublicKey) []byte {
	id, _ := protocol.KeyID(key)
	return id
}

func firstIssuerKeyID(proof []byte) []byte {
	headers, _, err := protocol.InspectProof(proof)
	if err != nil {
		return nil
	}
	id, ok := headers[4].([]byte)
	if !ok || len(id) != 32 {
		return nil
	}
	return id
}
