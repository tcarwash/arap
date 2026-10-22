package pixelqso

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/tcarwash/arap/protocol"
)

// SignJSON validates and canonicalizes a saved PixelQSO card, checks an
// optional frame-2 link, then signs the canonical card bytes as an ARAP
// content proof. Proof bytes contain authenticated claims and a digest, not
// the card itself; callers transport or store the card separately.
func SignJSON(signer protocol.Signer, cardJSON, firstCardJSON []byte, now time.Time) ([]byte, protocol.ContentClaims, error) {
	if signer == nil {
		return nil, protocol.ContentClaims{}, errors.New("PixelQSO signer is required")
	}
	canonical, card, err := CanonicalizeJSON(cardJSON)
	if err != nil {
		return nil, protocol.ContentClaims{}, err
	}
	signerCallsign, err := protocol.NormalizeCallsign(signer.Callsign())
	if err != nil || signerCallsign != card.Callsign {
		return nil, protocol.ContentClaims{}, errors.New("PixelQSO signer callsign must match card callsign")
	}
	if err := validateFrameLinkJSON(firstCardJSON, card); err != nil {
		return nil, protocol.ContentClaims{}, err
	}
	return protocol.SignContent(signer, bytes.NewReader(canonical), protocol.ContentMetadata{
		MediaType: MediaType, Canonicalization: "identity-v1", Context: Context,
	}, now)
}

// VerifyJSON validates and canonicalizes a saved PixelQSO card, verifies its
// optional frame-2 link, then evaluates the proof and the caller's identity
// policy. The returned result keeps signature, content integrity, callsign
// identity and overall policy outcomes separate.
func VerifyJSON(proof, cardJSON, firstCardJSON []byte, verifier protocol.Verifier,
	trust func(callsign, keyID, purpose string) string, now time.Time,
) (protocol.VerifyResult, error) {
	canonical, card, err := CanonicalizeJSON(cardJSON)
	if err != nil {
		return protocol.VerifyResult{}, err
	}
	if err := validateFrameLinkJSON(firstCardJSON, card); err != nil {
		return protocol.VerifyResult{}, err
	}
	if verifier == nil {
		return protocol.VerifyResult{}, errors.New("PixelQSO verifier is required")
	}
	return protocol.VerifyContentWithTrust(proof, bytes.NewReader(canonical), verifier, protocol.Expected{
		Purpose: protocol.PurposeContent, MediaType: MediaType,
		Canonicalization: "identity-v1", Context: Context, Callsign: card.Callsign,
	}, trust, now), nil
}

func validateFrameLinkJSON(firstCardJSON []byte, card Card) error {
	if card.Animation == nil {
		if len(firstCardJSON) != 0 {
			return errors.New("first-frame card is only valid for a frame-2 card")
		}
		return nil
	}
	if len(firstCardJSON) == 0 {
		return errors.New("first-frame card is required for a frame-2 card")
	}
	_, first, err := CanonicalizeJSON(firstCardJSON)
	if err != nil {
		return fmt.Errorf("invalid first-frame card: %w", err)
	}
	return ValidateAnimationPair(first, card)
}
