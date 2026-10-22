// Command content-proof demonstrates ARAP signing and verification from a
// separate Go application using only exported packages.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"github.com/tcarwash/arap/protocol"
)

func main() {
	const callsign = "N0CALL"
	content := []byte("sample application data\n")
	now := time.Now().UTC()

	signer, err := protocol.GenerateEd25519(callsign)
	if err != nil {
		log.Fatal(err)
	}
	proof, claims, err := protocol.SignContent(signer, bytes.NewReader(content), protocol.ContentMetadata{
		MediaType: "text/plain",
		Context:   "example-app/demo-object",
	}, now)
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := protocol.NewEd25519Verifier(signer.PublicKey().(ed25519.PublicKey))
	if err != nil {
		log.Fatal(err)
	}
	keyID, err := protocol.KeyID(verifier.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	trustedKeyID := hex.EncodeToString(keyID)
	result := protocol.VerifyContentWithTrust(
		proof,
		bytes.NewReader(content),
		verifier,
		protocol.Expected{
			Purpose:          protocol.PurposeContent,
			MediaType:        "text/plain",
			Canonicalization: "identity-v1",
			Context:          "example-app/demo-object",
			Callsign:         callsign,
		},
		func(call, id, purpose string) string {
			if call == callsign && id == trustedKeyID && purpose == protocol.PurposeContent {
				return "trusted"
			}
			return "untrusted"
		},
		now,
	)
	if result.OverallPolicy != "accepted" {
		log.Fatalf("proof rejected: %s", result.Reason)
	}
	fmt.Printf("accepted callsign=%s key_id=%s bytes=%d context=%s\n", claims.Callsign, claims.KeyID, claims.Size, claims.Context)
}
