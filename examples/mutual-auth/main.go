// Command mutual-auth demonstrates coordinated two-party challenge
// authentication through the public ARAP Go API.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/tcarwash/arap/challenge"
	"github.com/tcarwash/arap/protocol"
)

func main() {
	now := time.Now().UTC().Truncate(time.Second)
	session := []byte("demo-only-unique-session-binding")
	tempDir, err := os.MkdirTemp("", "arap-mutual-demo-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempDir)
	store, err := challenge.OpenSQLite(filepath.Join(tempDir, "challenges.sqlite"))
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	requests, err := challenge.NewMutualRequests(store, "K7ABC", "AG7SU", challenge.AuthPurpose, session, now, 2*time.Minute)
	if err != nil {
		log.Fatal(err)
	}
	partyA, err := protocol.GenerateEd25519("K7ABC")
	if err != nil {
		log.Fatal(err)
	}
	partyB, err := protocol.GenerateEd25519("AG7SU")
	if err != nil {
		log.Fatal(err)
	}
	publicA := partyA.PublicKey().(ed25519.PublicKey)
	publicB := partyB.PublicKey().(ed25519.PublicKey)
	verifierA, err := protocol.NewEd25519Verifier(publicA)
	if err != nil {
		log.Fatal(err)
	}
	verifierB, err := protocol.NewEd25519Verifier(publicB)
	if err != nil {
		log.Fatal(err)
	}
	keyIDA, err := protocol.KeyID(publicA)
	if err != nil {
		log.Fatal(err)
	}
	keyIDB, err := protocol.KeyID(publicB)
	if err != nil {
		log.Fatal(err)
	}

	// B answers A's request; A answers B's request. Production applications
	// exchange these request and response bytes over their own transport.
	responseFromB, _, err := challenge.Respond(partyB, requests.FromA, now.Add(time.Second))
	if err != nil {
		log.Fatal(err)
	}
	responseFromA, _, err := challenge.Respond(partyA, requests.FromB, now.Add(time.Second))
	if err != nil {
		log.Fatal(err)
	}
	trustA := func(call, keyID, purpose string) string {
		if call == "K7ABC" && keyID == hex.EncodeToString(keyIDA) && purpose == challenge.ResponsePurpose {
			return "trusted"
		}
		return "untrusted"
	}
	trustB := func(call, keyID, purpose string) string {
		if call == "AG7SU" && keyID == hex.EncodeToString(keyIDB) && purpose == challenge.ResponsePurpose {
			return "trusted"
		}
		return "untrusted"
	}
	result := challenge.VerifyMutualPair(requests, challenge.MutualResponses{FromA: responseFromA, FromB: responseFromB}, challenge.MutualVerificationConfig{
		VerifierA: verifierA, TrustA: trustA,
		VerifierB: verifierB, TrustB: trustB,
		Store: store, Session: session, Now: now.Add(2 * time.Second),
	})
	if !result.Accepted {
		log.Fatalf("mutual authentication rejected: %s", result.Reason)
	}
	fmt.Printf("mutually authenticated parties %s and %s for %s; session=%s\n", result.PartyA, result.PartyB, result.Purpose, result.SessionBinding)
}
