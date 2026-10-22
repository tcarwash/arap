package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/tcarwash/arap/adapters/pixelqso"
	"github.com/tcarwash/arap/challenge"
	"github.com/tcarwash/arap/endorsement"
	"github.com/tcarwash/arap/identity"
	"github.com/tcarwash/arap/internal/buildinfo"
	"github.com/tcarwash/arap/lotwenroll"
	"github.com/tcarwash/arap/protocol"
	"github.com/tcarwash/arap/reference"
	"golang.org/x/term"
)

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		if os.Getenv("ARAP_MACHINE") == "1" {
			name := "operation_error"
			switch code {
			case 1:
				name = "rejected"
			case 3:
				name = "incomplete"
			}
			var resolutionErr *reference.ResolutionError
			if errors.As(err, &resolutionErr) {
				name = string(resolutionErr.Code)
			}
			if code == 0 {
				code = 2
			}
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
				"protocol_version": 1, "ok": false,
				"error": map[string]string{"code": name, "message": err.Error()},
			})
			os.Exit(code)
		}
		fmt.Fprintln(os.Stderr, "arap:", err)
		if code == 0 {
			code = 2
		}
	}
	os.Exit(code)
}

type stringListFlag []string

func (s *stringListFlag) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringListFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func readFileBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds the %d byte limit", path, limit)
	}
	return data, nil
}

func run(args []string) (int, error) {
	if len(args) == 0 {
		usage()
		return 2, errors.New("command required")
	}
	switch args[0] {
	case "version", "--version":
		return versionCommand(args[1:])
	case "keygen":
		return keygen(args[1:])
	case "sign-content":
		return signContent(args[1:])
	case "verify-content":
		return verifyContent(args[1:])
	case "sign-pixelqso":
		return signPixelQSO(args[1:])
	case "verify-pixelqso":
		return verifyPixelQSO(args[1:])
	case "inspect-proof":
		return inspectProof(args[1:])
	case "fingerprint":
		return fingerprint(args[1:])
	case "trust":
		return trustCommand(args[1:])
	case "challenge":
		return challengeCommand(args[1:])
	case "endorsement":
		return endorsementCommand(args[1:])
	case "enrollment":
		return enrollmentCommand(args[1:])
	case "resolve":
		return resolveProof(args[1:])
	case "publish":
		return publishProof(args[1:])
	case "publish-key":
		return publishKey(args[1:])
	case "fetch-key":
		return fetchKey(args[1:])
	case "verify-ref":
		return verifyReference(args[1:])
	case "help", "-h", "--help":
		usage()
		return 0, nil
	default:
		usage()
		return 2, fmt.Errorf("unknown command %q", args[0])
	}
}

func versionCommand(args []string) (int, error) {
	if len(args) > 1 || (len(args) == 1 && args[0] != "--json") {
		return 2, errors.New("version accepts only optional --json")
	}
	info := buildinfo.For("arap")
	if len(args) == 1 {
		return 0, json.NewEncoder(os.Stdout).Encode(info)
	}
	fmt.Printf("ARAP %s (commit %s)\n", info.Version, info.Commit)
	return 0, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "ARAP proof and identity tools")
	fmt.Fprintln(os.Stderr, "  arap version [--json]")
	fmt.Fprintln(os.Stderr, "  arap keygen --private-key FILE --public-key FILE [--passphrase-stdin]")
	fmt.Fprintln(os.Stderr, "  arap sign-content --key FILE --callsign CALL --input FILE --media-type TYPE --context ID --out FILE [--passphrase-stdin]")
	fmt.Fprintln(os.Stderr, "  arap verify-content --proof FILE --input FILE --public-key FILE [--trust-store FILE|--enrollment-store DB] --expect-media-type TYPE --expect-context ID")
	fmt.Fprintln(os.Stderr, "  arap sign-pixelqso --key FILE --card FILE [--first-card FILE] --out FILE [--passphrase-stdin]")
	fmt.Fprintln(os.Stderr, "  arap verify-pixelqso --card FILE [--first-card FILE] --proof FILE --public-key FILE --trust-store FILE")
	fmt.Fprintln(os.Stderr, "  arap inspect-proof --proof FILE (claims are untrusted until verified)")
	fmt.Fprintln(os.Stderr, "  arap fingerprint --public-key FILE")
	fmt.Fprintln(os.Stderr, "  arap trust add|list|disable ...")
	fmt.Fprintln(os.Stderr, "  arap challenge issue|cancel|respond|verify-response ...")
	fmt.Fprintln(os.Stderr, "  arap challenge mutual-issue --party-a CALL --party-b CALL --session-binding-hex HEX --store DB --out-from-a FILE --out-from-b FILE")
	fmt.Fprintln(os.Stderr, "  arap challenge mutual-verify --request-from-a FILE --response-from-b FILE --request-from-b FILE --response-from-a FILE ...")
	fmt.Fprintln(os.Stderr, "  arap endorsement issue|pack|append|verify ...")
	fmt.Fprintln(os.Stderr, "  arap enrollment issue --audience ID --callsign CALL --public-key FILE --store FILE --out FILE [--purpose PURPOSE ...]")
	fmt.Fprintln(os.Stderr, "  arap enrollment respond --request FILE --private-key FILE --out FILE [--tqsl-helper FILE] [--tqsl-serial DECIMAL] [--tqsl-directory DIR]")
	fmt.Fprintln(os.Stderr, "  arap enrollment verify-response --response FILE --audience ID --store FILE [--roots PEM | --tqsl-directory DIR] [--allow-purpose PURPOSE ...]")
	fmt.Fprintln(os.Stderr, "  arap enrollment refresh --response FILE --callsign CALL --key-id SHA256 --store FILE [--roots PEM | --tqsl-directory DIR]")
	fmt.Fprintln(os.Stderr, "  arap enrollment list|disable --store FILE ...")
	fmt.Fprintln(os.Stderr, "  arap resolve --server URL [--server URL ...] --reference AR1... --out FILE")
	fmt.Fprintln(os.Stderr, "  arap publish --server URL --proof FILE (upload token from ARAP_UPLOAD_TOKEN)")
	fmt.Fprintln(os.Stderr, "  arap publish-key --server URL --public-key FILE (upload token from ARAP_UPLOAD_TOKEN)")
	fmt.Fprintln(os.Stderr, "  arap fetch-key --server URL [--server URL ...] --fingerprint SHA256 --out FILE")
	fmt.Fprintln(os.Stderr, "  arap verify-ref --server URL [--server URL ...] --reference AR1... --input FILE --public-key FILE --trust-store FILE --expect-media-type TYPE --expect-context ID")
}

func enrollmentCommand(args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("enrollment requires issue, respond, certificates, verify-response, refresh, list or disable")
	}
	if args[0] == "certificates" {
		return listEnrollmentCertificates(args[1:])
	}
	fs := flag.NewFlagSet("enrollment "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	storePath := fs.String("store", "", "LoTW enrollment SQLite database")
	callsign := fs.String("callsign", "", "callsign for disable")
	keyID := fs.String("key-id", "", "SHA-256 key fingerprint for disable")
	audience := fs.String("audience", "", "verifier identifier for an enrollment challenge")
	publicPath := fs.String("public-key", "", "Ed25519 public key to bind")
	out := fs.String("out", "", "exclusive challenge output file")
	expiresIn := fs.Int("expires-in", 120, "challenge lifetime in seconds, maximum 300")
	responsePath := fs.String("response", "", "signed LoTW enrollment response")
	rootsPath := fs.String("roots", "", "PEM bundle of trusted ARRL certificate roots")
	maxStatusAge := fs.Duration("max-status-age", 24*time.Hour, "maximum age of LoTW certificate status evidence")
	var enrollmentPurposes stringListFlag
	fs.Var(&enrollmentPurposes, "purpose", "key purpose requested by this verifier; repeatable; omitted means v1 challenge-response-only")
	var allowedEnrollmentPurposes stringListFlag
	fs.Var(&allowedEnrollmentPurposes, "allow-purpose", "enrollment purpose accepted by this verifier; repeatable; default challenge-response")
	// Retained as a no-op for compatibility with existing scripts. TQSL's
	// supported RSA/SHA-1 is the enrollment signature profile; ARAP's own
	// content and challenge signatures remain Ed25519.
	_ = fs.Bool("allow-legacy-rsa-sha1", false, "deprecated compatibility flag; TQSL RSA-SHA1 is accepted for enrollment only")
	requestPath := fs.String("request", "", "enrollment challenge CBOR")
	privatePath := fs.String("private-key", "", "ARAP Ed25519 private key")
	helperPath := fs.String("tqsl-helper", "", "native TQSL signing helper (or ARAP_TQSL_HELPER)")
	serial := fs.String("tqsl-serial", "", "decimal TQSL certificate serial when multiple callsign certificates exist")
	tqslDirectory := fs.String("tqsl-directory", "", "TQSL data directory for helper access and certificate-root discovery")
	passphraseStdin := fs.Bool("passphrase-stdin", false, "read two lines from stdin: ARAP key passphrase, then TQSL certificate password")
	if err := fs.Parse(args[1:]); err != nil {
		return 2, err
	}
	if args[0] != "respond" && *storePath == "" {
		return 2, errors.New("--store is required")
	}
	var store *lotwenroll.SQLiteStore
	if args[0] != "respond" {
		var err error
		store, err = lotwenroll.OpenSQLite(*storePath)
		if err != nil {
			return 2, err
		}
		defer store.Close()
	}
	switch args[0] {
	case "respond":
		if *requestPath == "" || *privatePath == "" || *out == "" {
			return 2, errors.New("enrollment respond requires --request, --private-key and --out")
		}
		request, err := readFileBounded(*requestPath, 4096)
		if err != nil {
			return 2, err
		}
		challenge, err := lotwenroll.Decode(request)
		if err != nil {
			return 2, err
		}
		var key ed25519.PrivateKey
		var tqslPassword []byte
		if *passphraseStdin {
			lines, err := readPassphraseLines(2)
			if err != nil {
				return 2, err
			}
			key, err = identity.LoadPrivateWithPassphrase(*privatePath, lines[0])
			if err != nil {
				wipe(lines[0])
				wipe(lines[1])
				return 2, err
			}
			tqslPassword = lines[1]
			wipe(lines[0])
		} else {
			key, err = loadPrivateKey(*privatePath, false)
			if err != nil {
				return 2, err
			}
			tqslPassword, err = promptPassphrase("TQSL certificate password (blank if none): ")
			if err != nil {
				wipe(key)
				return 2, err
			}
		}
		defer wipe(key)
		defer wipe(tqslPassword)
		keyID, err := protocol.KeyID(key.Public().(ed25519.PublicKey))
		if err != nil || !bytes.Equal(keyID, challenge.KeyID[:]) {
			return 2, errors.New("ARAP private key does not match the challenge")
		}
		program, err := resolveTQSLHelper(*helperPath)
		if err != nil {
			return 2, err
		}
		signer := &lotwenroll.TQSLHelperSigner{Path: program, Callsign: challenge.Callsign, Serial: *serial, Directory: *tqslDirectory, Passphrase: tqslPassword}
		response, err := lotwenroll.Respond(request, key, signer, nil)
		if err != nil {
			return 2, err
		}
		encoded, err := lotwenroll.EncodeResponse(response)
		if err != nil {
			return 2, err
		}
		if err := identity.WriteExclusive(*out, encoded, 0600); err != nil {
			return 2, err
		}
		return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{"callsign": challenge.Callsign, "audience": challenge.Audience, "response_file": *out, "tqsl_signature_algorithm": "RSA-SHA1"})
	case "verify-response":
		if *responsePath == "" || *audience == "" {
			return 2, errors.New("enrollment verify-response requires --response and --audience")
		}
		if *maxStatusAge <= 0 {
			return 2, errors.New("--max-status-age must be positive")
		}
		encoded, err := readFileBounded(*responsePath, lotwenroll.MaxResponse)
		if err != nil {
			return 2, err
		}
		roots, _, err := loadEnrollmentRoots(*rootsPath, *tqslDirectory)
		if err != nil {
			return 2, err
		}
		statusClient := lotwenroll.ARRLCertificateStatusClient{}
		var statusErr error
		verification := lotwenroll.VerifyEncoded(encoded, lotwenroll.VerifyConfig{
			Audience: *audience, Roots: roots, Now: time.Now().UTC(), Store: store,
			MaxStatusAge:    *maxStatusAge,
			AllowedPurposes: []string(allowedEnrollmentPurposes),
			CertificateStatus: func(cert *x509.Certificate) lotwenroll.StatusEvidence {
				evidence, err := statusClient.Check(context.Background(), cert)
				statusErr = err
				return evidence
			},
		})
		if statusErr != nil && !verification.Accepted {
			verification.Reason = fmt.Sprintf("%s: %v", verification.Reason, statusErr)
		}
		if err := json.NewEncoder(os.Stdout).Encode(verification); err != nil {
			return 2, err
		}
		if verification.Accepted {
			return 0, nil
		}
		return 1, nil
	case "refresh":
		if *responsePath == "" || *callsign == "" || *keyID == "" {
			return 2, errors.New("enrollment refresh requires --response, --callsign and --key-id")
		}
		if *maxStatusAge <= 0 {
			return 2, errors.New("--max-status-age must be positive")
		}
		encoded, err := readFileBounded(*responsePath, lotwenroll.MaxResponse)
		if err != nil {
			return 2, err
		}
		response, err := lotwenroll.DecodeResponse(encoded)
		if err != nil {
			return 2, err
		}
		roots, _, err := loadEnrollmentRoots(*rootsPath, *tqslDirectory)
		if err != nil {
			return 2, err
		}
		now := time.Now().UTC()
		statusClient := lotwenroll.ARRLCertificateStatusClient{}
		var statusErr error
		result := lotwenroll.RefreshStatus(lotwenroll.RefreshConfig{
			Callsign: *callsign, KeyID: *keyID, CertificateChain: response.Chain,
			Roots: roots, Now: now, MaxStatusAge: *maxStatusAge, Store: store,
			CertificateStatus: func(cert *x509.Certificate) lotwenroll.StatusEvidence {
				evidence, checkErr := statusClient.Check(context.Background(), cert)
				statusErr = checkErr
				return evidence
			},
		})
		if statusErr != nil && !result.Accepted {
			result.Reason = fmt.Sprintf("%s: %v", result.Reason, statusErr)
		}
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return 2, err
		}
		if result.Accepted {
			return 0, nil
		}
		return 1, nil
	case "issue":
		if *audience == "" || *callsign == "" || *publicPath == "" || *out == "" {
			return 2, errors.New("enrollment issue requires --audience, --callsign, --public-key and --out")
		}
		if *expiresIn < 1 || time.Duration(*expiresIn)*time.Second > lotwenroll.MaxLifetime {
			return 2, fmt.Errorf("--expires-in must be between 1 and %d seconds", int(lotwenroll.MaxLifetime/time.Second))
		}
		public, err := identity.LoadPublic(*publicPath)
		if err != nil {
			return 2, err
		}
		now := time.Now().UTC()
		var challenge lotwenroll.Challenge
		var encoded []byte
		if len(enrollmentPurposes) == 0 {
			challenge, encoded, err = lotwenroll.New(*audience, *callsign, public, now, time.Duration(*expiresIn)*time.Second)
		} else {
			challenge, encoded, err = lotwenroll.NewWithPurposes(*audience, *callsign, public, enrollmentPurposes, now, time.Duration(*expiresIn)*time.Second)
		}
		if err != nil {
			return 2, err
		}
		hash := sha256.Sum256(encoded)
		keyID := hex.EncodeToString(challenge.KeyID[:])
		if err := store.Issue(hash[:], challenge.Audience, challenge.Callsign, keyID, challenge.ExpiresAt); err != nil {
			return 2, err
		}
		if err := identity.WriteExclusive(*out, encoded, 0600); err != nil {
			if cancelErr := store.CancelPending(hash[:]); cancelErr != nil {
				return 2, fmt.Errorf("publish enrollment challenge: %v; cancel pending record: %w", err, cancelErr)
			}
			return 2, err
		}
		return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{
			"request_sha256": hex.EncodeToString(hash[:]), "audience": challenge.Audience,
			"callsign": challenge.Callsign, "key_id_sha256": keyID,
			"version": challenge.Version, "purposes": challenge.Purposes,
			"issued_at": challenge.IssuedAt, "expires_at": challenge.ExpiresAt, "request_file": *out,
		})
	case "list":
		bindings, err := store.Bindings()
		if err != nil {
			return 2, err
		}
		return 0, json.NewEncoder(os.Stdout).Encode(bindings)
	case "disable":
		if *callsign == "" || *keyID == "" {
			return 2, errors.New("enrollment disable requires --callsign and --key-id")
		}
		call, err := protocol.NormalizeCallsign(*callsign)
		if err != nil {
			return 2, err
		}
		if err := store.Disable(call, *keyID); err != nil {
			return 2, err
		}
		return 0, nil
	default:
		return 2, fmt.Errorf("unknown enrollment action %q", args[0])
	}
}

// listEnrollmentCertificates returns public serial metadata for current TQSL
// certificates matching the callsign bound into an enrollment challenge.
func listEnrollmentCertificates(args []string) (int, error) {
	fs := flag.NewFlagSet("enrollment certificates", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	requestPath := fs.String("request", "", "enrollment challenge CBOR (callsign is read from the challenge)")
	helperPath := fs.String("tqsl-helper", "", "native TQSL helper (or ARAP_TQSL_HELPER)")
	directory := fs.String("tqsl-directory", "", "TQSL configuration directory")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *requestPath == "" {
		return 2, errors.New("enrollment certificates requires --request")
	}
	request, err := readFileBounded(*requestPath, 4096)
	if err != nil {
		return 2, err
	}
	challenge, err := lotwenroll.Decode(request)
	if err != nil {
		return 2, err
	}
	program, err := resolveTQSLHelper(*helperPath)
	if err != nil {
		return 2, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	argv := []string{"--list-certificates", "--callsign", challenge.Callsign, "--resource-directory", filepath.Dir(program)}
	if *directory != "" {
		argv = append(argv, "--directory", *directory)
	}
	cmd := exec.CommandContext(ctx, program, argv...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if ctx.Err() != nil {
		return 2, errors.New("TQSL certificate listing timed out")
	}
	if err != nil {
		return 2, fmt.Errorf("TQSL certificate listing failed: %w", err)
	}
	var result struct {
		Certificates []struct {
			Callsign string `json:"callsign"`
			Serial   string `json:"serial"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(stdout, &result); err != nil {
		return 2, errors.New("TQSL helper returned invalid certificate list")
	}
	if len(result.Certificates) > 100 {
		return 2, errors.New("TQSL helper returned too many certificates")
	}
	for _, certificate := range result.Certificates {
		if certificate.Callsign != challenge.Callsign || certificate.Serial == "" {
			return 2, errors.New("TQSL helper returned a mismatched certificate")
		}
		for _, digit := range certificate.Serial {
			if digit < '0' || digit > '9' {
				return 2, errors.New("TQSL helper returned an invalid certificate serial")
			}
		}
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{"callsign": challenge.Callsign, "certificates": result.Certificates})
}

func resolveTQSLHelper(explicit string) (string, error) {
	program := explicit
	if program == "" {
		program = os.Getenv("ARAP_TQSL_HELPER")
	}
	if program == "" {
		program = "arap-tqsl-sign"
	}
	resolved, err := exec.LookPath(program)
	if err != nil {
		return "", fmt.Errorf("TQSL native helper not found or not executable at %q; set --tqsl-helper or ARAP_TQSL_HELPER: %w", program, err)
	}
	return resolved, nil
}

func readPassphraseLines(count int) ([][]byte, error) {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil {
		return nil, err
	}
	defer wipe(data)
	if len(data) > 4096 {
		return nil, errors.New("passphrase input is too large")
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) != count {
		return nil, fmt.Errorf("expected %d passphrase line(s) on standard input", count)
	}
	result := make([][]byte, len(lines))
	for i := range lines {
		result[i] = append([]byte(nil), bytes.TrimSuffix(lines[i], []byte("\r"))...)
	}
	return result, nil
}

func promptPassphrase(label string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("encrypted key needs a passphrase; supply it through --passphrase-stdin")
	}
	fmt.Fprint(os.Stderr, label)
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return passphrase, err
}

func loadPrivateKey(path string, passphraseStdin bool) (ed25519.PrivateKey, error) {
	if passphraseStdin {
		lines, err := readPassphraseLines(1)
		if err != nil {
			return nil, err
		}
		defer wipe(lines[0])
		return identity.LoadPrivateWithPassphrase(path, lines[0])
	}
	private, err := identity.LoadPrivate(path)
	if !errors.Is(err, identity.ErrPassphraseRequired) {
		return private, err
	}
	passphrase, err := promptPassphrase("Private key passphrase: ")
	if err != nil {
		return nil, err
	}
	defer wipe(passphrase)
	return identity.LoadPrivateWithPassphrase(path, passphrase)
}

func createKeyPassphrase(passphraseStdin bool) ([]byte, error) {
	if passphraseStdin {
		lines, err := readPassphraseLines(2)
		if err != nil {
			return nil, err
		}
		defer wipe(lines[1])
		if !bytes.Equal(lines[0], lines[1]) {
			wipe(lines[0])
			return nil, errors.New("passphrases do not match")
		}
		return lines[0], nil
	}
	first, err := promptPassphrase("Create private key passphrase: ")
	if err != nil {
		return nil, err
	}
	second, err := promptPassphrase("Confirm private key passphrase: ")
	if err != nil {
		wipe(first)
		return nil, err
	}
	defer wipe(second)
	if !bytes.Equal(first, second) {
		wipe(first)
		return nil, errors.New("passphrases do not match")
	}
	return first, nil
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func inspectProof(args []string) (int, error) {
	fs := flag.NewFlagSet("inspect-proof", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	path := fs.String("proof", "", "COSE proof file")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *path == "" {
		return 2, errors.New("--proof is required")
	}
	proof, err := readFileBounded(*path, protocol.MaxProofSize)
	if err != nil {
		return 2, err
	}
	headers, payload, err := protocol.InspectProof(proof)
	if err != nil {
		return 1, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{"authenticated": false, "note": "inspection parses untrusted claims; use a purpose-specific verifier", "protected_headers": headers, "payload": payload})
}

func verifyReference(args []string) (int, error) {
	fs := flag.NewFlagSet("verify-ref", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var servers stringListFlag
	fs.Var(&servers, "server", "configured keyserver URL (repeat for additional resolvers)")
	ref := fs.String("reference", "", "AR1 token or full proof hash")
	input := fs.String("input", "", "content file")
	pub := fs.String("public-key", "", "Ed25519 SPKI public key")
	trust := fs.String("trust-store", "", "local trust file")
	media := fs.String("expect-media-type", "", "expected media type")
	ctx := fs.String("expect-context", "", "expected application context")
	canon := fs.String("expect-canonicalization", "identity-v1", "expected canonicalization")
	call := fs.String("expect-callsign", "", "optional expected signer")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if len(servers) == 0 || *ref == "" || *input == "" || *pub == "" || *trust == "" || *media == "" || *ctx == "" {
		return 2, errors.New("--server, --reference, --input, --public-key, --trust-store, --expect-media-type and --expect-context are required")
	}
	client, err := reference.NewMulti(servers)
	if err != nil {
		return 2, err
	}
	resolved, err := client.Resolve(context.Background(), *ref)
	if err != nil {
		return 2, err
	}
	tmp, err := os.CreateTemp("", "arap-proof-*.cose")
	if err != nil {
		return 2, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return 2, err
	}
	if _, err := tmp.Write(resolved.Proof); err != nil {
		tmp.Close()
		return 2, err
	}
	if err := tmp.Close(); err != nil {
		return 2, err
	}
	verifyArgs := []string{"--proof", tmp.Name(), "--input", *input, "--public-key", *pub, "--trust-store", *trust, "--expect-media-type", *media, "--expect-context", *ctx, "--expect-canonicalization", *canon}
	if *call != "" {
		verifyArgs = append(verifyArgs, "--expect-callsign", *call)
	}
	return verifyContent(verifyArgs)
}

func resolveProof(args []string) (int, error) {
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var servers stringListFlag
	fs.Var(&servers, "server", "configured keyserver URL (repeat for additional resolvers)")
	ref := fs.String("reference", "", "AR1 token or full proof hash")
	out := fs.String("out", "", "proof output file")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if len(servers) == 0 || *ref == "" || *out == "" {
		return 2, errors.New("--server, --reference and --out are required")
	}
	client, err := reference.NewMulti(servers)
	if err != nil {
		return 2, err
	}
	resolved, err := client.Resolve(context.Background(), *ref)
	if err != nil {
		return 2, err
	}
	if err := identity.WriteExclusive(*out, resolved.Proof, 0600); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]string{"proof_file": *out, "proof_sha256": resolved.Hash, "reference": resolved.Token})
}

func publishProof(args []string) (int, error) {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", "", "configured keyserver URL")
	path := fs.String("proof", "", "COSE proof file")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *server == "" || *path == "" {
		return 2, errors.New("--server and --proof are required")
	}
	proof, err := readFileBounded(*path, protocol.MaxProofSize)
	if err != nil {
		return 2, err
	}
	client, err := reference.New(*server)
	if err != nil {
		return 2, err
	}
	published, err := client.PublishProof(context.Background(), proof, os.Getenv("ARAP_UPLOAD_TOKEN"))
	if err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]string{"proof_sha256": published.Hash, "reference": published.Token})
}

func publishKey(args []string) (int, error) {
	fs := flag.NewFlagSet("publish-key", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", "", "configured keyserver URL")
	path := fs.String("public-key", "", "SPKI public key or certificate PEM")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *server == "" || *path == "" {
		return 2, errors.New("--server and --public-key are required")
	}
	data, err := readFileBounded(*path, 1024*1024)
	if err != nil {
		return 2, err
	}
	pub, err := identity.ParsePublicKey(data)
	if err != nil {
		return 2, err
	}
	id, err := protocol.KeyID(pub)
	if err != nil {
		return 2, err
	}
	client, err := reference.New(*server)
	if err != nil {
		return 2, err
	}
	if err := client.PublishKey(context.Background(), hex.EncodeToString(id), data, os.Getenv("ARAP_UPLOAD_TOKEN")); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]string{"key_id_sha256": hex.EncodeToString(id)})
}

func fetchKey(args []string) (int, error) {
	fs := flag.NewFlagSet("fetch-key", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var servers stringListFlag
	fs.Var(&servers, "server", "configured keyserver URL (repeat for additional resolvers)")
	fingerprint := fs.String("fingerprint", "", "SPKI SHA-256 fingerprint")
	out := fs.String("out", "", "public-key output file")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if len(servers) == 0 || *fingerprint == "" || *out == "" {
		return 2, errors.New("--server, --fingerprint and --out are required")
	}
	client, err := reference.NewMulti(servers)
	if err != nil {
		return 2, err
	}
	data, err := client.FetchKey(context.Background(), *fingerprint)
	if err != nil {
		return 2, err
	}
	if err := identity.WriteExclusive(*out, data, 0644); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]string{"public_key_file": *out, "key_id_sha256": *fingerprint})
}

func challengeCommand(args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("challenge requires issue, cancel, respond, verify-response, mutual-issue or mutual-verify")
	}
	switch args[0] {
	case "issue":
		return issueChallenge(args[1:])
	case "cancel":
		return cancelChallenge(args[1:])
	case "respond":
		return respondChallenge(args[1:])
	case "verify-response":
		return verifyChallenge(args[1:])
	case "mutual-issue":
		return issueMutualChallenges(args[1:])
	case "mutual-verify":
		return verifyMutualChallenges(args[1:])
	default:
		return 2, fmt.Errorf("unknown challenge command %q", args[0])
	}
}

func cancelChallenge(args []string) (int, error) {
	fs := flag.NewFlagSet("challenge cancel", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	requestPath := fs.String("request", "", "canonical challenge request to cancel")
	dbPath := fs.String("store", "", "challenge database that issued the request")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *requestPath == "" || *dbPath == "" {
		return 2, errors.New("--request and --store are required")
	}
	encoded, err := readFileBounded(*requestPath, 4096)
	if err != nil {
		return 2, err
	}
	store, err := challenge.OpenSQLite(*dbPath)
	if err != nil {
		return 2, err
	}
	defer store.Close()
	if err := challenge.CancelRequest(store, encoded); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{"cancellation_requested": true})
}

func endorsementCommand(args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("endorsement requires issue, pack, append or verify")
	}
	switch args[0] {
	case "issue":
		return issueEndorsement(args[1:])
	case "pack":
		return packEndorsementChain(args[1:])
	case "append":
		return appendEndorsementChain(args[1:])
	case "verify":
		return verifyEndorsementChain(args[1:])
	default:
		return 2, fmt.Errorf("unknown endorsement command %q", args[0])
	}
}

func issueEndorsement(args []string) (int, error) {
	fs := flag.NewFlagSet("endorsement issue", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	keyPath := fs.String("key", "", "encrypted or legacy PKCS#8 Ed25519 private key")
	call := fs.String("callsign", "", "issuer callsign")
	subject := fs.String("subject", "", "endorsed callsign")
	subjectKeyPath := fs.String("subject-public-key", "", "endorsed Ed25519 public key")
	var purposes stringListFlag
	fs.Var(&purposes, "purpose", "delegated purpose (repeatable)")
	depth := fs.Int("max-delegation-depth", 0, "maximum additional endorsements this key may issue")
	expiresIn := fs.Int("expires-in", 30*24*60*60, "endorsement lifetime in seconds, maximum one year")
	out := fs.String("out", "", "signed endorsement proof output")
	passStdin := fs.Bool("passphrase-stdin", false, "read private-key passphrase from standard input")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *keyPath == "" || *call == "" || *subject == "" || *subjectKeyPath == "" || len(purposes) == 0 || *out == "" {
		return 2, errors.New("--key, --callsign, --subject, --subject-public-key, at least one --purpose and --out are required")
	}
	if *expiresIn < 1 || *expiresIn > int(endorsement.MaxLifetime/time.Second) {
		return 2, fmt.Errorf("--expires-in must be between 1 and %d seconds", int(endorsement.MaxLifetime/time.Second))
	}
	if *depth < 0 || *depth > endorsement.MaxChainDepth {
		return 2, fmt.Errorf("--max-delegation-depth must be between 0 and %d", endorsement.MaxChainDepth)
	}
	private, err := loadPrivateKey(*keyPath, *passStdin)
	if err != nil {
		return 2, err
	}
	signer, err := protocol.NewEd25519Signer(*call, private)
	if err != nil {
		return 2, err
	}
	subjectKey, err := identity.LoadPublic(*subjectKeyPath)
	if err != nil {
		return 2, err
	}
	now := time.Now().UTC()
	proof, claim, err := endorsement.Issue(signer, *subject, subjectKey, purposes, uint8(*depth), now, now.Add(time.Duration(*expiresIn)*time.Second))
	if err != nil {
		return 2, err
	}
	if err := identity.WriteExclusive(*out, proof, 0600); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{
		"proof_file": *out, "issuer": claim.Issuer, "subject": claim.Subject,
		"purposes": claim.Purposes, "issued_at": claim.Created, "expires_at": claim.NotAfter,
		"max_delegation_depth": claim.MaxDelegationDepth,
	})
}

func packEndorsementChain(args []string) (int, error) {
	fs := flag.NewFlagSet("endorsement pack", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var links stringListFlag
	fs.Var(&links, "link", "proof link in root-to-subject order (repeatable)")
	out := fs.String("out", "", "encoded endorsement chain output")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if len(links) == 0 || *out == "" {
		return 2, errors.New("at least one --link and --out are required")
	}
	proofs := make([][]byte, 0, len(links))
	for _, path := range links {
		proof, err := readFileBounded(path, protocol.MaxProofSize)
		if err != nil {
			return 2, err
		}
		proofs = append(proofs, proof)
	}
	encoded, err := endorsement.EncodeChain(proofs)
	if err != nil {
		return 2, err
	}
	if err := identity.WriteExclusive(*out, encoded, 0600); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{"chain_file": *out, "links": len(proofs)})
}

func appendEndorsementChain(args []string) (int, error) {
	fs := flag.NewFlagSet("endorsement append", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	chainPath := fs.String("chain", "", "existing encoded endorsement chain")
	linkPath := fs.String("link", "", "new signed link to append")
	out := fs.String("out", "", "encoded endorsement chain output")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *chainPath == "" || *linkPath == "" || *out == "" {
		return 2, errors.New("--chain, --link and --out are required")
	}
	encoded, err := readFileBounded(*chainPath, endorsement.MaxChainBytes)
	if err != nil {
		return 2, err
	}
	chain, err := endorsement.DecodeChain(encoded)
	if err != nil {
		return 2, err
	}
	link, err := readFileBounded(*linkPath, protocol.MaxProofSize)
	if err != nil {
		return 2, err
	}
	chain = append(chain, link)
	encoded, err = endorsement.EncodeChain(chain)
	if err != nil {
		return 2, err
	}
	if err := identity.WriteExclusive(*out, encoded, 0600); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{"chain_file": *out, "links": len(chain)})
}

func verifyEndorsementChain(args []string) (int, error) {
	fs := flag.NewFlagSet("endorsement verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	chainPath := fs.String("chain", "", "encoded endorsement chain")
	rootCall := fs.String("root-callsign", "", "explicitly trusted root callsign")
	rootKeyPath := fs.String("root-public-key", "", "explicitly trusted root Ed25519 key")
	var rootPurposes stringListFlag
	fs.Var(&rootPurposes, "root-purpose", "purpose the root is allowed to delegate (repeatable)")
	rootDepth := fs.Int("root-max-delegation-depth", 0, "maximum chain depth delegated below the root")
	subjectCall := fs.String("subject", "", "expected final subject callsign")
	subjectKeyPath := fs.String("subject-public-key", "", "expected final subject Ed25519 key")
	purpose := fs.String("purpose", "", "purpose to authorize")
	disabledPath := fs.String("disabled-trust-store", "", "optional trust store containing locally disabled keys")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *chainPath == "" || *rootCall == "" || *rootKeyPath == "" || len(rootPurposes) == 0 || *subjectCall == "" || *subjectKeyPath == "" || *purpose == "" {
		return 2, errors.New("--chain, root identity/key/purpose, subject identity/key and --purpose are required")
	}
	if *rootDepth < 0 || *rootDepth > endorsement.MaxChainDepth {
		return 2, errors.New("--root-max-delegation-depth must be between 0 and 8")
	}
	encoded, err := readFileBounded(*chainPath, endorsement.MaxChainBytes)
	if err != nil {
		return 2, err
	}
	rootKey, err := identity.LoadPublic(*rootKeyPath)
	if err != nil {
		return 2, err
	}
	subjectKey, err := identity.LoadPublic(*subjectKeyPath)
	if err != nil {
		return 2, err
	}
	var disabled identity.TrustStore
	if *disabledPath != "" {
		disabled, err = identity.LoadTrust(*disabledPath)
		if err != nil {
			return 2, err
		}
	}
	rootID, err := protocol.KeyID(rootKey)
	if err != nil {
		return 2, err
	}
	rootDisabled := disabled.Status(*rootCall, hex.EncodeToString(rootID), endorsement.Purpose) == "disabled"
	disabledDecision := func(call, keyID string) bool {
		return disabled.Status(call, keyID, endorsement.Purpose) == "disabled"
	}
	result := endorsement.VerifyEncoded(encoded, endorsement.VerifyConfig{
		Anchors: []endorsement.Anchor{{Callsign: *rootCall, PublicKey: rootKey, Purposes: rootPurposes, MaxDelegationDepth: uint8(*rootDepth), Disabled: rootDisabled}},
		Subject: *subjectCall, SubjectKey: subjectKey, Purpose: *purpose, Now: time.Now().UTC(), Disabled: disabledDecision,
	})
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 2, err
	}
	if result.Accepted {
		return 0, nil
	}
	return 1, nil
}

func issueMutualChallenges(args []string) (int, error) {
	fs := flag.NewFlagSet("challenge mutual-issue", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	partyA := fs.String("party-a", "", "first authenticated station callsign")
	partyB := fs.String("party-b", "", "second authenticated station callsign")
	purpose := fs.String("purpose", challenge.AuthPurpose, "shared requested authentication purpose")
	session := fs.String("session-binding-hex", "", "unique application session binding, hexadecimal")
	lifetime := fs.Int("expires-in", int(challenge.DefaultLifetime/time.Second), "lifetime in seconds, max 600")
	dbPath := fs.String("store", "", "durable challenge-pair database")
	outA := fs.String("out-from-a", "", "request from party A for party B")
	outB := fs.String("out-from-b", "", "request from party B for party A")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *partyA == "" || *partyB == "" || *session == "" || *dbPath == "" || *outA == "" || *outB == "" {
		return 2, errors.New("--party-a, --party-b, --session-binding-hex, --store, --out-from-a and --out-from-b are required")
	}
	if filepath.Clean(*outA) == filepath.Clean(*outB) {
		return 2, errors.New("mutual request output paths must differ")
	}
	sessionBytes, err := hex.DecodeString(*session)
	if err != nil || len(sessionBytes) == 0 {
		return 2, errors.New("--session-binding-hex must encode a non-empty value")
	}
	for _, path := range []string{*outA, *outB} {
		if _, err := os.Lstat(path); err == nil {
			return 2, fmt.Errorf("request output already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return 2, err
		}
	}
	store, err := challenge.OpenSQLite(*dbPath)
	if err != nil {
		return 2, err
	}
	defer store.Close()
	requests, err := challenge.NewMutualRequests(store, *partyA, *partyB, *purpose, sessionBytes, time.Now().UTC(), time.Duration(*lifetime)*time.Second)
	if err != nil {
		return 2, err
	}
	cancel := func() error {
		hashA := challenge.RequestHash(requests.FromA)
		hashB := challenge.RequestHash(requests.FromB)
		errA := store.CancelPending(hashA[:])
		errB := store.CancelPending(hashB[:])
		return errors.Join(errA, errB)
	}
	if err := identity.WriteExclusive(*outA, requests.FromA, 0600); err != nil {
		if cancelErr := cancel(); cancelErr != nil {
			return 2, fmt.Errorf("publish party A request: %v; cancel pending pair: %w", err, cancelErr)
		}
		return 2, err
	}
	if err := identity.WriteExclusive(*outB, requests.FromB, 0600); err != nil {
		if cancelErr := cancel(); cancelErr != nil {
			return 2, fmt.Errorf("publish party B request: %v; cancel pending pair: %w", err, cancelErr)
		}
		return 2, fmt.Errorf("publish party B request: %w; party A file may remain but the pair was canceled", err)
	}
	requestA, _ := challenge.DecodeRequest(requests.FromA)
	hashA := challenge.RequestHash(requests.FromA)
	hashB := challenge.RequestHash(requests.FromB)
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{
		"party_a": requestA.Requester, "party_b": requestA.Responder, "purpose": requestA.Purpose,
		"issued_at": requestA.IssuedAt, "expires_at": requestA.ExpiresAt,
		"session_binding_sha256": fmt.Sprintf("%x", sha256.Sum256(sessionBytes)),
		"request_from_a_file":    *outA, "request_from_b_file": *outB,
		"request_from_a_sha256": hex.EncodeToString(hashA[:]),
		"request_from_b_sha256": hex.EncodeToString(hashB[:]),
	})
}

func verifyMutualChallenges(args []string) (int, error) {
	fs := flag.NewFlagSet("challenge mutual-verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	requestAPath := fs.String("request-from-a", "", "challenge issued by party A for party B")
	responseBPath := fs.String("response-from-b", "", "party B response to party A challenge")
	requestBPath := fs.String("request-from-b", "", "challenge issued by party B for party A")
	responseAPath := fs.String("response-from-a", "", "party A response to party B challenge")
	partyA := fs.String("party-a", "", "expected first party callsign")
	partyB := fs.String("party-b", "", "expected second party callsign")
	publicAPath := fs.String("party-a-public-key", "", "party A Ed25519 public key")
	publicBPath := fs.String("party-b-public-key", "", "party B Ed25519 public key")
	trustAPath := fs.String("party-a-trust-store", "", "party A local trust store")
	trustBPath := fs.String("party-b-trust-store", "", "party B local trust store")
	enrollmentAPath := fs.String("party-a-enrollment-store", "", "optional party A enrollment database")
	enrollmentBPath := fs.String("party-b-enrollment-store", "", "optional party B enrollment database")
	enrollmentMaxAge := fs.Duration("max-enrollment-status-age", 24*time.Hour, "maximum age of enrollment status evidence")
	session := fs.String("session-binding-hex", "", "expected application session binding, hexadecimal")
	dbPath := fs.String("store", "", "database used to issue both challenges")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *requestAPath == "" || *responseBPath == "" || *requestBPath == "" || *responseAPath == "" || *partyA == "" || *partyB == "" || *publicAPath == "" || *publicBPath == "" || *session == "" || *dbPath == "" {
		return 2, errors.New("both request/response pairs, --party-a/--party-b, both public keys, --session-binding-hex and --store are required")
	}
	sessionBytes, err := hex.DecodeString(*session)
	if err != nil || len(sessionBytes) == 0 {
		return 2, errors.New("--session-binding-hex must encode a non-empty value")
	}
	requestA, err := readFileBounded(*requestAPath, 4096)
	if err != nil {
		return 2, err
	}
	requestB, err := readFileBounded(*requestBPath, 4096)
	if err != nil {
		return 2, err
	}
	responseA, err := readFileBounded(*responseAPath, protocol.MaxProofSize)
	if err != nil {
		return 2, err
	}
	responseB, err := readFileBounded(*responseBPath, protocol.MaxProofSize)
	if err != nil {
		return 2, err
	}
	decodedA, err := challenge.DecodeRequest(requestA)
	if err != nil {
		return 2, err
	}
	decodedB, err := challenge.DecodeRequest(requestB)
	if err != nil {
		return 2, err
	}
	partyACall, err := protocol.NormalizeCallsign(*partyA)
	if err != nil {
		return 2, err
	}
	partyBCall, err := protocol.NormalizeCallsign(*partyB)
	if err != nil {
		return 2, err
	}
	if decodedA.Requester != partyACall || decodedA.Responder != partyBCall || decodedB.Requester != partyBCall || decodedB.Responder != partyACall {
		return 2, errors.New("challenge pair does not match --party-a and --party-b")
	}
	publicA, err := identity.LoadPublic(*publicAPath)
	if err != nil {
		return 2, err
	}
	publicB, err := identity.LoadPublic(*publicBPath)
	if err != nil {
		return 2, err
	}
	verifierA, err := protocol.NewEd25519Verifier(publicA)
	if err != nil {
		return 2, err
	}
	verifierB, err := protocol.NewEd25519Verifier(publicB)
	if err != nil {
		return 2, err
	}
	now := time.Now().UTC()
	trustA, closeA, err := openChallengeTrust(*trustAPath, *enrollmentAPath, *enrollmentMaxAge, now)
	if err != nil {
		return 2, fmt.Errorf("party A trust: %w", err)
	}
	defer closeA()
	trustB, closeB, err := openChallengeTrust(*trustBPath, *enrollmentBPath, *enrollmentMaxAge, now)
	if err != nil {
		return 2, fmt.Errorf("party B trust: %w", err)
	}
	defer closeB()
	store, err := challenge.OpenSQLite(*dbPath)
	if err != nil {
		return 2, err
	}
	defer store.Close()
	result := challenge.VerifyMutualPair(
		challenge.MutualRequests{FromA: requestA, FromB: requestB},
		challenge.MutualResponses{FromA: responseA, FromB: responseB},
		challenge.MutualVerificationConfig{VerifierA: verifierA, TrustA: trustA, VerifierB: verifierB, TrustB: trustB, Store: store, Session: sessionBytes, Now: now},
	)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 2, err
	}
	if result.Accepted {
		return 0, nil
	}
	return 1, nil
}

func issueChallenge(args []string) (int, error) {
	fs := flag.NewFlagSet("challenge issue", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	requester := fs.String("requester", "", "requesting station callsign")
	responder := fs.String("responder", "", "challenged station callsign")
	purpose := fs.String("purpose", challenge.AuthPurpose, "requested authentication purpose")
	session := fs.String("session-binding-hex", "", "optional session binding bytes as hex")
	lifetime := fs.Int("expires-in", int(challenge.DefaultLifetime/time.Second), "lifetime in seconds, max 600")
	dbPath := fs.String("store", "", "durable challenge database")
	out := fs.String("out", "", "request output file")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *requester == "" || *responder == "" || *dbPath == "" || *out == "" {
		return 2, errors.New("--requester, --responder, --store and --out are required")
	}
	sessionBytes, err := hex.DecodeString(*session)
	if err != nil {
		return 2, fmt.Errorf("invalid session binding hex: %w", err)
	}
	now := time.Now().UTC()
	store, err := challenge.OpenSQLite(*dbPath)
	if err != nil {
		return 2, err
	}
	defer store.Close()
	encoded, err := challenge.IssueRequest(store, *requester, *responder, *purpose, sessionBytes, now, time.Duration(*lifetime)*time.Second)
	if err != nil {
		return 2, err
	}
	req, err := challenge.DecodeRequest(encoded)
	if err != nil {
		return 2, err
	}
	h := challenge.RequestHash(encoded)
	if err := identity.WriteExclusive(*out, encoded, 0600); err != nil {
		if cancelErr := challenge.CancelRequest(store, encoded); cancelErr != nil {
			return 2, fmt.Errorf("publish challenge request: %v; cancel pending record: %w", err, cancelErr)
		}
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{"request_sha256": hex.EncodeToString(h[:]), "requester": req.Requester, "responder": req.Responder, "issued_at": req.IssuedAt, "expires_at": req.ExpiresAt, "purpose": req.Purpose, "request_file": *out})
}

func respondChallenge(args []string) (int, error) {
	fs := flag.NewFlagSet("challenge respond", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	requestPath := fs.String("request", "", "canonical challenge request")
	keyPath := fs.String("key", "", "PKCS#8 Ed25519 private key")
	call := fs.String("callsign", "", "responder callsign")
	out := fs.String("out", "", "signed response output")
	passStdin := fs.Bool("passphrase-stdin", false, "read private-key passphrase from standard input")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *requestPath == "" || *keyPath == "" || *call == "" || *out == "" {
		return 2, errors.New("--request, --key, --callsign and --out are required")
	}
	request, err := readFileBounded(*requestPath, 4096)
	if err != nil {
		return 2, err
	}
	private, err := loadPrivateKey(*keyPath, *passStdin)
	if err != nil {
		return 2, err
	}
	signer, err := protocol.NewEd25519Signer(*call, private)
	if err != nil {
		return 2, err
	}
	proof, claims, err := challenge.Respond(signer, request, time.Now())
	if err != nil {
		return 2, err
	}
	if err := identity.WriteExclusive(*out, proof, 0600); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(map[string]any{"response_file": *out, "claims": claims})
}

func verifyChallenge(args []string) (int, error) {
	fs := flag.NewFlagSet("challenge verify-response", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	requestPath := fs.String("request", "", "original challenge request")
	proofPath := fs.String("response", "", "signed response proof")
	pubPath := fs.String("public-key", "", "responder Ed25519 SPKI key")
	trustPath := fs.String("trust-store", "", "local trust store")
	enrollmentPath := fs.String("enrollment-store", "", "optional LoTW enrollment SQLite store")
	enrollmentMaxAge := fs.Duration("max-enrollment-status-age", 24*time.Hour, "maximum age for LoTW certificate status evidence")
	dbPath := fs.String("store", "", "requester's challenge database")
	requester := fs.String("requester", "", "expected local requester callsign")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *requestPath == "" || *proofPath == "" || *pubPath == "" || (*trustPath == "" && *enrollmentPath == "") || *dbPath == "" || *requester == "" {
		return 2, errors.New("--request, --response, --public-key, one of --trust-store/--enrollment-store, --store and --requester are required")
	}
	request, err := readFileBounded(*requestPath, 4096)
	if err != nil {
		return 2, err
	}
	proof, err := readFileBounded(*proofPath, protocol.MaxProofSize)
	if err != nil {
		return 2, err
	}
	pub, err := identity.LoadPublic(*pubPath)
	if err != nil {
		return 2, err
	}
	verifier, err := protocol.NewEd25519Verifier(pub)
	if err != nil {
		return 2, err
	}
	store, err := challenge.OpenSQLite(*dbPath)
	if err != nil {
		return 2, err
	}
	defer store.Close()
	now := time.Now().UTC()
	trustDecision, closeTrust, err := openChallengeTrust(*trustPath, *enrollmentPath, *enrollmentMaxAge, now)
	if err != nil {
		return 2, err
	}
	defer closeTrust()
	result := challenge.VerifyResponseWithTrust(request, proof, verifier, trustDecision, store, *requester, now)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 2, err
	}
	if result.OverallPolicy == "accepted" {
		return 0, nil
	}
	return 1, nil
}

func openChallengeTrust(trustPath, enrollmentPath string, maxAge time.Duration, now time.Time) (challenge.TrustDecisionFunc, func(), error) {
	if trustPath == "" && enrollmentPath == "" {
		return nil, func() {}, errors.New("one of a local trust store or enrollment store is required")
	}
	if enrollmentPath != "" && maxAge <= 0 {
		return nil, func() {}, errors.New("maximum enrollment status age must be positive")
	}
	localTrust := identity.TrustStore{Version: 1, Bindings: []identity.Binding{}}
	var err error
	if trustPath != "" {
		localTrust, err = identity.LoadTrust(trustPath)
		if err != nil {
			return nil, func() {}, err
		}
	}
	var enrolled *lotwenroll.SQLiteStore
	if enrollmentPath != "" {
		enrolled, err = lotwenroll.OpenSQLite(enrollmentPath)
		if err != nil {
			return nil, func() {}, err
		}
	}
	closeStore := func() {
		if enrolled != nil {
			_ = enrolled.Close()
		}
	}
	decision := func(call, keyID, purpose string) string {
		local := localTrust.Status(call, keyID, purpose)
		if local == "disabled" {
			return "disabled"
		}
		if enrolled != nil {
			status := enrolled.TrustStatus(call, keyID, purpose, now, maxAge)
			if status == "disabled" || status == "trusted" {
				return status
			}
		}
		return local
	}
	return decision, closeStore, nil
}

func fingerprint(args []string) (int, error) {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pubPath := fs.String("public-key", "", "SPKI public key or X.509 certificate PEM")
	jsonOutput := fs.Bool("json", false, "emit a machine-readable fingerprint result")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *pubPath == "" {
		return 2, errors.New("--public-key is required")
	}
	pub, err := identity.LoadPublicKey(*pubPath)
	if err != nil {
		return 2, err
	}
	id, err := protocol.KeyID(pub)
	if err != nil {
		return 2, err
	}
	if *jsonOutput {
		return 0, json.NewEncoder(os.Stdout).Encode(map[string]string{"key_id_sha256": hex.EncodeToString(id)})
	}
	_, err = fmt.Fprintln(os.Stdout, hex.EncodeToString(id))
	if err != nil {
		return 2, err
	}
	return 0, nil
}

func keygen(args []string) (int, error) {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	priv := fs.String("private-key", "", "encrypted Ed25519 private-key PEM output (created mode 0600)")
	pub := fs.String("public-key", "", "SPKI PEM output")
	passStdin := fs.Bool("passphrase-stdin", false, "read and confirm the new private-key passphrase from standard input")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *priv == "" || *pub == "" {
		return 2, errors.New("--private-key and --public-key are required")
	}
	passphrase, err := createKeyPassphrase(*passStdin)
	if err != nil {
		return 2, err
	}
	defer wipe(passphrase)
	if err := identity.GenerateEncryptedKeyPair(*priv, *pub, passphrase); err != nil {
		return 2, err
	}
	return 0, nil
}

func signContent(args []string) (int, error) {
	fs := flag.NewFlagSet("sign-content", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	key := fs.String("key", "", "encrypted or legacy PKCS#8 Ed25519 private key")
	call := fs.String("callsign", "", "signer callsign")
	input := fs.String("input", "", "content file")
	media := fs.String("media-type", "", "content media type")
	ctx := fs.String("context", "", "application context")
	canon := fs.String("canonicalization", "identity-v1", "canonicalization id")
	contentID := fs.String("content-id", "", "optional application id")
	out := fs.String("out", "", "proof output")
	notAfter := fs.String("not-after", "", "optional RFC3339 expiration")
	passStdin := fs.Bool("passphrase-stdin", false, "read private-key passphrase from standard input")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *key == "" || *call == "" || *input == "" || *media == "" || *ctx == "" || *out == "" {
		return 2, errors.New("--key, --callsign, --input, --media-type, --context and --out are required")
	}
	private, err := loadPrivateKey(*key, *passStdin)
	if err != nil {
		return 2, err
	}
	signer, err := protocol.NewEd25519Signer(*call, private)
	if err != nil {
		return 2, err
	}
	f, err := os.Open(*input)
	if err != nil {
		return 2, err
	}
	defer f.Close()
	meta := protocol.ContentMetadata{MediaType: *media, Canonicalization: *canon, Context: *ctx, ContentID: *contentID}
	if *notAfter != "" {
		t, e := time.Parse(time.RFC3339, *notAfter)
		if e != nil {
			return 2, e
		}
		meta.NotAfter = &t
	}
	proof, claims, err := protocol.SignContent(signer, f, meta, time.Now())
	if err != nil {
		return 2, err
	}
	if err := identity.WriteExclusive(*out, proof, 0600); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(claims)
}

func verifyContent(args []string) (int, error) {
	fs := flag.NewFlagSet("verify-content", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	proofPath := fs.String("proof", "", "COSE_Sign1 proof")
	input := fs.String("input", "", "content file")
	pubPath := fs.String("public-key", "", "SPKI Ed25519 key")
	storePath := fs.String("trust-store", "", "local callsign trust store")
	enrollmentStorePath := fs.String("enrollment-store", "", "optional LoTW enrollment database")
	enrollmentMaxAge := fs.Duration("max-enrollment-status-age", 24*time.Hour, "maximum age for enrolled certificate status evidence")
	media := fs.String("expect-media-type", "", "expected media type")
	ctx := fs.String("expect-context", "", "expected application context")
	canon := fs.String("expect-canonicalization", "identity-v1", "expected canonicalization")
	call := fs.String("expect-callsign", "", "optional expected signer")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *proofPath == "" || *input == "" || *pubPath == "" || (*storePath == "" && *enrollmentStorePath == "") || *media == "" || *ctx == "" {
		return 2, errors.New("--proof, --input, --public-key, one of --trust-store/--enrollment-store, --expect-media-type and --expect-context are required")
	}
	if *enrollmentStorePath != "" && *enrollmentMaxAge <= 0 {
		return 2, errors.New("--max-enrollment-status-age must be positive")
	}
	proof, err := readFileBounded(*proofPath, protocol.MaxProofSize)
	if err != nil {
		return 2, err
	}
	pub, err := identity.LoadPublic(*pubPath)
	if err != nil {
		return 2, err
	}
	verifier, err := protocol.NewEd25519Verifier(pub)
	if err != nil {
		return 2, err
	}
	now := time.Now().UTC()
	trustDecision, closeTrust, err := openChallengeTrust(*storePath, *enrollmentStorePath, *enrollmentMaxAge, now)
	if err != nil {
		return 2, err
	}
	defer closeTrust()
	content, err := os.Open(*input)
	if err != nil {
		return 2, err
	}
	defer content.Close()
	result := protocol.VerifyContentWithTrust(proof, content, verifier, protocol.Expected{Purpose: protocol.PurposeContent, MediaType: *media, Canonicalization: *canon, Context: *ctx, Callsign: *call}, trustDecision, now)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 2, err
	}
	switch result.OverallPolicy {
	case "accepted":
		return 0, nil
	case "incomplete":
		return 3, nil
	default:
		return 1, nil
	}
}

func signPixelQSO(args []string) (int, error) {
	fs := flag.NewFlagSet("sign-pixelqso", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	keyPath := fs.String("key", "", "PKCS#8 Ed25519 private key")
	cardPath := fs.String("card", "", "saved PixelQSO card JSON")
	firstCardPath := fs.String("first-card", "", "first frame JSON when signing frame 2")
	out := fs.String("out", "", "COSE proof output")
	passStdin := fs.Bool("passphrase-stdin", false, "read private-key passphrase from standard input")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *keyPath == "" || *cardPath == "" || *out == "" {
		return 2, errors.New("--key, --card and --out are required")
	}
	cardJSON, err := readFileBounded(*cardPath, pixelqso.MaxJSON)
	if err != nil {
		return 2, err
	}
	_, card, err := pixelqso.CanonicalizeJSON(cardJSON)
	if err != nil {
		return 2, err
	}
	var firstCardJSON []byte
	if *firstCardPath != "" {
		firstCardJSON, err = readFileBounded(*firstCardPath, pixelqso.MaxJSON)
		if err != nil {
			return 2, err
		}
	}
	private, err := loadPrivateKey(*keyPath, *passStdin)
	if err != nil {
		return 2, err
	}
	signer, err := protocol.NewEd25519Signer(card.Callsign, private)
	if err != nil {
		return 2, err
	}
	proof, claims, err := pixelqso.SignJSON(signer, cardJSON, firstCardJSON, time.Now())
	if err != nil {
		return 2, err
	}
	if err := identity.WriteExclusive(*out, proof, 0600); err != nil {
		return 2, err
	}
	return 0, json.NewEncoder(os.Stdout).Encode(claims)
}

func verifyPixelQSO(args []string) (int, error) {
	fs := flag.NewFlagSet("verify-pixelqso", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cardPath := fs.String("card", "", "saved PixelQSO card JSON")
	firstCardPath := fs.String("first-card", "", "first frame JSON when verifying frame 2")
	proofPath := fs.String("proof", "", "COSE_Sign1 proof")
	pubPath := fs.String("public-key", "", "SPKI Ed25519 public key")
	trustPath := fs.String("trust-store", "", "local callsign trust store")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *cardPath == "" || *proofPath == "" || *pubPath == "" || *trustPath == "" {
		return 2, errors.New("--card, --proof, --public-key and --trust-store are required")
	}
	cardJSON, err := readFileBounded(*cardPath, pixelqso.MaxJSON)
	if err != nil {
		return 2, err
	}
	var firstCardJSON []byte
	if *firstCardPath != "" {
		firstCardJSON, err = readFileBounded(*firstCardPath, pixelqso.MaxJSON)
		if err != nil {
			return 2, err
		}
	}
	proof, err := readFileBounded(*proofPath, protocol.MaxProofSize)
	if err != nil {
		return 2, err
	}
	public, err := identity.LoadPublic(*pubPath)
	if err != nil {
		return 2, err
	}
	verifier, err := protocol.NewEd25519Verifier(public)
	if err != nil {
		return 2, err
	}
	trust, err := identity.LoadTrust(*trustPath)
	if err != nil {
		return 2, err
	}
	result, err := pixelqso.VerifyJSON(proof, cardJSON, firstCardJSON, verifier, trust.Status, time.Now())
	if err != nil {
		return 2, err
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return 2, err
	}
	switch result.OverallPolicy {
	case "accepted":
		return 0, nil
	case "incomplete":
		return 3, nil
	default:
		return 1, nil
	}
}

func trustCommand(args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("trust requires add, list or disable (add re-enables a disabled binding for the requested purpose)")
	}
	fs := flag.NewFlagSet("trust "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	storePath := fs.String("store", "", "trust-store JSON")
	pubPath := fs.String("public-key", "", "SPKI PEM")
	call := fs.String("callsign", "", "callsign")
	purpose := fs.String("purpose", protocol.PurposeContent, "authorized purpose")
	keyID := fs.String("key-id", "", "key fingerprint for disable")
	if err := fs.Parse(args[1:]); err != nil {
		return 2, err
	}
	if *storePath == "" {
		return 2, errors.New("--store is required")
	}
	store, err := identity.LoadTrust(*storePath)
	if err != nil {
		return 2, err
	}
	switch args[0] {
	case "list":
		return 0, json.NewEncoder(os.Stdout).Encode(store)
	case "add":
		if *pubPath == "" || *call == "" {
			return 2, errors.New("trust add requires --public-key and --callsign")
		}
		callNorm, err := protocol.NormalizeCallsign(*call)
		if err != nil {
			return 2, err
		}
		pub, err := identity.LoadPublic(*pubPath)
		if err != nil {
			return 2, err
		}
		id, err := protocol.KeyID(pub)
		if err != nil {
			return 2, err
		}
		if *purpose != protocol.PurposeContent && *purpose != challenge.ResponsePurpose {
			return 2, errors.New("unsupported purpose")
		}
		store.Add(callNorm, hex.EncodeToString(id), []string{*purpose})
		return 0, identity.SaveTrust(*storePath, store)
	case "disable":
		if *call == "" || *keyID == "" {
			return 2, errors.New("trust disable requires --callsign and --key-id")
		}
		callNorm, err := protocol.NormalizeCallsign(*call)
		if err != nil {
			return 2, err
		}
		if !store.Disable(callNorm, *keyID) {
			return 2, errors.New("trust binding not found")
		}
		return 0, identity.SaveTrust(*storePath, store)
	default:
		return 2, fmt.Errorf("unknown trust action %q", args[0])
	}
}
