// Package reference implements bounded fetch and publish operations for ARAP proofs.
package reference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tcarwash/arap/identity"
	"github.com/tcarwash/arap/protocol"
)

const lookupLimit = 16 * 1024
const MaxLookupCandidates = 100
const MaxResolvers = 8
const MaxReferenceInput = 256

// ResolutionCode is a stable machine-readable outcome for proof and key
// resolution. Human-readable error text may change; branch on Code instead.
type ResolutionCode string

const (
	ResolutionInvalidInput    ResolutionCode = "invalid_input"
	ResolutionNotFound        ResolutionCode = "not_found"
	ResolutionAmbiguous       ResolutionCode = "ambiguous"
	ResolutionIncomplete      ResolutionCode = "incomplete"
	ResolutionUnavailable     ResolutionCode = "unavailable"
	ResolutionInvalidResponse ResolutionCode = "invalid_response"
	ResolutionCanceled        ResolutionCode = "canceled"
)

// ResolutionError describes a stable resolver outcome and retains its cause
// for errors.Is/errors.As. Resolver may be empty when the outcome combines
// multiple configured servers.
type ResolutionError struct {
	Code     ResolutionCode
	Resolver string
	Cause    error
}

func (e *ResolutionError) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return string(e.Code)
}

func (e *ResolutionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

type httpStatusError struct{ status int }

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("keyserver GET returned HTTP %d", e.status)
}

func resolutionError(code ResolutionCode, cause error) error {
	return &ResolutionError{Code: code, Cause: cause}
}

func resolutionTransportError(cause error) error {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return resolutionError(ResolutionCanceled, cause)
	}
	return resolutionError(ResolutionUnavailable, cause)
}

type Client struct {
	base  string
	bases []string
	http  *http.Client
}

type Resolved struct {
	Proof []byte
	Hash  string
	Token string
}

type lookupResponse struct {
	Proofs    []string `json:"proofs"`
	Truncated bool     `json:"truncated"`
}

func New(base string) (*Client, error) {
	return NewMulti([]string{base})
}

// NewMulti creates a client that resolves read requests across a bounded,
// ordered resolver set. Publishing uses the first configured resolver.
func NewMulti(bases []string) (*Client, error) {
	if len(bases) == 0 || len(bases) > MaxResolvers {
		return nil, fmt.Errorf("configure between 1 and %d keyserver URLs", MaxResolvers)
	}
	normalized := make([]string, 0, len(bases))
	seen := make(map[string]bool, len(bases))
	for _, base := range bases {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		u, err := url.Parse(base)
		if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("invalid keyserver base URL")
		}
		if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
			return nil, errors.New("keyserver must use HTTPS except on loopback")
		}
		base = strings.TrimRight(u.String(), "/")
		if !seen[base] {
			normalized = append(normalized, base)
			seen[base] = true
		}
	}
	return &Client{base: normalized[0], bases: normalized, http: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Resolve(ctx context.Context, reference string) (Resolved, error) {
	if c == nil || c.http == nil {
		return Resolved{}, resolutionError(ResolutionUnavailable, errors.New("keyserver client is not initialized"))
	}
	normalized, token, full, err := ParseReference(reference)
	if err != nil {
		return Resolved{}, resolutionError(ResolutionInvalidInput, err)
	}
	var hash string
	if full {
		hash = normalized
	} else {
		candidates := make(map[string]struct{})
		sawUnavailable := false
		var lookupErr error
		var failedResolver string
		for _, base := range c.bases {
			body, err := c.getAt(ctx, base, "/v1/lookup/"+token, lookupLimit)
			if err != nil {
				var statusErr *httpStatusError
				if errors.As(err, &statusErr) && statusErr.status == http.StatusNotFound {
				} else {
					sawUnavailable = true
					lookupErr, failedResolver = err, base
				}
				continue
			}
			result, err := parseLookup(body)
			if err != nil {
				return Resolved{}, &ResolutionError{Code: ResolutionInvalidResponse, Resolver: base, Cause: fmt.Errorf("resolver %s: %w", base, err)}
			}
			if result.Truncated {
				return Resolved{}, resolutionError(ResolutionIncomplete, errors.New("lookup candidate list was truncated; use a full proof hash"))
			}
			for _, candidate := range result.Proofs {
				if !validHash(candidate) {
					return Resolved{}, &ResolutionError{Code: ResolutionInvalidResponse, Resolver: base, Cause: fmt.Errorf("resolver %s returned an invalid proof hash", base)}
				}
				if strings.TrimPrefix(Token(candidate), "AR1") != token {
					return Resolved{}, &ResolutionError{Code: ResolutionInvalidResponse, Resolver: base, Cause: fmt.Errorf("resolver %s returned a candidate that does not match the reference token", base)}
				}
				candidates[candidate] = struct{}{}
			}
		}
		if len(candidates) == 0 {
			if sawUnavailable {
				return Resolved{}, &ResolutionError{Code: ResolutionUnavailable, Resolver: failedResolver,
					Cause: fmt.Errorf("resolver %s lookup failed: %w", failedResolver, lookupErr)}
			}
			return Resolved{}, resolutionError(ResolutionNotFound, errors.New("no proof matches reference"))
		}
		if sawUnavailable {
			return Resolved{}, &ResolutionError{Code: ResolutionUnavailable, Resolver: failedResolver,
				Cause: fmt.Errorf("resolver %s lookup failed: %w", failedResolver, lookupErr)}
		}
		if len(candidates) != 1 {
			return Resolved{}, resolutionError(ResolutionAmbiguous, fmt.Errorf("reference is ambiguous across configured resolvers: %d candidates", len(candidates)))
		}
		for hash = range candidates {
		}
	}
	var proof []byte
	var lastErr error
	sawNotFound, sawInvalidResponse, sawOtherFailure := false, false, false
	for _, base := range c.bases {
		proof, lastErr = c.getAt(ctx, base, "/v1/proofs/"+hash, protocol.MaxProofSize)
		if lastErr != nil {
			var statusErr *httpStatusError
			if errors.As(lastErr, &statusErr) && statusErr.status == http.StatusNotFound {
				sawNotFound = true
			} else {
				sawOtherFailure = true
			}
			continue
		}
		digest := sha256.Sum256(proof)
		if hex.EncodeToString(digest[:]) == hash {
			return Resolved{Proof: proof, Hash: hash, Token: Token(hash)}, nil
		}
		lastErr = errors.New("proof bytes do not match requested full hash")
		sawInvalidResponse = true
	}
	if sawInvalidResponse {
		return Resolved{}, resolutionError(ResolutionInvalidResponse, fmt.Errorf("no configured resolver returned the requested proof: %w", lastErr))
	}
	if sawNotFound && !sawOtherFailure {
		return Resolved{}, resolutionError(ResolutionNotFound, fmt.Errorf("proof %s was not found: %w", hash, lastErr))
	}
	return Resolved{}, resolutionTransportError(fmt.Errorf("no configured resolver returned the requested proof: %w", lastErr))
}

func (c *Client) PublishProof(ctx context.Context, proof []byte, token string) (Resolved, error) {
	if c == nil || c.http == nil {
		return Resolved{}, errors.New("keyserver client is not initialized")
	}
	if len(proof) == 0 || len(proof) > protocol.MaxProofSize {
		return Resolved{}, errors.New("proof must be 1..64 KiB")
	}
	h := sha256.Sum256(proof)
	hash := hex.EncodeToString(h[:])
	if err := c.put(ctx, "/v1/proofs/"+hash, proof, token); err != nil {
		return Resolved{}, err
	}
	return Resolved{Proof: append([]byte(nil), proof...), Hash: hash, Token: Token(hash)}, nil
}

func (c *Client) PublishKey(ctx context.Context, fingerprint string, key []byte, token string) error {
	fingerprint = strings.ToLower(fingerprint)
	if !validHash(fingerprint) || len(key) == 0 || len(key) > 1024*1024 {
		return errors.New("invalid fingerprint or public-key size")
	}
	pub, err := parsePublicKey(key)
	if err != nil {
		return err
	}
	id, err := protocol.KeyID(pub)
	if err != nil || hex.EncodeToString(id) != fingerprint {
		return errors.New("public-key fingerprint does not match requested path")
	}
	return c.put(ctx, "/v1/keys/"+fingerprint, key, token)
}

func (c *Client) FetchKey(ctx context.Context, fingerprint string) ([]byte, error) {
	if c == nil || c.http == nil {
		return nil, resolutionError(ResolutionUnavailable, errors.New("keyserver client is not initialized"))
	}
	fingerprint = strings.ToLower(fingerprint)
	if !validHash(fingerprint) {
		return nil, resolutionError(ResolutionInvalidInput, errors.New("fingerprint must be a full SHA-256 hash"))
	}
	var lastErr error
	sawNotFound, sawInvalidResponse, sawOtherFailure := false, false, false
	for _, base := range c.bases {
		data, err := c.getAt(ctx, base, "/v1/keys/"+fingerprint, 1024*1024)
		if err != nil {
			lastErr = err
			var statusErr *httpStatusError
			if errors.As(err, &statusErr) && statusErr.status == http.StatusNotFound {
				sawNotFound = true
			} else {
				sawOtherFailure = true
			}
			continue
		}
		pub, err := parsePublicKey(data)
		if err != nil {
			lastErr = err
			sawInvalidResponse = true
			continue
		}
		id, err := protocol.KeyID(pub)
		if err != nil || hex.EncodeToString(id) != fingerprint {
			lastErr = errors.New("downloaded public key fingerprint mismatch")
			sawInvalidResponse = true
			continue
		}
		return data, nil
	}
	if sawInvalidResponse {
		return nil, resolutionError(ResolutionInvalidResponse, fmt.Errorf("no configured resolver returned a valid public key: %w", lastErr))
	}
	if sawNotFound && !sawOtherFailure {
		return nil, resolutionError(ResolutionNotFound, fmt.Errorf("public key %s was not found: %w", fingerprint, lastErr))
	}
	return nil, resolutionTransportError(fmt.Errorf("no configured resolver returned the requested public key: %w", lastErr))
}

func parseLookup(body []byte) (lookupResponse, error) {
	var result lookupResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil {
		return lookupResponse{}, fmt.Errorf("invalid lookup response: %w", err)
	}
	if opening != json.Delim('{') {
		return lookupResponse{}, errors.New("invalid lookup response: expected an object")
	}
	seen := make(map[string]bool, 2)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return lookupResponse{}, fmt.Errorf("invalid lookup response field: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return lookupResponse{}, errors.New("invalid lookup response: field names must be strings")
		}
		if seen[name] {
			return lookupResponse{}, fmt.Errorf("invalid lookup response: duplicate field %q", name)
		}
		seen[name] = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return lookupResponse{}, fmt.Errorf("invalid lookup response field %q: %w", name, err)
		}
		value := bytes.TrimSpace(raw)
		switch name {
		case "proofs":
			if len(value) == 0 || value[0] != '[' {
				return lookupResponse{}, errors.New("invalid lookup response: proofs must be an array")
			}
			if err := json.Unmarshal(value, &result.Proofs); err != nil {
				return lookupResponse{}, fmt.Errorf("invalid lookup response proofs: %w", err)
			}
		case "truncated":
			if !bytes.Equal(value, []byte("true")) && !bytes.Equal(value, []byte("false")) {
				return lookupResponse{}, errors.New("invalid lookup response: truncated must be a boolean")
			}
			result.Truncated = bytes.Equal(value, []byte("true"))
		default:
			return lookupResponse{}, fmt.Errorf("invalid lookup response: unknown field %q", name)
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return lookupResponse{}, errors.New("invalid lookup response: missing object terminator")
	}
	if !seen["proofs"] || !seen["truncated"] {
		return lookupResponse{}, errors.New("invalid lookup response: proofs and truncated are required")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return lookupResponse{}, errors.New("lookup response has trailing JSON")
	}
	if len(result.Proofs) > MaxLookupCandidates {
		return lookupResponse{}, fmt.Errorf("lookup response exceeds %d candidates", MaxLookupCandidates)
	}
	return result, nil
}

func ParseReference(input string) (normalized, token string, fullHash bool, err error) {
	if len(input) > MaxReferenceInput {
		return "", "", false, errors.New("reference input exceeds 256 bytes")
	}
	s := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(input)))
	if strings.HasPrefix(s, "AR1") {
		t := s[3:]
		if len(t) != 16 {
			return "", "", false, errors.New("AR1 reference must contain sixteen Base32 characters")
		}
		for _, r := range t {
			if !(r >= 'A' && r <= 'Z') && !(r >= '2' && r <= '7') {
				return "", "", false, errors.New("invalid Base32 reference")
			}
		}
		return "", t, false, nil
	}
	if len(s) != 64 {
		return "", "", false, errors.New("reference must be an AR1 token or full SHA-256 hash")
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'F') {
			return "", "", false, errors.New("invalid SHA-256 hash")
		}
	}
	return strings.ToLower(s), "", true, nil
}

func Token(hash string) string {
	b, err := hex.DecodeString(hash)
	if err != nil || len(b) != sha256.Size {
		return ""
	}
	return "AR1" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:10])
}

func (c *Client) get(ctx context.Context, path string, limit int) ([]byte, error) {
	return c.getAt(ctx, c.base, path, limit)
}

func (c *Client) getAt(ctx context.Context, base, path string, limit int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpStatusError{status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, errors.New("keyserver response exceeds size limit")
	}
	return data, nil
}
func (c *Client) put(ctx context.Context, path string, data []byte, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keyserver PUT returned HTTP %d", resp.StatusCode)
	}
	return nil
}
func validHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}
func parsePublicKey(data []byte) (any, error) {
	return identity.ParsePublicKey(data)
}
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
