package reference

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tcarwash/arap/keyserver"
	"github.com/tcarwash/arap/protocol"
)

func TestPublishResolveByTokenAndFullHash(t *testing.T) {
	server, err := keyserver.New(filepath.Join(t.TempDir(), "objects"), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client, err := New(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	proof := []byte("synthetic proof object")
	published, err := client.PublishProof(context.Background(), proof, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	byToken, err := client.Resolve(context.Background(), published.Token)
	if err != nil {
		t.Fatal(err)
	}
	if string(byToken.Proof) != string(proof) || byToken.Hash != published.Hash {
		t.Fatalf("token resolution mismatch: %#v", byToken)
	}
	byHash, err := client.Resolve(context.Background(), published.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if string(byHash.Proof) != string(proof) {
		t.Fatalf("full-hash resolution mismatch: %#v", byHash)
	}
}

func TestPublishAndFetchKeyChecksFingerprint(t *testing.T) {
	server, err := keyserver.New(filepath.Join(t.TempDir(), "keys"), "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	client, err := New(httpServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	id, err := protocol.KeyID(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := hex.EncodeToString(id)
	if err := client.PublishKey(context.Background(), fingerprint, encoded, "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	fetched, err := client.FetchKey(context.Background(), fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if string(fetched) != string(encoded) {
		t.Fatal("fetched public key differs from published bytes")
	}
	if err := client.PublishKey(context.Background(), strings.Repeat("0", 64), encoded, "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("accepted mismatched fingerprint")
	}
}

func TestResolutionErrorsHaveStableUnknownCode(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, err := NewMulti([]string{server.URL, server.URL + "/second"})
	if err != nil {
		t.Fatal(err)
	}
	unknownHash := strings.Repeat("a", 64)
	_, err = client.Resolve(context.Background(), unknownHash)
	var resolutionErr *ResolutionError
	if !errors.As(err, &resolutionErr) || resolutionErr.Code != ResolutionNotFound {
		t.Fatalf("Resolve error = %v, want typed not_found", err)
	}
	_, err = client.FetchKey(context.Background(), unknownHash)
	if !errors.As(err, &resolutionErr) || resolutionErr.Code != ResolutionNotFound {
		t.Fatalf("FetchKey error = %v, want typed not_found", err)
	}
}

func TestResolverRejectsAmbiguousTruncatedAndRedirectResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "ambiguous", status: 200, body: `{"proofs":["` + repeat("0", 64) + `","` + repeat("0", 20) + repeat("1", 44) + `"],"truncated":false}`, want: "ambiguous"},
		{name: "truncated", status: 200, body: `{"proofs":["` + repeat("0", 64) + `"],"truncated":true}`, want: "truncated"},
		{name: "redirect", status: 302, body: "", want: "HTTP 302"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status == 302 {
					w.Header().Set("Location", "/elsewhere")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Resolve(context.Background(), "AR1AAAAAAAAAAAAAAAA")
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want substring %q", err, tc.want)
			}
		})
	}
}

func TestParseLookupRejectsDuplicateAndMalformedFields(t *testing.T) {
	for _, body := range []string{
		`{"proofs":[],"proofs":["` + strings.Repeat("0", 64) + `"],"truncated":false}`,
		`{"proofs":[],"truncated":true,"truncated":false}`,
		`{"proofs":[]}`,
		`{"truncated":false}`,
		`{"proofs":null,"truncated":false}`,
		`{"proofs":[],"truncated":null}`,
		`{"proofs":[],"truncated":false,"extra":1}`,
		`{"proofs":[],"truncated":false} {}`,
	} {
		if _, err := parseLookup([]byte(body)); err == nil {
			t.Fatalf("accepted malformed lookup response: %s", body)
		}
	}
	parsed, err := parseLookup([]byte(`{"truncated":false,"proofs":[]}`))
	if err != nil || parsed.Truncated || len(parsed.Proofs) != 0 {
		t.Fatalf("valid lookup response was rejected: %#v, %v", parsed, err)
	}
	tooMany := make([]string, MaxLookupCandidates+1)
	for i := range tooMany {
		tooMany[i] = `"` + strings.Repeat("0", 64) + `"`
	}
	body := `{"proofs":[` + strings.Join(tooMany, ",") + `],"truncated":false}`
	if _, err := parseLookup([]byte(body)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("excessive candidate list error=%v", err)
	}
}

func TestParseReferenceInputSizeBound(t *testing.T) {
	if _, _, _, err := ParseReference(strings.Repeat(" ", MaxReferenceInput+1)); err == nil {
		t.Fatal("accepted an overlong formatted reference")
	}
	formatted := "AR1" + strings.Repeat("A-", 16)
	if len(formatted) > MaxReferenceInput {
		t.Fatal("test reference unexpectedly exceeds the supported formatting bound")
	}
	if _, token, full, err := ParseReference(formatted); err != nil || full || token != strings.Repeat("A", 16) {
		t.Fatalf("valid grouped reference=(%q,%v,%v)", token, full, err)
	}
}

func FuzzParseReference(f *testing.F) {
	f.Add("AR1ABCDEFGHIJKLMNOP")
	f.Add("ar1-abcd efgh ijkl mnop")
	f.Add(strings.Repeat("0", 64))
	f.Add(strings.Repeat("-", MaxReferenceInput+1))
	f.Add("ＡＲ１ABCDEFGHIJKLMNOP")
	f.Fuzz(func(t *testing.T, input string) {
		_, _, _, _ = ParseReference(input)
	})
}

func FuzzParseLookup(f *testing.F) {
	f.Add([]byte(`{"proofs":[],"truncated":false}`))
	f.Add([]byte(`{"proofs":[],"proofs":[],"truncated":false}`))
	f.Add([]byte{0xff, '{', '}'})
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > lookupLimit {
			t.Skip()
		}
		_, _ = parseLookup(body)
	})
}

func TestResolverRejectsRemoteHTTPAndBadHash(t *testing.T) {
	if _, err := New("http://example.com"); err == nil {
		t.Fatal("accepted remote HTTP")
	}
	if _, _, _, err := ParseReference("../etc/passwd"); err == nil {
		t.Fatal("accepted path")
	}
}

func TestResolverRejectsFalseFullHashResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not the claimed object"))
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Resolve(context.Background(), strings.Repeat("0", 64))
	if err == nil || !contains(err.Error(), "do not match") {
		t.Fatalf("false hash response was not rejected: %v", err)
	}
}

func TestResolverRejectsMaliciousLookupCandidates(t *testing.T) {
	matchingPrefixCandidate := strings.Repeat("0", 20) + strings.Repeat("1", 44)
	for _, tc := range []struct {
		name      string
		reference string
		candidate string
		proof     string
		want      string
	}{
		{
			name:      "candidate does not match token",
			reference: "AR1AAAAAAAAAAAAAAAA",
			candidate: strings.Repeat("f", 64),
			proof:     "unused",
			want:      "does not match the reference token",
		},
		{
			name:      "candidate path returns false object",
			reference: Token(matchingPrefixCandidate),
			candidate: matchingPrefixCandidate,
			proof:     "different bytes",
			want:      "do not match requested full hash",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/v1/lookup/") {
					_, _ = fmt.Fprintf(w, `{"proofs":["%s"],"truncated":false}`, tc.candidate)
					return
				}
				_, _ = io.WriteString(w, tc.proof)
			}))
			defer server.Close()
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Resolve(context.Background(), tc.reference)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("malicious resolver response error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestResolverRejectsOversizedLookupAndProofResponses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reference string
		limit     int
	}{
		{name: "lookup", reference: "AR1AAAAAAAAAAAAAAAA", limit: lookupLimit},
		{name: "proof", reference: strings.Repeat("0", 64), limit: protocol.MaxProofSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(bytes.Repeat([]byte("x"), tc.limit+1))
			}))
			defer server.Close()
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Resolve(context.Background(), tc.reference); err == nil || !strings.Contains(err.Error(), "size limit") {
				t.Fatalf("oversized response error=%v, want size-limit rejection", err)
			}
		})
	}
}

func TestResolverHonorsContextCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-started:
			cancel()
		case <-time.After(time.Second):
			cancel()
		}
	}()
	_, err = client.Resolve(ctx, "AR1AAAAAAAAAAAAAAAA")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve error=%v, want context cancellation", err)
	}
}

func TestMultiResolverMergesCandidatesAndRejectsCrossServerAmbiguity(t *testing.T) {
	firstHash := strings.Repeat("a", 20) + strings.Repeat("0", 44)
	secondHash := strings.Repeat("a", 20) + strings.Repeat("1", 44)
	servers := make([]*httptest.Server, 0, 2)
	for _, candidate := range []string{firstHash, secondHash} {
		candidate := candidate
		servers = append(servers, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/v1/lookup/") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"proofs":["` + candidate + `"],"truncated":false}`))
		})))
	}
	defer servers[0].Close()
	defer servers[1].Close()
	client, err := NewMulti([]string{servers[0].URL, servers[1].URL})
	if err != nil {
		t.Fatal(err)
	}
	firstToken := Token(firstHash)
	_, err = client.Resolve(context.Background(), firstToken)
	if err == nil || !strings.Contains(err.Error(), "ambiguous across configured resolvers") {
		t.Fatalf("cross-resolver collision error=%v", err)
	}
}

func TestMultiResolverFailsClosedOnUnavailableLookupAndRetriesFullHash(t *testing.T) {
	proof := []byte("proof from second resolver")
	digest := sha256.Sum256(proof)
	hash := hex.EncodeToString(digest[:])
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/lookup/") {
			_, _ = w.Write([]byte(`{"proofs":["` + hash + `"],"truncated":false}`))
			return
		}
		_, _ = w.Write([]byte("corrupt body"))
	}))
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/lookup/") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(proof)
	}))
	defer first.Close()
	defer second.Close()
	client, err := NewMulti([]string{first.URL, second.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Resolve(context.Background(), Token(hash)); err == nil || !strings.Contains(err.Error(), "lookup failed") {
		t.Fatalf("partial lookup set was accepted: %v", err)
	}
	resolved, err := client.Resolve(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resolved.Proof, proof) {
		t.Fatal("full-hash retrieval did not retry the next resolver")
	}
}

func TestNewMultiBoundsAndDeduplicatesResolvers(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, err := NewMulti([]string{server.URL, server.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(client.bases) != 1 {
		t.Fatalf("duplicate resolver count=%d, want 1", len(client.bases))
	}
	tooMany := make([]string, MaxResolvers+1)
	for i := range tooMany {
		tooMany[i] = server.URL
	}
	if _, err := NewMulti(tooMany); err == nil {
		t.Fatal("accepted resolver set above its bound")
	}
}

func TestMultiResolverFetchKeyRetriesAfterFingerprintMismatch(t *testing.T) {
	_, wantedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(key any) []byte {
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	wanted := encode(wantedPrivate.Public())
	wrong := encode(wrongPrivate.Public())
	wantedID, err := protocol.KeyID(wantedPrivate.Public())
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(wrong) }))
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(wanted) }))
	defer first.Close()
	defer second.Close()
	client, err := NewMulti([]string{first.URL, second.URL})
	if err != nil {
		t.Fatal(err)
	}
	fetched, err := client.FetchKey(context.Background(), hex.EncodeToString(wantedID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fetched, wanted) {
		t.Fatal("fetch did not retry after an invalid resolver response")
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
func contains(s, part string) bool {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
