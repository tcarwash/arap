package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustStatusDistinguishesUnknownDisabledAndPurpose(t *testing.T) {
	store := TrustStore{Version: 1, Bindings: []Binding{}}
	if got := store.Status("AG7SU", "abc", "content-signature"); got != "untrusted" {
		t.Fatalf("unknown status=%q", got)
	}
	store.Add("AG7SU", "abc", []string{"content-signature"})
	if got := store.Status("AG7SU", "abc", "content-signature"); got != "trusted" {
		t.Fatalf("trusted status=%q", got)
	}
	if got := store.Status("AG7SU", "abc", "challenge-response"); got != "untrusted" {
		t.Fatalf("wrong-purpose status=%q", got)
	}
	if !store.Disable("AG7SU", "abc") {
		t.Fatal("binding was not found")
	}
	if got := store.Status("AG7SU", "abc", "content-signature"); got != "disabled" {
		t.Fatalf("disabled status=%q", got)
	}
}

func TestReaddingDisabledBindingRestoresOnlyRequestedPurposes(t *testing.T) {
	store := TrustStore{Version: 1, Bindings: []Binding{}}
	store.Add("AG7SU", "abc", []string{"content-signature", "challenge-response"})
	if !store.Disable("AG7SU", "abc") {
		t.Fatal("binding was not found for disable")
	}
	store.Add("AG7SU", "abc", []string{"content-signature"})
	if got := store.Status("AG7SU", "abc", "content-signature"); got != "trusted" {
		t.Fatalf("requested purpose status=%q, want trusted", got)
	}
	if got := store.Status("AG7SU", "abc", "challenge-response"); got != "untrusted" {
		t.Fatalf("unrequested purpose status=%q, want untrusted", got)
	}
	if len(store.Bindings) != 1 || len(store.Bindings[0].Purposes) != 1 || store.Bindings[0].Purposes[0] != "content-signature" {
		t.Fatalf("re-enabled purposes=%v, want only content-signature", store.Bindings)
	}
}

func TestDisabledTrustBindingOverridesDuplicates(t *testing.T) {
	store := TrustStore{Version: 1, Bindings: []Binding{
		{Callsign: "AG7SU", KeyID: "abc", Purposes: []string{"content-signature"}},
		{Callsign: "AG7SU", KeyID: "abc", Purposes: []string{"challenge-response"}, Disabled: true},
	}}
	if got := store.Status("AG7SU", "abc", "content-signature"); got != "disabled" {
		t.Fatalf("disabled duplicate binding status=%q", got)
	}
	if got := store.Status("AG7SU", "abc", "challenge-response"); got != "disabled" {
		t.Fatalf("disabled key status for another purpose=%q", got)
	}
	if !store.Disable("AG7SU", "abc") {
		t.Fatal("duplicate binding was not found")
	}
	for i, binding := range store.Bindings {
		if !binding.Disabled {
			t.Fatalf("binding %d remained enabled after disable", i)
		}
	}
}

func TestLoadTrustRejectsDuplicateJSONAndBindings(t *testing.T) {
	keyID := strings.Repeat("a", 64)
	for _, body := range []string{
		`{"version":1,"version":1,"bindings":[]}`,
		fmt.Sprintf(`{"version":1,"bindings":[{"callsign":"AG7SU","key_id_sha256":%q,"purposes":["content-signature"],"disabled":true,"disabled":false}]}`, keyID),
		fmt.Sprintf(`{"version":1,"bindings":[{"callsign":"AG7SU","key_id_sha256":%q,"purposes":["content-signature"]},{"callsign":"AG7SU","key_id_sha256":%q,"purposes":["content-signature"],"disabled":true}]}`, keyID, keyID),
	} {
		path := filepath.Join(t.TempDir(), "trust.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrust(path); err == nil {
			t.Fatalf("accepted ambiguous trust store: %s", body)
		}
	}
}

func TestLoadTrustRejectsInvalidBindings(t *testing.T) {
	keyID := strings.Repeat("a", 64)
	for _, binding := range []string{
		fmt.Sprintf(`{"callsign":"ag7su","key_id_sha256":%q,"purposes":["content-signature"]}`, keyID),
		`{"callsign":"AG7SU","key_id_sha256":"bad","purposes":["content-signature"]}`,
		fmt.Sprintf(`{"callsign":"AG7SU","key_id_sha256":%q,"purposes":["future-purpose"]}`, keyID),
		fmt.Sprintf(`{"callsign":"AG7SU","key_id_sha256":%q,"purposes":[]}`, keyID),
		fmt.Sprintf(`{"callsign":"AG7SU","key_id_sha256":%q,"purposes":["content-signature","content-signature"]}`, keyID),
	} {
		path := filepath.Join(t.TempDir(), "trust.json")
		body := `{"version":1,"bindings":[` + binding + `]}`
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrust(path); err == nil {
			t.Fatalf("accepted invalid trust binding: %s", binding)
		}
	}
}

func TestLoadTrustRequiresBindingsArray(t *testing.T) {
	for _, body := range []string{`{"version":1}`, `{"version":1,"bindings":null}`} {
		path := filepath.Join(t.TempDir(), "trust.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadTrust(path); err == nil {
			t.Fatalf("accepted trust store without bindings array: %s", body)
		}
	}
}

func TestLoadTrustRejectsExcessiveJSONNesting(t *testing.T) {
	body := `{"version":1,"bindings":[],"nested":` + strings.Repeat("[", 20) + `0` + strings.Repeat("]", 20) + `}`
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTrust(path); err == nil {
		t.Fatal("accepted trust store beyond JSON nesting limit")
	}
}
