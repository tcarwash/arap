package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/tcarwash/arap/protocol"
)

type Binding struct {
	Callsign string   `json:"callsign"`
	KeyID    string   `json:"key_id_sha256"`
	Purposes []string `json:"purposes"`
	Disabled bool     `json:"disabled,omitempty"`
}
type TrustStore struct {
	Version  int       `json:"version"`
	Bindings []Binding `json:"bindings"`
}

func LoadTrust(path string) (TrustStore, error) {
	var store TrustStore
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return TrustStore{Version: 1, Bindings: []Binding{}}, nil
	}
	if err != nil {
		return store, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return store, err
	}
	if len(b) > 1024*1024 {
		return store, fmt.Errorf("trust store exceeds 1 MiB limit")
	}
	if err := rejectDuplicateJSONKeys(b); err != nil {
		return store, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&store); err != nil {
		return store, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return store, fmt.Errorf("trust store must contain exactly one JSON object")
	}
	if store.Version != 1 {
		return store, fmt.Errorf("unsupported trust-store version")
	}
	if store.Bindings == nil {
		return store, fmt.Errorf("trust-store bindings must be an array")
	}
	if err := validateTrustStore(store); err != nil {
		return TrustStore{}, err
	}
	return store, nil
}

func validateTrustStore(store TrustStore) error {
	if store.Version != 1 {
		return fmt.Errorf("unsupported trust-store version")
	}
	if store.Bindings == nil {
		return fmt.Errorf("trust-store bindings must be an array")
	}
	seenBindings := make(map[string]struct{}, len(store.Bindings))
	for _, binding := range store.Bindings {
		call, err := protocol.NormalizeCallsign(binding.Callsign)
		if err != nil || call != binding.Callsign {
			return fmt.Errorf("trust store contains an invalid or non-normalized callsign")
		}
		fingerprint, err := hex.DecodeString(binding.KeyID)
		if err != nil || len(fingerprint) != 32 || hex.EncodeToString(fingerprint) != binding.KeyID {
			return fmt.Errorf("trust store contains an invalid key fingerprint")
		}
		bindingKey := binding.Callsign + "\x00" + binding.KeyID
		if _, exists := seenBindings[bindingKey]; exists {
			return fmt.Errorf("trust store contains duplicate callsign/key binding")
		}
		seenBindings[bindingKey] = struct{}{}

		if !binding.Disabled && len(binding.Purposes) == 0 {
			return fmt.Errorf("enabled trust binding must authorize at least one purpose")
		}
		seenPurposes := make(map[string]struct{}, len(binding.Purposes))
		for _, purpose := range binding.Purposes {
			if purpose != "content-signature" && purpose != "challenge-response" {
				return fmt.Errorf("trust store contains an unsupported purpose")
			}
			if _, exists := seenPurposes[purpose]; exists {
				return fmt.Errorf("trust store contains a duplicate purpose")
			}
			seenPurposes[purpose] = struct{}{}
		}
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trust store must contain exactly one JSON value")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return fmt.Errorf("trust store exceeds JSON nesting limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("trust-store object has a non-text key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("trust store contains duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("trust store has an unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("trust store has an unterminated JSON array")
		}
	default:
		return fmt.Errorf("trust store has an unexpected JSON delimiter")
	}
	return nil
}

func (s TrustStore) Allows(callsign, keyID, purpose string) bool {
	return s.Status(callsign, keyID, purpose) == "trusted"
}

// Status distinguishes an explicitly disabled binding from an unknown or
// purpose-mismatched key. Only "trusted" authorizes an operation.
func (s TrustStore) Status(callsign, keyID, purpose string) string {
	disabled := false
	trusted := false
	for _, b := range s.Bindings {
		if b.Callsign == callsign && b.KeyID == keyID {
			disabled = disabled || b.Disabled
			for _, p := range b.Purposes {
				if p == purpose {
					trusted = trusted || !b.Disabled
				}
			}
		}
	}
	if disabled {
		return "disabled"
	}
	if trusted {
		return "trusted"
	}
	return "untrusted"
}

func (s *TrustStore) Add(callsign, keyID string, purposes []string) {
	for i := range s.Bindings {
		if s.Bindings[i].Callsign == callsign && s.Bindings[i].KeyID == keyID {
			if s.Bindings[i].Disabled {
				// Re-enabling is a fresh authorization decision. Restore only the
				// purpose set that the caller explicitly selected.
				s.Bindings[i].Purposes = unique(purposes)
			} else {
				s.Bindings[i].Purposes = unique(append(s.Bindings[i].Purposes, purposes...))
			}
			s.Bindings[i].Disabled = false
			return
		}
	}
	s.Bindings = append(s.Bindings, Binding{Callsign: callsign, KeyID: keyID, Purposes: unique(purposes)})
}

func (s *TrustStore) Disable(callsign, keyID string) bool {
	found := false
	for i := range s.Bindings {
		if s.Bindings[i].Callsign == callsign && s.Bindings[i].KeyID == keyID {
			s.Bindings[i].Disabled = true
			found = true
		}
	}
	return found
}

func SaveTrust(path string, store TrustStore) error {
	store.Version = 1
	if store.Bindings == nil {
		store.Bindings = []Binding{}
	}
	if err := validateTrustStore(store); err != nil {
		return err
	}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".arap-trust-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		defer dir.Close()
		_ = dir.Sync()
	}
	return nil
}

func unique(v []string) []string {
	m := map[string]bool{}
	for _, p := range v {
		m[p] = true
	}
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
