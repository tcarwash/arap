package main

import (
	"strings"
	"testing"

	"github.com/tcarwash/arap/keyserver"
)

func TestValidateUploadToken(t *testing.T) {
	for _, token := range []string{
		strings.Repeat("a", 32),
		strings.Repeat("a", 32) + "==",
		"0123456789abcdef0123456789abcdef",
	} {
		if err := keyserver.ValidateUploadToken(token); err != nil {
			t.Errorf("rejected valid bearer token %q: %v", token, err)
		}
	}
	for _, token := range []string{
		"",
		strings.Repeat("a", 31),
		strings.Repeat("a", 31) + "=",
		strings.Repeat("a", 32) + "===",
		strings.Repeat("a", 16) + "=" + strings.Repeat("a", 16),
		strings.Repeat("a", 31) + " ",
	} {
		if err := keyserver.ValidateUploadToken(token); err == nil {
			t.Errorf("accepted invalid upload token %q", token)
		}
	}
}

func TestServerOptionsFromEnvDefaultsAndOverrides(t *testing.T) {
	for _, name := range []string{"ARAP_MAX_PROOF_OBJECTS", "ARAP_MAX_KEY_OBJECTS", "ARAP_MAX_TOTAL_BYTES", "ARAP_MAX_UPLOADS_PER_MINUTE", "ARAP_RETENTION_DAYS"} {
		t.Setenv(name, "")
	}
	options, err := serverOptionsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if options.MaxProofObjects != 100_000 || options.MaxKeyObjects != 10_000 || options.MaxTotalBytes != 10<<30 || options.MaxUploadsPerMinute != 600 || options.Retention != 0 {
		t.Fatalf("unexpected defaults: %+v", options)
	}
	t.Setenv("ARAP_MAX_PROOF_OBJECTS", "42")
	t.Setenv("ARAP_MAX_KEY_OBJECTS", "24")
	t.Setenv("ARAP_MAX_TOTAL_BYTES", "4096")
	t.Setenv("ARAP_MAX_UPLOADS_PER_MINUTE", "12")
	t.Setenv("ARAP_RETENTION_DAYS", "7")
	options, err = serverOptionsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if options.MaxProofObjects != 42 || options.MaxKeyObjects != 24 || options.MaxTotalBytes != 4096 || options.MaxUploadsPerMinute != 12 || options.Retention.Hours() != 168 {
		t.Fatalf("unexpected configured options: %+v", options)
	}
}

func TestServerOptionsRejectInvalidLimits(t *testing.T) {
	for _, value := range []string{"0", "-1", "not-a-number"} {
		t.Setenv("ARAP_MAX_PROOF_OBJECTS", value)
		if _, err := serverOptionsFromEnv(); err == nil {
			t.Fatalf("accepted invalid limit %q", value)
		}
	}
	t.Setenv("ARAP_MAX_PROOF_OBJECTS", "")
	for _, value := range []string{"-1", "not-a-number"} {
		t.Setenv("ARAP_RETENTION_DAYS", value)
		if _, err := serverOptionsFromEnv(); err == nil {
			t.Fatalf("accepted invalid retention %q", value)
		}
	}
}
