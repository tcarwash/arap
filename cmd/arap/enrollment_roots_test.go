package main

import (
	"path/filepath"
	"testing"
)

func TestEnrollmentRootPathPriority(t *testing.T) {
	t.Setenv("TQSLDIR", filepath.Join("env", "tqsl"))

	got, err := enrollmentRootPath("explicit-roots.pem", filepath.Join("custom", "tqsl"))
	if err != nil || got != "explicit-roots.pem" {
		t.Fatalf("explicit root bundle should take precedence: path=%q err=%v", got, err)
	}

	got, err = enrollmentRootPath("", filepath.Join("custom", "tqsl"))
	want := filepath.Join("custom", "tqsl", "certs", "root")
	if err != nil || got != want {
		t.Fatalf("selected TQSL data directory root path = %q, want %q (err=%v)", got, want, err)
	}

	got, err = enrollmentRootPath("", "")
	want = filepath.Join("env", "tqsl", "certs", "root")
	if err != nil || got != want {
		t.Fatalf("TQSLDIR root path = %q, want %q (err=%v)", got, want, err)
	}
}
