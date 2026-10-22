package kisschat

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vectorManifest struct {
	Vectors []struct {
		Name    string `json:"name"`
		Message struct {
			Origin    string `json:"o"`
			Sequence  uint32 `json:"s"`
			Timestamp uint32 `json:"ts"`
			Channel   string `json:"c"`
			Nick      string `json:"n"`
			Body      string `json:"b"`
			Image     *struct {
				Digest string `json:"digest"`
				Size   uint32 `json:"size"`
				Width  uint16 `json:"width"`
				Height uint16 `json:"height"`
			} `json:"image"`
		} `json:"message"`
		Callsign  string `json:"signing_callsign"`
		Canonical string `json:"canonical"`
	} `json:"vectors"`
}

func TestSharedKISSChatGoldenVectors(t *testing.T) {
	path := filepath.Join("..", "..", "test-vectors", "kisschat-message-v1", "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Python/Go shared vectors: %v", err)
	}
	var manifest vectorManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, vector := range manifest.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			m := Message{Origin: vector.Message.Origin, Sequence: vector.Message.Sequence,
				Timestamp: vector.Message.Timestamp, Channel: vector.Message.Channel,
				Nick: vector.Message.Nick, Callsign: vector.Callsign, Body: vector.Message.Body}
			if vector.Message.Image != nil {
				m.Image = &Image{SHA256: vector.Message.Image.Digest, Size: vector.Message.Image.Size,
					Width: vector.Message.Image.Width, Height: vector.Message.Image.Height}
			}
			got, err := Canonicalize(m)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != vector.Canonical {
				t.Fatalf("canonical bytes differ\n got: %s\nwant: %s", got, vector.Canonical)
			}
		})
	}
}

func TestRejectsInvalidKISSChatProfileValues(t *testing.T) {
	base := Message{Origin: "0123456789abcdef0123456789abcdef", Sequence: 1,
		Timestamp: 1, Channel: "#test", Nick: "AG7SU", Callsign: "AG7SU", Body: "hello"}
	cases := []struct {
		name string
		edit func(*Message)
	}{
		{"zero sequence", func(m *Message) { m.Sequence = 0 }},
		{"bad UUID", func(m *Message) { m.Origin = "AG7SU" }},
		{"bad channel", func(m *Message) { m.Channel = "test" }},
		{"missing callsign digit", func(m *Message) { m.Callsign = "CALL" }},
		{"oversize body", func(m *Message) { m.Body = strings.Repeat("x", MaxBody+1) }},
		{"empty text without image", func(m *Message) { m.Body = "" }},
		{"bad image digest", func(m *Message) { m.Image = &Image{SHA256: "x", Size: 1, Width: 1, Height: 1} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := base
			tc.edit(&m)
			if _, err := Canonicalize(m); err == nil {
				t.Fatal("invalid profile value accepted")
			}
		})
	}
}

func TestMaximumBodyBoundaryVector(t *testing.T) {
	m := Message{Origin: "ffffffffffffffffffffffffffffffff", Sequence: ^uint32(0),
		Timestamp: ^uint32(0), Channel: "#max", Nick: "AG7SU", Callsign: "AG7SU",
		Body: string(bytesOf('x', MaxBody))}
	canonical, err := Canonicalize(m)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(canonical)); got != "51a6f895db1df564aae0ba7ed0858f1b2b35a8616a2cdb1eb09c62216a33cf6e" {
		t.Fatalf("maximum-body vector digest %s", got)
	}
}

func bytesOf(value byte, count int) []byte {
	data := make([]byte, count)
	for i := range data {
		data[i] = value
	}
	return data
}
