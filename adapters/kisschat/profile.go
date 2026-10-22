// Package kisschat implements the KISSChat-message-v1 ARAP content profile.
package kisschat

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MediaType = "application/vnd.kisschat.message+json"
	Context   = "kisschat/message-v1"
	MaxBody   = 4096
	MaxNick   = 16
	MaxImage  = 8192
	MaxEdge   = 160
)

var (
	originPattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	channelPattern  = regexp.MustCompile(`^#[A-Za-z0-9_-]{1,31}$`)
	callsignPattern = regexp.MustCompile(`^[A-Z0-9]+(?:/[A-Z0-9]+)*$`)
)

// Image contains the signed metadata for a JPEG thumbnail.
type Image struct {
	SHA256 string
	Size   uint32
	Width  uint16
	Height uint16
}

// Message contains exactly the application fields authenticated by ARAP.
type Message struct {
	Origin    string
	Sequence  uint32
	Timestamp uint32
	Channel   string
	Nick      string
	Callsign  string
	Body      string
	Image     *Image
}

// Canonicalize validates a message and returns its profile-defined UTF-8 JSON.
func Canonicalize(m Message) ([]byte, error) {
	if !originPattern.MatchString(m.Origin) {
		return nil, errors.New("invalid KISSChat origin UUID")
	}
	if m.Sequence == 0 {
		return nil, errors.New("KISSChat sequence must be nonzero")
	}
	if !channelPattern.MatchString(m.Channel) {
		return nil, errors.New("invalid KISSChat channel")
	}
	if !validText(m.Nick, true) || len([]byte(m.Nick)) > MaxNick {
		return nil, errors.New("invalid KISSChat nick")
	}
	if len(m.Callsign) < 3 || len(m.Callsign) > 20 ||
		!callsignPattern.MatchString(m.Callsign) ||
		!strings.ContainsAny(m.Callsign, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") ||
		!strings.ContainsAny(m.Callsign, "0123456789") {
		return nil, errors.New("invalid KISSChat signing callsign")
	}
	if !validText(m.Body, false) || len([]byte(m.Body)) > MaxBody {
		return nil, errors.New("invalid KISSChat body")
	}
	if m.Body == "" && m.Image == nil {
		return nil, errors.New("KISSChat message needs text or a thumbnail")
	}
	content := map[string]any{
		"body": m.Body, "callsign": m.Callsign, "channel": m.Channel,
		"nick": m.Nick, "origin": m.Origin, "sequence": m.Sequence,
		"timestamp": m.Timestamp, "version": 1,
	}
	if m.Image != nil {
		if len(m.Image.SHA256) != 64 {
			return nil, errors.New("invalid KISSChat thumbnail SHA-256")
		}
		if _, err := hex.DecodeString(m.Image.SHA256); err != nil || strings.ToLower(m.Image.SHA256) != m.Image.SHA256 {
			return nil, errors.New("invalid KISSChat thumbnail SHA-256")
		}
		if m.Image.Size == 0 || m.Image.Size > MaxImage || m.Image.Width == 0 || m.Image.Width > MaxEdge || m.Image.Height == 0 || m.Image.Height > MaxEdge {
			return nil, errors.New("invalid KISSChat thumbnail dimensions or size")
		}
		content["image"] = map[string]any{
			"height": m.Image.Height, "media_type": "image/jpeg",
			"sha256": m.Image.SHA256, "size": m.Image.Size, "width": m.Image.Width,
		}
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(content); err != nil {
		return nil, fmt.Errorf("encode KISSChat message profile: %w", err)
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

func validText(value string, nick bool) bool {
	if !utf8.ValidString(value) || (nick && value == "") {
		return false
	}
	for _, r := range value {
		if r == '\t' || (!nick && r == '\n') {
			continue
		}
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
