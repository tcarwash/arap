// Package pixelqso converts saved PixelQSO card JSON into a versioned,
// deterministic byte sequence suitable for ARAP content proofs.
package pixelqso

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/tcarwash/arap/protocol"
)

const (
	MediaType     = "application/vnd.pixelqso.card+cbor"
	Context       = "pixelqso/card-v1"
	MaxJSON       = 1024 * 1024
	MaxJSONDepth  = 16
	MaxJSONValues = 250_000
)

// Card is the authenticated subset of a PixelQSO saved-card document.
// Editor layers and local receipt/archive metadata are intentionally excluded.
type Card struct {
	Callsign  string
	Grid      string
	CardID    uint16
	Width     uint8
	Height    uint8
	Palette   [][]uint8
	Pixels    []uint8
	Animation *Animation
}

type Animation struct {
	FirstCardID uint16
	FirstDigest [8]byte
	FrameMS     uint16
}

// CanonicalizeJSON validates a saved PixelQSO card and returns its canonical
// ARAP CBOR representation. Known editor-local fields are ignored; unknown
// fields are rejected so new card semantics require an explicit profile update.
func CanonicalizeJSON(data []byte) ([]byte, Card, error) {
	if len(data) == 0 || len(data) > MaxJSON {
		return nil, Card{}, fmt.Errorf("PixelQSO card JSON must be 1..%d bytes", MaxJSON)
	}
	value, err := decodeJSON(data)
	if err != nil {
		return nil, Card{}, fmt.Errorf("invalid PixelQSO card JSON: %w", err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, Card{}, errors.New("PixelQSO card JSON must be an object")
	}
	if err := checkFields(object); err != nil {
		return nil, Card{}, err
	}
	card, err := parseCard(object)
	if err != nil {
		return nil, Card{}, err
	}
	encoded, err := protocol.EncodeCanonical(cardValue(card))
	if err != nil {
		return nil, Card{}, fmt.Errorf("encode canonical PixelQSO card: %w", err)
	}
	return encoded, card, nil
}

func checkFields(object map[string]any) error {
	for key := range object {
		switch key {
		case "format", "version", "callsign", "grid", "card_id", "width", "height", "palette", "pixels", "animation",
			"base_pixels", "stamp_layers", "archive_reason", "copied_from", "reception_report":
		default:
			return fmt.Errorf("unsupported PixelQSO card field %q", key)
		}
	}
	if value, exists := object["format"]; exists {
		format, ok := value.(string)
		if !ok || format != "pixel-qso-card" {
			return errors.New("unsupported PixelQSO card format")
		}
	}
	if version, exists := object["version"]; exists {
		v, err := integer(version, "version", 1, 1)
		if err != nil || v != 1 {
			return errors.New("unsupported PixelQSO card version")
		}
	}
	return nil
}

func parseCard(object map[string]any) (Card, error) {
	var card Card
	call, ok := object["callsign"].(string)
	if !ok {
		return card, errors.New("PixelQSO card callsign must be text")
	}
	card.Callsign, _ = protocol.NormalizeCallsign(call)
	if card.Callsign == "" {
		return card, errors.New("PixelQSO card callsign is invalid")
	}
	if card.Callsign != call {
		return card, errors.New("PixelQSO card callsign must be normalized uppercase ASCII")
	}
	grid, ok := object["grid"].(string)
	if !ok || len(grid) > 8 || !ascii(grid) || strings.ToUpper(grid) != grid {
		return card, errors.New("PixelQSO card grid must be uppercase ASCII text of at most 8 bytes")
	}
	card.Grid = grid
	value, ok := object["card_id"]
	if !ok {
		return card, errors.New("PixelQSO card card_id is required")
	}
	id, err := integer(value, "card_id", 0, 65535)
	if err != nil {
		return card, err
	}
	card.CardID = uint16(id)
	value, ok = object["width"]
	if !ok {
		return card, errors.New("PixelQSO card width is required")
	}
	width, err := integer(value, "width", 1, 255)
	if err != nil {
		return card, err
	}
	value, ok = object["height"]
	if !ok {
		return card, errors.New("PixelQSO card height is required")
	}
	height, err := integer(value, "height", 1, 255)
	if err != nil {
		return card, err
	}
	card.Width, card.Height = uint8(width), uint8(height)

	paletteValue, ok := object["palette"].([]any)
	if !ok || (len(paletteValue) != 2 && len(paletteValue) != 8 && len(paletteValue) != 16 && len(paletteValue) != 32) {
		return card, errors.New("PixelQSO card palette must have 2, 8, 16 or 32 RGB444 entries")
	}
	card.Palette = make([][]uint8, len(paletteValue))
	for i, entry := range paletteValue {
		channels, ok := entry.([]any)
		if !ok || len(channels) != 3 {
			return card, fmt.Errorf("palette entry %d must be an RGB444 triple", i)
		}
		card.Palette[i] = make([]uint8, 3)
		for j, channel := range channels {
			v, err := integer(channel, "palette channel", 0, 15)
			if err != nil {
				return card, fmt.Errorf("palette entry %d: %w", i, err)
			}
			card.Palette[i][j] = uint8(v)
		}
	}
	pixels, ok := object["pixels"].([]any)
	if !ok || len(pixels) != int(width*height) {
		return card, fmt.Errorf("PixelQSO card pixels must contain exactly %d row-major indices", width*height)
	}
	card.Pixels = make([]uint8, len(pixels))
	for i, pixel := range pixels {
		v, err := integer(pixel, "pixel index", 0, int64(len(card.Palette)-1))
		if err != nil {
			return card, fmt.Errorf("pixel %d: %w", i, err)
		}
		card.Pixels[i] = uint8(v)
	}
	if value, exists := object["animation"]; exists && value != nil {
		animation, err := parseAnimation(value, card.CardID)
		if err != nil {
			return card, err
		}
		card.Animation = &animation
	}
	return card, nil
}

func parseAnimation(value any, ownID uint16) (Animation, error) {
	var result Animation
	object, ok := value.(map[string]any)
	if !ok {
		return result, errors.New("PixelQSO animation must be an object or null")
	}
	for key := range object {
		if key != "first_card_id" && key != "first_digest" && key != "frame_ms" {
			return result, fmt.Errorf("unsupported PixelQSO animation field %q", key)
		}
	}
	value, ok = object["first_card_id"]
	if !ok {
		return result, errors.New("animation first_card_id is required")
	}
	id, err := integer(value, "animation first_card_id", 0, 65535)
	if err != nil {
		return result, err
	}
	if uint16(id) == ownID {
		return result, errors.New("animation frames must have different card IDs")
	}
	result.FirstCardID = uint16(id)
	digest, ok := object["first_digest"].(string)
	if !ok || len(digest) != 16 {
		return result, errors.New("animation first_digest must be 16 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 8 {
		return result, errors.New("animation first_digest must encode 8 bytes")
	}
	copy(result.FirstDigest[:], decoded)
	frameMS := int64(500)
	if value, exists := object["frame_ms"]; exists {
		frameMS, err = integer(value, "animation frame_ms", 100, 10000)
		if err != nil {
			return result, err
		}
	}
	result.FrameMS = uint16(frameMS)
	return result, nil
}

func cardValue(card Card) map[uint64]any {
	palette := make([]any, len(card.Palette))
	for i, entry := range card.Palette {
		palette[i] = []any{uint64(entry[0]), uint64(entry[1]), uint64(entry[2])}
	}
	pixels := make([]any, len(card.Pixels))
	for i, pixel := range card.Pixels {
		pixels[i] = uint64(pixel)
	}
	result := map[uint64]any{
		1: uint64(1), 2: card.Callsign, 3: card.Grid, 4: uint64(card.CardID),
		5: uint64(card.Width), 6: uint64(card.Height), 7: palette, 8: pixels,
	}
	if card.Animation != nil {
		result[9] = map[uint64]any{1: uint64(card.Animation.FirstCardID), 2: card.Animation.FirstDigest[:], 3: uint64(card.Animation.FrameMS)}
	}
	return result
}

func integer(value any, name string, minimum, maximum int64) (int64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	parsed, err := strconv.ParseInt(string(number), 10, 64)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be in %d..%d", name, minimum, maximum)
	}
	return parsed, nil
}

func ascii(value string) bool {
	for i := range value {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func decodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	state := jsonReadState{}
	value, err := readJSONValue(decoder, &state, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

type jsonReadState struct{ values int }

func readJSONValue(decoder *json.Decoder, state *jsonReadState, depth int) (any, error) {
	state.values++
	if state.values > MaxJSONValues {
		return nil, fmt.Errorf("PixelQSO card JSON exceeds the %d value limit", MaxJSONValues)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			if depth >= MaxJSONDepth {
				return nil, fmt.Errorf("PixelQSO card JSON exceeds the nesting limit of %d", MaxJSONDepth)
			}
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key must be text")
				}
				if _, duplicate := object[key]; duplicate {
					return nil, fmt.Errorf("duplicate JSON field %q", key)
				}
				child, err := readJSONValue(decoder, state, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return object, nil
		case '[':
			if depth >= MaxJSONDepth {
				return nil, fmt.Errorf("PixelQSO card JSON exceeds the nesting limit of %d", MaxJSONDepth)
			}
			array := make([]any, 0)
			for decoder.More() {
				child, err := readJSONValue(decoder, state, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return array, nil
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter %q", value)
		}
	default:
		return token, nil
	}
}
