package pixelqso

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleCard() string {
	return `{"format":"pixel-qso-card","version":1,"callsign":"AG7SU","grid":"CN85","card_id":12,"width":2,"height":2,"palette":[[0,0,0],[15,15,15]],"pixels":[0,1,1,0],"animation":null,"base_pixels":[0,1,1,0],"stamp_layers":[]}`
}

func TestIndependentPixelQSOCanonicalVector(t *testing.T) {
	base := filepath.Join("..", "..", "test-vectors", "pixelqso-card-v1")
	firstInput, err := os.ReadFile(filepath.Join(base, "first-card.json"))
	if err != nil {
		t.Fatal(err)
	}
	firstWant, err := os.ReadFile(filepath.Join(base, "first.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, first, err := CanonicalizeJSON(firstInput)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstBytes, firstWant) {
		t.Fatalf("first-frame canonical card differs from Python vector\n got %x\nwant %x", firstBytes, firstWant)
	}
	input, err := os.ReadFile(filepath.Join(base, "card.json"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(base, "canonical.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	got, second, err := CanonicalizeJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical card differs from Python vector\n got %x\nwant %x", got, want)
	}
	digest, err := ArtworkDigest(first)
	if err != nil {
		t.Fatal(err)
	}
	if digest != second.Animation.FirstDigest {
		t.Fatalf("PixelQSO artwork digest mismatch: got %x, card has %x", digest, second.Animation.FirstDigest)
	}
	if err := ValidateAnimationPair(first, second); err != nil {
		t.Fatalf("Python-generated frame pair rejected: %v", err)
	}
	first.Pixels[0] = (first.Pixels[0] + 1) % uint8(len(first.Palette))
	if err := ValidateAnimationPair(first, second); err == nil {
		t.Fatal("accepted frame 2 after its linked first-frame art changed")
	}
}

func TestCanonicalizeIgnoresJSONLayoutAndEditorState(t *testing.T) {
	first, card, err := CanonicalizeJSON([]byte(sampleCard()))
	if err != nil {
		t.Fatal(err)
	}
	secondJSON := `{
 "stamp_layers": [{"anything":"local editor state"}], "pixels": [0,1,1,0],
 "height":2,"palette":[[0,0,0],[15,15,15]],"grid":"CN85",
 "callsign":"AG7SU","card_id":12,"width":2,"base_pixels":[1,1,1,1]
}`
	second, _, err := CanonicalizeJSON([]byte(secondJSON))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("JSON whitespace, key order, or editor state changed canonical card bytes")
	}
	if card.Callsign != "AG7SU" || card.CardID != 12 || card.Width != 2 || len(card.Pixels) != 4 {
		t.Fatalf("unexpected parsed card: %#v", card)
	}
}

func TestCanonicalizeBindsSemanticCardChanges(t *testing.T) {
	base, _, err := CanonicalizeJSON([]byte(sampleCard()))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, from, to string }{
		{"pixel", `"pixels":[0,1,1,0]`, `"pixels":[0,1,0,0]`},
		{"palette order", `"palette":[[0,0,0],[15,15,15]]`, `"palette":[[15,15,15],[0,0,0]]`},
		{"grid", `"grid":"CN85"`, `"grid":"CN86"`},
		{"card id", `"card_id":12`, `"card_id":13`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed, _, err := CanonicalizeJSON([]byte(strings.Replace(sampleCard(), tc.from, tc.to, 1)))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(base, changed) {
				t.Fatal("semantic card change did not change canonical bytes")
			}
		})
	}
}

func TestCanonicalizeAnimationAndDefaultTiming(t *testing.T) {
	json := strings.Replace(sampleCard(), `"animation":null`, `"animation":{"first_card_id":11,"first_digest":"0123456789abcdef"}`, 1)
	_, card, err := CanonicalizeJSON([]byte(json))
	if err != nil {
		t.Fatal(err)
	}
	if card.Animation == nil || card.Animation.FrameMS != 500 || card.Animation.FirstCardID != 11 || card.Animation.FirstDigest[0] != 1 {
		t.Fatalf("unexpected animation: %#v", card.Animation)
	}
	json = strings.Replace(json, `"first_card_id":11`, `"first_card_id":12`, 1)
	if _, _, err := CanonicalizeJSON([]byte(json)); err == nil {
		t.Fatal("accepted a self-referencing animation")
	}
}

func TestCanonicalizeRejectsAmbiguousOrInvalidCards(t *testing.T) {
	base := sampleCard()
	cases := []struct{ name, input string }{
		{"duplicate field", `{"callsign":"AG7SU","callsign":"W1XYZ"}`},
		{"unknown field", strings.TrimSuffix(base, "}") + `,"surprise":true}`},
		{"wrong version", strings.Replace(base, `"version":1`, `"version":2`, 1)},
		{"lowercase callsign", strings.Replace(base, `"callsign":"AG7SU"`, `"callsign":"ag7su"`, 1)},
		{"wrong pixel count", strings.Replace(base, `"pixels":[0,1,1,0]`, `"pixels":[0,1,1]`, 1)},
		{"out of range palette channel", strings.Replace(base, `[15,15,15]`, `[16,15,15]`, 1)},
		{"out of range pixel", strings.Replace(base, `"pixels":[0,1,1,0]`, `"pixels":[0,2,1,0]`, 1)},
		{"trailing JSON", base + ` {}`},
		{"animation bad digest", strings.Replace(base, `"animation":null`, `"animation":{"first_card_id":11,"first_digest":"bad"}`, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := CanonicalizeJSON([]byte(tc.input)); err == nil {
				t.Fatal("accepted invalid card")
			}
		})
	}
}

func TestCanonicalizeJSONSizeBound(t *testing.T) {
	if _, _, err := CanonicalizeJSON(bytes.Repeat([]byte(" "), MaxJSON+1)); err == nil {
		t.Fatal("accepted oversized card JSON")
	}
}

func TestCanonicalizeJSONDepthAndValueBounds(t *testing.T) {
	deep := `{"surprise":` + strings.Repeat("[", MaxJSONDepth) + "null" + strings.Repeat("]", MaxJSONDepth) + `}`
	if _, _, err := CanonicalizeJSON([]byte(deep)); err == nil || !strings.Contains(err.Error(), "nesting limit") {
		t.Fatalf("deeply nested JSON error=%v, want nesting-limit rejection", err)
	}
	maxRaster := strings.TrimSuffix(strings.Repeat("0,", 255*255), ",")
	maxCard := `{"format":"pixel-qso-card","version":1,"callsign":"AG7SU","grid":"","card_id":1,"width":255,"height":255,"palette":[[0,0,0],[15,15,15]],"pixels":[` + maxRaster + `],"base_pixels":[` + maxRaster + `]}`
	if _, _, err := CanonicalizeJSON([]byte(maxCard)); err != nil {
		t.Fatalf("maximum raster with full-size editor base_pixels was rejected: %v", err)
	}

	values := `{"stamp_layers":[` + strings.Repeat("0,", MaxJSONValues-1) + "0]," + strings.TrimPrefix(sampleCard(), "{")
	if _, _, err := CanonicalizeJSON([]byte(values)); err == nil || !strings.Contains(err.Error(), "value limit") {
		t.Fatalf("large JSON structure error=%v, want value-limit rejection", err)
	}
}

func FuzzCanonicalizeJSON(f *testing.F) {
	f.Add([]byte(sampleCard()))
	f.Add([]byte(`{"format":"pixel-qso-card","version":1,"callsign":"AG7SU","grid":"CN85","card_id":12,"width":2,"height":2,"palette":[[0,0,0],[15,15,15]],"pixels":[0,1,1,0]}`))
	f.Add([]byte(`{"callsign":"AG7SU","callsign":"W1XYZ"}`))
	f.Add([]byte(`{"animation":{"first_card_id":1,"first_digest":"0000000000000000","frame_ms":65535}}`))
	f.Add([]byte{0xff, 0x00, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxJSON {
			t.Skip()
		}
		_, _, _ = CanonicalizeJSON(data)
	})
}

func ExampleCanonicalizeJSON() {
	encoded, card, err := CanonicalizeJSON([]byte(sampleCard()))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s %s %t\n", card.Callsign, Context, len(encoded) > 0)
	// Output: AG7SU pixelqso/card-v1 true
}
