package pixelqso

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mikroskeem/golang-blake2s"
	"github.com/tcarwash/arap/protocol"
)

var sharedPalettes = [][][]uint8{
	{{0, 0, 0}, {15, 15, 15}, {0, 0, 15}, {0, 15, 15}, {0, 15, 0}, {15, 15, 0}, {15, 0, 0}, {15, 0, 15}},
	makePalette([]uint8{0, 5, 10, 15}, []uint8{0, 15}, []uint8{0, 15}),
	makePalette([]uint8{0, 5, 10, 15}, []uint8{0, 5, 10, 15}, []uint8{0, 15}),
}

func makePalette(red, green, blue []uint8) [][]uint8 {
	colors := make([][]uint8, 0, len(red)*len(green)*len(blue))
	for _, r := range red {
		for _, g := range green {
			for _, b := range blue {
				colors = append(colors, []uint8{r, g, b})
			}
		}
	}
	return colors
}

// ArtworkDigest reproduces PixelQSO's BLAKE2s-64 frame-link fingerprint over
// shared-palette-quantized artwork and the callsign, card ID and dimensions.
func ArtworkDigest(card Card) ([8]byte, error) {
	var empty [8]byte
	if err := validateArtworkCard(card); err != nil {
		return empty, err
	}
	paletteIndex := map[int]int{8: 0, 16: 1, 32: 2}[len(card.Palette)]
	if len(card.Palette) != 8 && len(card.Palette) != 16 && len(card.Palette) != 32 {
		return empty, errors.New("PixelQSO animation artwork requires an 8, 16 or 32 color palette")
	}
	quantized := make([]byte, len(card.Pixels))
	target := sharedPalettes[paletteIndex]
	for i, pixel := range card.Pixels {
		color := card.Palette[pixel]
		closest, bestDistance := 0, int(^uint(0)>>1)
		for candidate, targetColor := range target {
			distance := 0
			for channel := 0; channel < 3; channel++ {
				delta := int(color[channel]) - int(targetColor[channel])
				distance += delta * delta
			}
			if distance < bestDistance { // first index wins ties, matching PixelQSO.
				closest, bestDistance = candidate, distance
			}
		}
		quantized[i] = byte(closest)
	}
	identity, err := json.Marshal([]any{strings.ToUpper(card.Callsign), card.CardID, card.Width, card.Height, len(target)})
	if err != nil {
		return empty, err
	}
	// encoding/json marshals []any as a compact array, matching json.dumps with
	// separators=(',', ':') for the ASCII-only PixelQSO identity tuple.
	hash, err := blake2s.New(8, nil)
	if err != nil {
		return empty, err
	}
	_, _ = hash.Write(identity)
	_, _ = hash.Write(quantized)
	sum := hash.Sum(nil)
	copy(empty[:], sum)
	return empty, nil
}

// ValidateAnimationPair confirms that second is PixelQSO's frame 2 and its
// stored first_digest names the supplied first card's shared-palette artwork.
func ValidateAnimationPair(first, second Card) error {
	if err := validateArtworkCard(first); err != nil {
		return fmt.Errorf("invalid first frame: %w", err)
	}
	if err := validateArtworkCard(second); err != nil {
		return fmt.Errorf("invalid second frame: %w", err)
	}
	if second.Animation == nil {
		return errors.New("second PixelQSO card has no animation reference")
	}
	if first.Animation != nil {
		return errors.New("first PixelQSO card cannot itself be an animation frame 2")
	}
	if first.Callsign != second.Callsign {
		return errors.New("PixelQSO animation cards must have the same callsign")
	}
	if first.CardID != second.Animation.FirstCardID || first.CardID == second.CardID {
		return errors.New("PixelQSO animation first card ID does not match")
	}
	if first.Width != second.Width || first.Height != second.Height {
		return errors.New("PixelQSO animation cards must have matching dimensions")
	}
	digest, err := ArtworkDigest(first)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest[:], second.Animation.FirstDigest[:]) {
		return errors.New("PixelQSO animation first-card artwork fingerprint does not match")
	}
	return nil
}

func validateArtworkCard(card Card) error {
	call, err := protocol.NormalizeCallsign(card.Callsign)
	if err != nil || call != card.Callsign {
		return errors.New("PixelQSO animation callsign must be normalized uppercase ASCII")
	}
	if card.Width == 0 || card.Height == 0 || len(card.Pixels) != int(card.Width)*int(card.Height) {
		return errors.New("PixelQSO animation artwork has an invalid raster size")
	}
	if len(card.Palette) != 8 && len(card.Palette) != 16 && len(card.Palette) != 32 {
		return errors.New("PixelQSO animation artwork requires an 8, 16 or 32 color palette")
	}
	for i, color := range card.Palette {
		if len(color) != 3 || color[0] > 15 || color[1] > 15 || color[2] > 15 {
			return fmt.Errorf("PixelQSO animation palette entry %d is not RGB444", i)
		}
	}
	for i, pixel := range card.Pixels {
		if int(pixel) >= len(card.Palette) {
			return fmt.Errorf("PixelQSO animation pixel %d is outside its palette", i)
		}
	}
	return nil
}
