package protocol

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

var encodeMode cbor.EncMode
var decodeMode cbor.DecMode

func init() {
	var err error
	encodeMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decodeMode, err = (cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  8,
		MaxArrayElements: 16,
		MaxMapPairs:      32,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsAllowed,
		DefaultMapType:   reflect.TypeOf(map[uint64]any{}),
		IntDec:           cbor.IntDecConvertNone,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

func marshal(v any) ([]byte, error) { return encodeMode.Marshal(v) }

func unmarshal(data []byte, dst any) error {
	if len(data) == 0 {
		return fmt.Errorf("empty CBOR input")
	}
	if err := decodeMode.Unmarshal(data, dst); err != nil {
		return err
	}
	return nil
}

// EncodeCanonical encodes a value with RFC 8949 core deterministic ordering.
func EncodeCanonical(v any) ([]byte, error) { return marshal(v) }

// DecodeCanonical decodes one bounded item and requires its canonical bytes.
func DecodeCanonical(data []byte, dst any) error {
	if err := unmarshal(data, dst); err != nil {
		return err
	}
	return requireCanonical(data, dst)
}

func requireCanonical(data []byte, v any) error {
	b, err := marshal(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, b) {
		return fmt.Errorf("CBOR item is not core deterministic encoding")
	}
	return nil
}

func uintMap(v any, where string) (map[uint64]any, error) {
	m, ok := v.(map[uint64]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a map with unsigned integer labels", where)
	}
	return m, nil
}

func exactLabels(m map[uint64]any, required []uint64, optional ...uint64) error {
	allowed := make(map[uint64]bool, len(required)+len(optional))
	for _, k := range required {
		allowed[k] = true
		if _, ok := m[k]; !ok {
			return fmt.Errorf("missing required label %d", k)
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return fmt.Errorf("unknown label %d", k)
		}
	}
	return nil
}

func getText(m map[uint64]any, key uint64, name string, max int) (string, error) {
	v, ok := m[key].(string)
	if !ok {
		return "", fmt.Errorf("%s must be text", name)
	}
	if len(v) == 0 || len(v) > max {
		return "", fmt.Errorf("%s length must be 1..%d bytes", name, max)
	}
	return v, nil
}

func getBytes(m map[uint64]any, key uint64, name string, exact int) ([]byte, error) {
	v, ok := m[key].([]byte)
	if !ok {
		return nil, fmt.Errorf("%s must be a byte string", name)
	}
	if exact >= 0 && len(v) != exact {
		return nil, fmt.Errorf("%s must be %d bytes", name, exact)
	}
	return v, nil
}

func getUint(m map[uint64]any, key uint64, name string) (uint64, error) {
	v, ok := m[key].(uint64)
	if !ok {
		return 0, fmt.Errorf("%s must be an unsigned integer", name)
	}
	return v, nil
}

func getInt(m map[uint64]any, key uint64, name string) (int64, error) {
	switch v := m[key].(type) {
	case uint64:
		if v > uint64(^uint64(0)>>1) {
			return 0, fmt.Errorf("%s is out of range", name)
		}
		return int64(v), nil
	case int64:
		return v, nil
	default:
		return 0, fmt.Errorf("%s must be an integer", name)
	}
}
