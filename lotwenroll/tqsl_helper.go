package lotwenroll

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const tqslHelperMagic = "ARAPTQ1\n"

// TQSLHelperSigner invokes the optional native TQSLLIB helper. Passwords are
// sent only over its stdin framing and are never included in process arguments.
type TQSLHelperSigner struct {
	Path, Callsign, Serial string
	Directory              string
	Passphrase             []byte
	chain                  [][]byte
}

func (s *TQSLHelperSigner) run(challenge []byte) ([]byte, error) {
	if s == nil || s.Path == "" || s.Callsign == "" {
		return nil, errors.New("TQSL helper path and callsign are required")
	}
	if len(s.Passphrase) > 79 || len(challenge) == 0 || len(challenge) > 4096 {
		return nil, errors.New("TQSL password or challenge exceeds its size limit")
	}
	var input bytes.Buffer
	writeFrame := func(b []byte) { _ = binary.Write(&input, binary.LittleEndian, uint32(len(b))); _, _ = input.Write(b) }
	writeFrame(s.Passphrase)
	writeFrame(challenge)
	args := []string{"--callsign", s.Callsign, "--resource-directory", filepath.Dir(s.Path)}
	if s.Directory != "" {
		args = append(args, "--directory", s.Directory)
	}
	if s.Serial != "" {
		if _, err := strconv.ParseUint(s.Serial, 10, 64); err != nil {
			return nil, errors.New("TQSL certificate serial must be decimal")
		}
		args = append(args, "--serial", s.Serial)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Path, args...)
	cmd.Stdin = &input
	var output limitedBuffer
	cmd.Stdout = &output
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("TQSL helper timed out")
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			return nil, fmt.Errorf("TQSL helper failed: %w", err)
		}
		return nil, fmt.Errorf("TQSL helper failed: %s", message)
	}
	if output.exceeded {
		return nil, errors.New("TQSL helper output exceeds size limit")
	}
	return append([]byte(nil), output.Bytes()...), nil
}

func (s *TQSLHelperSigner) SignEnrollmentChallenge(challenge []byte) ([]byte, error) {
	data, err := s.run(challenge)
	if err != nil {
		return nil, err
	}
	sig, chain, err := decodeTQSLHelperOutput(data)
	if err != nil {
		return nil, err
	}
	s.chain = chain
	return sig, nil
}

func (s *TQSLHelperSigner) EnrollmentCertificateChain() ([][]byte, error) {
	if len(s.chain) == 0 {
		return nil, errors.New("TQSL helper has not returned a certificate chain")
	}
	chain := make([][]byte, len(s.chain))
	for i := range s.chain {
		chain[i] = append([]byte(nil), s.chain[i]...)
	}
	return chain, nil
}

func decodeTQSLHelperOutput(data []byte) ([]byte, [][]byte, error) {
	r := bytes.NewReader(data)
	magic := make([]byte, len(tqslHelperMagic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != tqslHelperMagic {
		return nil, nil, errors.New("invalid TQSL helper response header")
	}
	readFrame := func(limit uint32) ([]byte, error) {
		var n uint32
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
			return nil, err
		}
		if n == 0 || n > limit || uint64(n) > uint64(r.Len()) {
			return nil, errors.New("invalid TQSL helper frame length")
		}
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	sig, err := readFrame(1024)
	if err != nil {
		return nil, nil, fmt.Errorf("read TQSL signature: %w", err)
	}
	var count uint32
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil || count == 0 || count > 8 {
		return nil, nil, errors.New("invalid TQSL certificate count")
	}
	chain := make([][]byte, 0, count)
	total := 0
	for i := uint32(0); i < count; i++ {
		encoded, err := readFrame(MaxChainBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("read TQSL certificate %d: %w", i+1, err)
		}
		block, rest := pem.Decode(encoded)
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, nil, errors.New("TQSL helper returned invalid certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse TQSL certificate: %w", err)
		}
		_ = cert
		total += len(block.Bytes)
		if total > MaxChainBytes {
			return nil, nil, errors.New("TQSL certificate chain exceeds size limit")
		}
		chain = append(chain, append([]byte(nil), block.Bytes...))
	}
	if r.Len() != 0 {
		return nil, nil, errors.New("trailing bytes in TQSL helper response")
	}
	return sig, chain, nil
}

type limitedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	const limit = MaxResponse + 16*1024
	if b.Len()+len(p) > limit {
		b.exceeded = true
		return 0, errors.New("output limit exceeded")
	}
	return b.Buffer.Write(p)
}
