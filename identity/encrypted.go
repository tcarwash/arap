package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	privateAgeWorkFactor    = 15
	privateAgeMaxWorkFactor = 18
)

var ErrPassphraseRequired = errors.New("encrypted private key requires a passphrase")

// EncryptPrivate stores PKCS#8 Ed25519 DER in the standard age armored file
// format, encrypted to a passphrase with age's scrypt recipient.
func EncryptPrivate(private ed25519.PrivateKey, passphrase []byte) ([]byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key")
	}
	if len(passphrase) < 12 {
		return nil, fmt.Errorf("passphrase must contain at least 12 bytes")
	}
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(privateAgeWorkFactor)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	defer clearBytes(der)
	var output bytes.Buffer
	armored := armor.NewWriter(&output)
	encrypted, err := age.Encrypt(armored, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := encrypted.Write(der); err != nil {
		_ = encrypted.Close()
		_ = armored.Close()
		return nil, err
	}
	if err := encrypted.Close(); err != nil {
		_ = armored.Close()
		return nil, err
	}
	if err := armored.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

// LoadPrivateWithPassphrase loads a standard age-encrypted key or a legacy
// unencrypted PKCS#8 key.
func LoadPrivateWithPassphrase(path string, passphrase []byte) (ed25519.PrivateKey, error) {
	data, err := readPrivateBounded(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte(armor.Header)) {
		return decryptAge(data, passphrase)
	}
	block, err := decodeOnePEMBlock(data)
	if err != nil || block == nil {
		return nil, fmt.Errorf("expected one PKCS#8 or armored encrypted private-key file")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return parseEd25519Private(block.Bytes)
	default:
		return nil, fmt.Errorf("expected one PKCS#8 or armored encrypted private-key file")
	}
}

func decryptAge(data, passphrase []byte) (ed25519.PrivateKey, error) {
	if len(passphrase) == 0 {
		return nil, ErrPassphraseRequired
	}
	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, err
	}
	identity.SetMaxWorkFactor(privateAgeMaxWorkFactor)
	reader, err := age.Decrypt(armor.NewReader(bytes.NewReader(data)), identity)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt private key (incorrect passphrase or damaged file)")
	}
	der, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt private key (incorrect passphrase or damaged file)")
	}
	defer clearBytes(der)
	if len(der) > 4096 {
		return nil, fmt.Errorf("decrypted private key exceeds size limit")
	}
	return parseEd25519Private(der)
}

func clearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func parseEd25519Private(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return private, nil
}

func readPrivateBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := checkPrivateFileMode(f, path); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64*1024 {
		return nil, fmt.Errorf("%s exceeds %d byte limit", path, 64*1024)
	}
	return data, nil
}

func GenerateEncryptedKeyPair(privatePath, publicPath string, passphrase []byte) error {
	if privatePath == publicPath {
		return fmt.Errorf("private and public key paths must differ")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privateArmored, err := EncryptPrivate(private, passphrase)
	if err != nil {
		return err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return err
	}
	if err := WriteExclusive(privatePath, privateArmored, 0600); err != nil {
		return err
	}
	if err := WriteExclusive(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0644); err != nil {
		_ = os.Remove(privatePath)
		return err
	}
	return nil
}
