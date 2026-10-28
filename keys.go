package runtime

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/camelliavv/license-contract"
)

// EncryptionKeyPair contains an X25519 private/public key pair.
type EncryptionKeyPair struct {
	Private []byte
	Public  []byte
}

// GenerateEncryptionKeyPair generates a new X25519 encryption key pair.
func GenerateEncryptionKeyPair() (EncryptionKeyPair, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return EncryptionKeyPair{}, err
	}
	return EncryptionKeyPair{Private: private.Bytes(), Public: private.PublicKey().Bytes()}, nil
}

// DeriveEncryptionKeyID derives the stable identifier for an X25519 public key.
func DeriveEncryptionKeyID(key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("invalid X25519 public key")
	}
	digest := sha256.Sum256(key)
	return "enc-" + hex.EncodeToString(digest[:8]), nil
}

// MarshalEncryptionPrivateKeyPEM encodes an X25519 private key as PKCS#8 PEM.
func MarshalEncryptionPrivateKeyPEM(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid X25519 private key")
	}
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseEncryptionPrivateKeyPEM decodes an X25519 private key from PEM.
func ParseEncryptionPrivateKeyPEM(raw []byte) ([]byte, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid X25519 private key PEM")
	}
	if block.Type == "X25519 PRIVATE KEY" && len(block.Bytes) == 32 {
		return append([]byte(nil), block.Bytes...), nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 private key PEM: %w", err)
	}
	private, ok := key.(*ecdh.PrivateKey)
	if !ok || private.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("PEM key is not X25519")
	}
	return append([]byte(nil), private.Bytes()...), nil
}

// MarshalEncryptionPublicKeyPEM encodes an X25519 public key as PKIX PEM.
func MarshalEncryptionPublicKeyPEM(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid X25519 public key")
	}
	public, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParseEncryptionPublicKeyPEM decodes an X25519 public key from PEM.
func ParseEncryptionPublicKeyPEM(raw []byte) ([]byte, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid X25519 public key PEM")
	}
	if block.Type == "X25519 PUBLIC KEY" && len(block.Bytes) == 32 {
		return append([]byte(nil), block.Bytes...), nil
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key PEM: %w", err)
	}
	public, ok := key.(*ecdh.PublicKey)
	if !ok || public.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("PEM key is not X25519")
	}
	return append([]byte(nil), public.Bytes()...), nil
}

// ParsePublicKeyPEM decodes an Ed25519 public key from PEM.
func ParsePublicKeyPEM(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("public key is not PEM encoded")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("PEM key is not Ed25519")
	}
	return public, nil
}

// DecodePublicKey decodes a base64url-encoded Ed25519 public key.
func DecodePublicKey(value string) (ed25519.PublicKey, error) {
	key, err := contractDecode(value)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(key), nil
}

// DecodeEncryptionPublicKey decodes a base64url-encoded X25519 public key.
func DecodeEncryptionPublicKey(value string) ([]byte, error) {
	key, err := contractDecode(value)
	if err != nil || len(key) != 32 {
		return nil, contract.ErrRecipientKeyRequired
	}
	return key, nil
}
func contractDecode(value string) ([]byte, error) { return decodeBase64(value) }

// LoadPublicKeySet loads one Ed25519 public key from PEM or a JSON key set.
func LoadPublicKeySet(path, keyID string) (map[string][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if keyID != "" {
		key, err := ParsePublicKeyPEM(raw)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{keyID: append([]byte(nil), key...)}, nil
	}
	var encoded map[string]string
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return nil, fmt.Errorf("public key set needs key id or JSON map: %w", err)
	}
	keys := make(map[string][]byte, len(encoded))
	for id, value := range encoded {
		key, err := DecodePublicKey(value)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", id, err)
		}
		keys[id] = append([]byte(nil), key...)
	}
	return keys, nil
}
