package runtime

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/camelliavv/license-contract"
)

// License is a verified and decrypted license document.
type License struct {
	payload contract.LicensePayload
	raw     []byte
}

// Payload returns a copy of the verified wire-level payload.
func (l License) Payload() contract.LicensePayload { return clonePayload(l.payload) }

// Raw returns a copy of the original license token bytes.
func (l License) Raw() []byte { return append([]byte(nil), l.raw...) }

// Entitlement returns the verified license in its application-facing form.
func (l License) Entitlement() Entitlement { return ToEntitlement(l.payload) }

// HasFeature reports whether the verified license contains feature.
func (l License) HasFeature(feature string) bool { return HasFeature(l.payload, feature) }

// Authorize reports an error when feature is not present in the verified license.
func (l License) Authorize(feature string) error {
	if feature != "" && !l.HasFeature(feature) {
		return fmt.Errorf("%w: %s", ErrFeatureNotLicensed, feature)
	}
	return nil
}

// Verifier validates, decrypts, and applies the policy to license tokens.
type Verifier struct {
	rootPublicKeys      map[string][]byte
	recipientPrivateKey []byte
	recipientKeyID      string
	policy              ValidationPolicy
	mu                  sync.RWMutex
}

// NewVerifierOptions creates verifier options using the current host hardware ID.
func NewVerifierOptions(rootPublicKeys map[string][]byte, decryptionPrivateKey []byte) (VerifierOptions, error) {
	hardwareID, err := CurrentHardwareID()
	if err != nil {
		return VerifierOptions{}, err
	}
	return VerifierOptions{
		RootPublicKeys:       rootPublicKeys,
		HardwareID:           hardwareID,
		DecryptionPrivateKey: decryptionPrivateKey,
	}, nil
}

// NewVerifier creates a verifier from trusted root and recipient key material.
func NewVerifier(options VerifierOptions) (*Verifier, error) {
	if len(options.RootPublicKeys) == 0 {
		return nil, fmt.Errorf("root public keys are required")
	}
	rootKeys := make(map[string][]byte, len(options.RootPublicKeys))
	for id, key := range options.RootPublicKeys {
		if strings.TrimSpace(id) == "" || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("root public key %q is invalid", id)
		}
		rootKeys[id] = append([]byte(nil), key...)
	}
	if strings.TrimSpace(options.HardwareID) == "" {
		return nil, fmt.Errorf("hardware id is required")
	}
	if len(options.DecryptionPrivateKey) != 32 {
		return nil, contract.ErrRecipientKeyRequired
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(options.DecryptionPrivateKey)
	if err != nil {
		return nil, contract.ErrRecipientKeyRequired
	}
	recipientKeyID, err := DeriveEncryptionKeyID(privateKey.PublicKey().Bytes())
	if err != nil {
		return nil, contract.ErrRecipientKeyRequired
	}
	policy := ValidationPolicy{HardwareID: options.HardwareID, ClockSkew: options.ClockSkew}
	if policy.ClockSkew == 0 {
		policy.ClockSkew = 2 * time.Minute
	}
	return &Verifier{rootPublicKeys: rootKeys, recipientPrivateKey: append([]byte(nil), options.DecryptionPrivateKey...), recipientKeyID: recipientKeyID, policy: policy}, nil
}

// Verify validates a license using the current UTC time.
func (v *Verifier) Verify(raw []byte) (License, error) { return v.verifyWithTime(raw, time.Time{}) }

// VerifyAt validates a license as of the supplied time.
func (v *Verifier) VerifyAt(raw []byte, now time.Time) (License, error) {
	return v.verifyWithTime(raw, now)
}

func (v *Verifier) verifyWithTime(raw []byte, now time.Time) (License, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return License{}, fmt.Errorf("license bytes are empty or too large")
	}
	v.mu.RLock()
	rootPublicKeys := make(map[string][]byte, len(v.rootPublicKeys))
	for id, key := range v.rootPublicKeys {
		rootPublicKeys[id] = append([]byte(nil), key...)
	}
	recipientPrivateKey := append([]byte(nil), v.recipientPrivateKey...)
	recipientKeyID := v.recipientKeyID
	policy := v.policy
	v.mu.RUnlock()
	if !now.IsZero() {
		policy.Now = now.UTC()
	}
	payload, err := parseAndVerify(raw, rootPublicKeys, recipientPrivateKey, recipientKeyID, policy)
	if err != nil {
		return License{}, err
	}
	return License{payload: payload, raw: append([]byte(nil), raw...)}, nil
}

// LoadFile reads and validates a license file using the current UTC time.
func (v *Verifier) LoadFile(path string) (License, error) { return v.loadFileAt(path, time.Time{}) }

// VerifyAtFile reads and validates a license file as of the supplied time.
func (v *Verifier) VerifyAtFile(path string, now time.Time) (License, error) {
	return v.loadFileAt(path, now)
}

func (v *Verifier) loadFileAt(path string, now time.Time) (License, error) {
	info, err := os.Stat(path)
	if err != nil {
		return License{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return License{}, fmt.Errorf("license file is invalid or too large")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return License{}, err
	}
	return v.verifyWithTime(raw, now)
}

// Policy returns the verifier's validation policy.
func (v *Verifier) Policy() ValidationPolicy {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.policy
}

// ImportFile verifies raw and stores it at path using an atomic file replacement.
func ImportFile(path string, raw []byte, verifier *Verifier) error {
	if verifier == nil {
		return fmt.Errorf("verifier is required")
	}
	if _, err := verifier.Verify(raw); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".license-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func parseAndVerify(raw []byte, rootPublicKeys map[string][]byte, recipientPrivateKey []byte, recipientKeyID string, policy ValidationPolicy) (contract.LicensePayload, error) {
	decoded, err := contract.DecodeLicenseToken(bytes.TrimSpace(raw))
	if err != nil {
		return contract.LicensePayload{}, err
	}
	var envelope contract.LicenseEnvelope
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		return contract.LicensePayload{}, fmt.Errorf("%w: envelope JSON: %v", contract.ErrMalformedLicense, err)
	}
	if envelope.EnvelopeVersion != contract.EnvelopeFormatVersionV1 || envelope.SignatureAlgorithm != contract.SignatureAlgorithm || envelope.EncryptionAlgorithm != contract.EncryptionAlgorithm || envelope.KeyID == "" || envelope.RecipientKeyID == "" {
		return contract.LicensePayload{}, contract.ErrUnsupportedFormat
	}
	if recipientKeyID == "" || envelope.RecipientKeyID != recipientKeyID || len(recipientPrivateKey) != 32 {
		return contract.LicensePayload{}, contract.ErrRecipientKeyRequired
	}
	unsigned, err := contract.CanonicalEnvelope(envelope)
	if err != nil {
		return contract.LicensePayload{}, err
	}
	sig, err := contract.DecodeBase64URL(envelope.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return contract.LicensePayload{}, fmt.Errorf("%w: signature encoding", contract.ErrMalformedLicense)
	}
	certRaw, err := contract.DecodeBase64URL(envelope.SigningCertificate)
	if err != nil {
		return contract.LicensePayload{}, contract.ErrInvalidSignature
	}
	key, err := verifySigningKeyCertificate(certRaw, rootPublicKeys, policy.Now)
	if err != nil {
		return contract.LicensePayload{}, err
	}
	if !ed25519.Verify(key, unsigned, sig) {
		return contract.LicensePayload{}, contract.ErrInvalidSignature
	}
	ephemeralBytes, err := contract.DecodeBase64URL(envelope.EphemeralPublicKey)
	if err != nil || len(ephemeralBytes) != 32 {
		return contract.LicensePayload{}, contract.ErrInvalidEncryption
	}
	nonce, err := contract.DecodeBase64URL(envelope.Nonce)
	if err != nil {
		return contract.LicensePayload{}, contract.ErrInvalidEncryption
	}
	ciphertext, err := contract.DecodeBase64URL(envelope.Ciphertext)
	if err != nil {
		return contract.LicensePayload{}, contract.ErrInvalidEncryption
	}
	private, err := ecdh.X25519().NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return contract.LicensePayload{}, contract.ErrInvalidEncryption
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(ephemeralBytes)
	if err != nil {
		return contract.LicensePayload{}, contract.ErrInvalidEncryption
	}
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return contract.LicensePayload{}, contract.ErrInvalidEncryption
	}
	block, err := newEnvelopeGCM(deriveEnvelopeKey(shared, envelope.KeyID, envelope.RecipientKeyID))
	if err != nil {
		return contract.LicensePayload{}, contract.ErrInvalidEncryption
	}
	if len(nonce) != block.NonceSize() {
		return contract.LicensePayload{}, contract.ErrInvalidEncryption
	}
	canonical, err := block.Open(nil, nonce, ciphertext, contract.EnvelopeAAD(envelope))
	if err != nil {
		return contract.LicensePayload{}, contract.ErrInvalidEncryption
	}
	var payload contract.LicensePayload
	if err := json.Unmarshal(canonical, &payload); err != nil {
		return contract.LicensePayload{}, fmt.Errorf("%w: payload JSON: %v", contract.ErrMalformedLicense, err)
	}
	recanonical, err := contract.CanonicalPayload(payload)
	if err != nil || !bytes.Equal(canonical, recanonical) || payload.KeyID != envelope.KeyID {
		return contract.LicensePayload{}, fmt.Errorf("%w: payload is not canonical", contract.ErrMalformedLicense)
	}
	if err := validatePayload(payload, policy); err != nil {
		return contract.LicensePayload{}, err
	}
	return payload, nil
}
func deriveEnvelopeKey(shared []byte, signingKeyID, recipientKeyID string) []byte {
	salt := sha256.Sum256([]byte("license/envelope/hkdf-salt/v1"))
	extract := hmac.New(sha256.New, salt[:])
	_, _ = extract.Write(shared)
	prk := extract.Sum(nil)
	info := []byte("license/envelope/hkdf-info/v1/" + signingKeyID + "/" + recipientKeyID)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write(info)
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)[:32]
}
func newEnvelopeGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func validatePayload(payload contract.LicensePayload, policy ValidationPolicy) error {
	if payload.HardwareID != policy.HardwareID {
		return fmt.Errorf("%w: got %q", ErrWrongHardware, payload.HardwareID)
	}
	now := policy.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	skew := policy.ClockSkew
	if skew < 0 {
		skew = 0
	}
	if now.Add(skew).Before(payload.NotBefore) {
		return contract.ErrNotYetValid
	}
	if payload.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: expiry is required", contract.ErrMalformedLicense)
	}
	if now.Add(-skew).After(payload.ExpiresAt) {
		return contract.ErrExpired
	}
	return nil
}

// HasFeature reports whether a payload contains feature.
func HasFeature(payload contract.LicensePayload, feature string) bool {
	for _, value := range payload.Features {
		if value == feature {
			return true
		}
	}
	return false
}

// ToEntitlement converts a wire-level payload to an application-facing entitlement.
func ToEntitlement(payload contract.LicensePayload) Entitlement {
	features := append([]string(nil), payload.Features...)
	limits := make(map[string]uint64, len(payload.Limits))
	for key, value := range payload.Limits {
		limits[key] = value
	}
	return Entitlement{LicenseID: payload.LicenseID, IssuedAt: payload.IssuedAt, Product: payload.Product, HardwareID: payload.HardwareID, Features: features, Limits: limits, ExpiresAt: payload.ExpiresAt}
}
func clonePayload(input contract.LicensePayload) contract.LicensePayload {
	output := input
	output.Features = append([]string(nil), input.Features...)
	if input.Limits != nil {
		output.Limits = make(map[string]uint64, len(input.Limits))
		for key, value := range input.Limits {
			output.Limits[key] = value
		}
	}
	return output
}
