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
	"github.com/camelliavv/license-contract"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type License struct {
	payload contract.LicensePayload
	raw     []byte
}

func (l License) Payload() contract.LicensePayload { return clonePayload(l.payload) }
func (l License) Raw() []byte                      { return append([]byte(nil), l.raw...) }
func (l License) Entitlement() Entitlement         { return ToEntitlement(l.payload) }
func (l License) HasFeature(feature string) bool   { return HasFeature(l.payload, feature) }
func (l License) Authorize(feature string) error {
	if feature != "" && !l.HasFeature(feature) {
		return fmt.Errorf("%w: %s", ErrFeatureNotLicensed, feature)
	}
	return nil
}

type Verifier struct {
	rootPublicKeys      map[string][]byte
	recipientPrivateKey []byte
	recipientKeyID      string
	policy              ValidationPolicy
	mu                  sync.RWMutex
}

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
	if len(options.DecryptionPrivateKey) != 32 || strings.TrimSpace(options.DecryptionKeyID) == "" {
		return nil, ErrRecipientKeyRequired
	}
	policy := ValidationPolicy{HardwareID: options.HardwareID, ClockSkew: options.ClockSkew, RequireExpiry: options.RequireExpiry, AllowedFeatures: copyFeatureSet(options.AllowedFeatures)}
	if policy.ClockSkew == 0 {
		policy.ClockSkew = 2 * time.Minute
	}
	if !options.RequireExpiry {
		policy.RequireExpiry = true
	}
	return &Verifier{rootPublicKeys: rootKeys, recipientPrivateKey: append([]byte(nil), options.DecryptionPrivateKey...), recipientKeyID: options.DecryptionKeyID, policy: policy}, nil
}
func (v *Verifier) Verify(raw []byte) (License, error) { return v.verifyWithTime(raw, time.Time{}) }
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
func (v *Verifier) LoadFile(path string) (License, error) { return v.loadFileAt(path, time.Time{}) }
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
func (v *Verifier) Policy() ValidationPolicy {
	v.mu.RLock()
	defer v.mu.RUnlock()
	policy := v.policy
	policy.AllowedFeatures = copyFeatureSet(policy.AllowedFeatures)
	return policy
}
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
		return contract.LicensePayload{}, fmt.Errorf("%w: envelope JSON: %v", ErrMalformedLicense, err)
	}
	if envelope.EnvelopeVersion != contract.EnvelopeFormatVersionV1 || envelope.SignatureAlgorithm != contract.SignatureAlgorithm || envelope.EncryptionAlgorithm != contract.EncryptionAlgorithm || envelope.KeyID == "" || envelope.RecipientKeyID == "" {
		return contract.LicensePayload{}, ErrUnsupportedFormat
	}
	if recipientKeyID == "" || envelope.RecipientKeyID != recipientKeyID || len(recipientPrivateKey) != 32 {
		return contract.LicensePayload{}, ErrRecipientKeyRequired
	}
	unsigned, err := contract.CanonicalEnvelope(envelope)
	if err != nil {
		return contract.LicensePayload{}, err
	}
	sig, err := contract.DecodeBase64URL(envelope.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return contract.LicensePayload{}, fmt.Errorf("%w: signature encoding", ErrMalformedLicense)
	}
	certRaw, err := contract.DecodeBase64URL(envelope.SigningCertificate)
	if err != nil {
		return contract.LicensePayload{}, ErrInvalidSignature
	}
	key, err := verifySigningKeyCertificate(certRaw, rootPublicKeys, policy.Now)
	if err != nil {
		return contract.LicensePayload{}, err
	}
	if !ed25519.Verify(key, unsigned, sig) {
		return contract.LicensePayload{}, ErrInvalidSignature
	}
	ephemeralBytes, err := contract.DecodeBase64URL(envelope.EphemeralPublicKey)
	if err != nil || len(ephemeralBytes) != 32 {
		return contract.LicensePayload{}, ErrInvalidEncryption
	}
	nonce, err := contract.DecodeBase64URL(envelope.Nonce)
	if err != nil {
		return contract.LicensePayload{}, ErrInvalidEncryption
	}
	ciphertext, err := contract.DecodeBase64URL(envelope.Ciphertext)
	if err != nil {
		return contract.LicensePayload{}, ErrInvalidEncryption
	}
	private, err := ecdh.X25519().NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return contract.LicensePayload{}, ErrInvalidEncryption
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(ephemeralBytes)
	if err != nil {
		return contract.LicensePayload{}, ErrInvalidEncryption
	}
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return contract.LicensePayload{}, ErrInvalidEncryption
	}
	block, err := newEnvelopeGCM(deriveEnvelopeKey(shared, envelope.KeyID, envelope.RecipientKeyID))
	if err != nil {
		return contract.LicensePayload{}, ErrInvalidEncryption
	}
	if len(nonce) != block.NonceSize() {
		return contract.LicensePayload{}, ErrInvalidEncryption
	}
	canonical, err := block.Open(nil, nonce, ciphertext, contract.EnvelopeAAD(envelope))
	if err != nil {
		return contract.LicensePayload{}, ErrInvalidEncryption
	}
	var payload contract.LicensePayload
	if err := json.Unmarshal(canonical, &payload); err != nil {
		return contract.LicensePayload{}, fmt.Errorf("%w: payload JSON: %v", ErrMalformedLicense, err)
	}
	recanonical, err := contract.CanonicalPayload(payload)
	if err != nil || !bytes.Equal(canonical, recanonical) || payload.KeyID != envelope.KeyID {
		return contract.LicensePayload{}, fmt.Errorf("%w: payload is not canonical", ErrMalformedLicense)
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
	if len(policy.AllowedFeatures) > 0 {
		for _, feature := range payload.Features {
			if _, ok := policy.AllowedFeatures[feature]; !ok {
				return fmt.Errorf("%w: %s", ErrFeatureNotLicensed, feature)
			}
		}
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
		return ErrNotYetValid
	}
	if policy.RequireExpiry && payload.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: expiry is required", ErrMalformedLicense)
	}
	if !payload.ExpiresAt.IsZero() && now.Add(-skew).After(payload.ExpiresAt) {
		return ErrExpired
	}
	return nil
}
func HasFeature(payload contract.LicensePayload, feature string) bool {
	for _, value := range payload.Features {
		if value == feature {
			return true
		}
	}
	return false
}
func ToEntitlement(payload contract.LicensePayload) Entitlement {
	features := append([]string(nil), payload.Features...)
	limits := make(map[string]uint64, len(payload.Limits))
	for key, value := range payload.Limits {
		limits[key] = value
	}
	return Entitlement{LicenseID: payload.LicenseID, IssuedAt: payload.IssuedAt, Product: payload.Product, HardwareID: payload.HardwareID, Features: features, Limits: limits, ExpiresAt: payload.ExpiresAt}
}
func copyFeatureSet(input map[string]struct{}) map[string]struct{} {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]struct{}, len(input))
	for key := range input {
		output[key] = struct{}{}
	}
	return output
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
