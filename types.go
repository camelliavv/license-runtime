package runtime

import (
	"github.com/camelliavv/license-contract"
	"time"
)

type LicensePayload = contract.LicensePayload
type LicenseEnvelope = contract.LicenseEnvelope
type SigningKeyCertificate = contract.SigningKeyCertificate
type ActivationRequest = contract.ActivationRequest

type ValidationPolicy struct {
	HardwareID      string
	Now             time.Time
	ClockSkew       time.Duration
	RequireExpiry   bool
	AllowedFeatures map[string]struct{}
}

type Entitlement struct {
	LicenseID  string            `json:"license_id"`
	IssuedAt   time.Time         `json:"issued_at"`
	Product    string            `json:"product"`
	HardwareID string            `json:"hardware_id,omitempty"`
	Features   []string          `json:"features"`
	Limits     map[string]uint64 `json:"limits,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

type VerifierOptions struct {
	RootPublicKeys       map[string][]byte
	HardwareID           string
	DecryptionPrivateKey []byte
	DecryptionKeyID      string
	ClockSkew            time.Duration
	RequireExpiry        bool
	AllowedFeatures      map[string]struct{}
}

const (
	FormatVersionV1         = contract.FormatVersionV1
	EnvelopeFormatVersionV1 = contract.EnvelopeFormatVersionV1
	LicenseTokenPrefix      = contract.LicenseTokenPrefix
	ActivationTokenPrefix   = contract.ActivationTokenPrefix
	SignatureAlgorithm      = contract.SignatureAlgorithm
	EncryptionAlgorithm     = contract.EncryptionAlgorithm
)
