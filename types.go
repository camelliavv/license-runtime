package runtime

import "time"

// ValidationPolicy contains the time and device checks applied to a license.
type ValidationPolicy struct {
	HardwareID string
	Now        time.Time
	ClockSkew  time.Duration
}

// Entitlement is the application-facing view of a verified license.
type Entitlement struct {
	LicenseID  string            `json:"license_id"`
	IssuedAt   time.Time         `json:"issued_at"`
	Product    string            `json:"product"`
	HardwareID string            `json:"hardware_id,omitempty"`
	Features   []string          `json:"features"`
	Limits     map[string]uint64 `json:"limits,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

// Limit returns an immutable numeric entitlement by its contract key.
func (e Entitlement) Limit(key string) (uint64, bool) {
	value, ok := e.Limits[key]
	return value, ok
}

// VerifierOptions configures a Verifier with trust keys, device identity, and decryption keys.
type VerifierOptions struct {
	RootPublicKeys       map[string][]byte
	HardwareID           string
	DecryptionPrivateKey []byte
	ClockSkew            time.Duration
}
