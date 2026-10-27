package runtime

import (
	"errors"
	"github.com/camelliavv/license-contract"
)

var (
	ErrMalformedLicense      = contract.ErrMalformedLicense
	ErrInvalidSignature      = contract.ErrInvalidSignature
	ErrUnsupportedFormat     = contract.ErrUnsupportedFormat
	ErrNotYetValid           = contract.ErrNotYetValid
	ErrExpired               = contract.ErrExpired
	ErrRecipientKeyRequired  = contract.ErrRecipientKeyRequired
	ErrInvalidEncryption     = contract.ErrInvalidEncryption
	ErrWrongIssuer           = errors.New("license issuer mismatch")
	ErrWrongAudience         = errors.New("license audience mismatch")
	ErrWrongProduct          = errors.New("license product mismatch")
	ErrWrongHardware         = errors.New("license hardware mismatch")
	ErrFeatureNotLicensed    = errors.New("feature is not licensed")
	ErrHardwareRequired      = errors.New("hardware key provider is required")
	ErrKeyUnavailable        = errors.New("protected key is unavailable")
	ErrHardwareIDUnavailable = hardwareIDUnavailable()
)
