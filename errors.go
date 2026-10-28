package runtime

import "errors"

var (
	// ErrWrongHardware indicates that a license targets a different device.
	ErrWrongHardware = errors.New("license hardware mismatch")
	// ErrFeatureNotLicensed indicates that a requested feature is absent.
	ErrFeatureNotLicensed = errors.New("feature is not licensed")
	// ErrHardwareRequired indicates that a hardware key protector is required.
	ErrHardwareRequired = errors.New("hardware key provider is required")
	// ErrKeyUnavailable indicates that protected key material cannot be obtained.
	ErrKeyUnavailable = errors.New("protected key is unavailable")
)
