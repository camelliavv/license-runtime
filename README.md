# license-runtime

`license-runtime` is a Go SDK for applications that need to create activation
requests and verify licenses. It binds a verified license to the current device,
decrypts the license payload, and exposes the resulting entitlement to the
application.

The SDK does not issue licenses or contain signing secrets.

## Requirements

- Go 1.20 or newer

Install the module with:

```bash
go get github.com/camelliavv/license-runtime
```

## Typical use

Generate a recipient key pair once and store the private key in application
controlled protected storage. Do not write the private key to logs, source
control, or unprotected configuration.

```go
package main

import (
	"log"

	runtime "github.com/camelliavv/license-runtime"
)

func main() {
	keys, err := runtime.GenerateEncryptionKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	hardwareID, err := runtime.CurrentHardwareID()
	if err != nil {
		log.Fatal(err)
	}
	activationToken, err := runtime.NewActivationRequestToken(
		hardwareID,
		keys.Public,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Send activationToken to your license service through your own transport.
	_ = activationToken
}
```

For verification, load root public keys from a trusted application configuration.
The convenience constructor reads the current hardware ID and derives the
recipient key ID from the private key.

```go
func verifyLicense(tokenBytes []byte, privateKey []byte) error {
	rootKeys, err := runtime.LoadPublicKeySet("/path/to/trusted-root-keys.json", "")
	if err != nil {
		return err
	}

	options, err := runtime.NewVerifierOptions(rootKeys, privateKey)
	if err != nil {
		return err
	}
	verifier, err := runtime.NewVerifier(options)
	if err != nil {
		return err
	}

	license, err := verifier.Verify(tokenBytes)
	if err != nil {
		return err
	}
	if err := license.Authorize("feature-id"); err != nil {
		return err
	}
	_ = license.Entitlement()
	return nil
}
```

Use `VerifyAt` when a caller must validate against a specific trusted time, such
as in deterministic tests. `LoadFile` and `VerifyAtFile` provide the equivalent
operations for a license file.

For tests, construct `VerifierOptions` directly so the hardware ID and key
material are explicit:

```go
options := runtime.VerifierOptions{
	RootPublicKeys:       rootKeys,
	HardwareID:           "test-device-id",
	DecryptionPrivateKey: privateKey,
}
```

## Security guidance

- Treat license tokens, activation responses, and files as untrusted input.
- Keep recipient private keys in protected application storage and erase
  temporary copies when they are no longer needed.
- Pin root public keys in trusted configuration. Never accept a root key from a
  license token or an untrusted response.
- Use a license only after verification succeeds, and handle verification errors
  explicitly.
- Do not log private keys, activation tokens, license tokens, or decrypted
  payloads.
- Device identity is a binding check, not a replacement for the rest of the
  license verification process.
