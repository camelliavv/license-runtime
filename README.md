# license-runtime

`license-runtime` is a Go SDK for applications that need to create activation
requests and verify licenses. It binds a verified license to the current device,
decrypts the license payload, and exposes the resulting entitlement to the
application. It can also sign JWT inputs using a verified license's Ed25519 key.

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
`NewVerifierOptions` reads the current hardware ID. The recommended clock skew
(third argument) is `2*time.Minute`. This tolerance applies to both clock rollback
detection and the license payload's validity window. Pass `0` for zero tolerance.
`NewVerifier` derives the recipient key ID from the private key.

```go
import (
	"time"

	"github.com/camelliavv/license-contract"
	runtime "github.com/camelliavv/license-runtime"
)

func verifyLicense(tokenBytes []byte, privateKey []byte) error {
	rootKeys, err := runtime.LoadPublicKeySet("/path/to/trusted-root-keys.json", "")
	if err != nil {
		return err
	}

	options, err := runtime.NewVerifierOptions(rootKeys, privateKey, 2*time.Minute)
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
	if err := license.Authorize(contract.FeatureSCT); err != nil {
		return err
	}
	_ = license.Entitlement()
	return nil
}
```

`HasFeature` and `Authorize` accept `contract.Feature`; `License.Limit` and
`Entitlement.Limit` accept `contract.Limit`. Prefer the predefined constants,
such as `contract.FeatureSCT` and `contract.LimitUserTotal`. `Limit` returns
`(value, found)`, so a zero limit can be distinguished from an absent limit.

When migrating string-based callers, use `[]contract.Feature` and
`map[contract.Limit]uint64` for entitlement collections. Convert string variables
explicitly with `contract.Feature(value)` or `contract.Limit(value)`; JSON values
and keys remain strings. The former `LimitUsersTotal` constant is now
`contract.LimitUserTotal`.

`Verify` and `LoadFile` share a clock across all verifiers in the process.
If the system clock falls behind the time expected from monotonic elapsed time
by more than `ClockSkew` (zero by default), verification returns
`ErrClockRollback`. Smaller corrections never move verification time backwards.
The check runs on each verification; it does not recheck a cached `License`.
The baseline is kept in memory and resets when the process restarts.

Use `VerifyAt` or `VerifyAtFile` only with a trusted time, such as in deterministic
tests. An explicit nonzero time bypasses the rollback check and does not change
its baseline. A zero time uses the guarded current time.

For tests, construct `VerifierOptions` directly so the hardware ID and key
material are explicit:

```go
options := runtime.VerifierOptions{
	RootPublicKeys:       rootKeys,
	HardwareID:           "test-device-id",
	DecryptionPrivateKey: privateKey,
}
```

## Signing a JWT

Build the protected header and claims in trusted application code. Pass the
two unpadded Base64URL segments, joined by a period, to `SignJWTInput`.
For example, given the application's serialized `claimsJSON` and a header
selecting Ed25519, assemble the compact token as follows.

```go
encoding := base64.RawURLEncoding // from encoding/base64
header := encoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
signingInput := header + "." + encoding.EncodeToString(claimsJSON)
signature, err := verifier.SignJWTInput(rawLicense, []byte(signingInput))
if err != nil {
	return "", err
}
return signingInput + "." + encoding.EncodeToString(signature), nil
```

Each call verifies the encrypted license, device binding and current time.
Signing stops at `ExpiresAt`, including when `ClockSkew` would still allow
ordinary verification. The application sets and enforces the token's own
expiry. To have tokens expire with the license, cap their `exp` at `ExpiresAt`.

`runtime.DecodePublicKey(license.Payload().JWT.PublicKey)` returns the Ed25519
public key from a verified license. The SDK omits the signing seed from the
returned payload. Licenses issued with the older payload format that omitted
the `jwt` field need to be reissued for this SDK version.

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
