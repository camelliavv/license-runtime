package runtime

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/camelliavv/license-contract"
	"time"
)

func verifySigningKeyCertificate(raw []byte, rootPublicKeys map[string][]byte, now time.Time) (ed25519.PublicKey, error) {
	var cert contract.SigningKeyCertificate
	if err := json.Unmarshal(raw, &cert); err != nil || cert.FormatVersion != contract.FormatVersionV1 || cert.RootKeyID == "" || cert.KeyID == "" {
		return nil, contract.ErrInvalidSignature
	}
	sig, err := contract.DecodeBase64URL(cert.Signature)
	if err != nil {
		return nil, contract.ErrInvalidSignature
	}
	cert.Signature = ""
	canonical, err := json.Marshal(cert)
	if err != nil {
		return nil, contract.ErrInvalidSignature
	}
	rootPublic, ok := rootPublicKeys[cert.RootKeyID]
	if !ok || len(rootPublic) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(rootPublic), canonical, sig) {
		return nil, contract.ErrInvalidSignature
	}
	child, err := contract.DecodeBase64URL(cert.PublicKey)
	if err != nil || len(child) != ed25519.PublicKeySize {
		return nil, contract.ErrInvalidSignature
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if !cert.NotBefore.IsZero() && now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("%w: signing certificate is not yet valid", contract.ErrNotYetValid)
	}
	if !cert.ExpiresAt.IsZero() && now.After(cert.ExpiresAt) {
		return nil, fmt.Errorf("%w: signing certificate expired", contract.ErrExpired)
	}
	return ed25519.PublicKey(child), nil
}
