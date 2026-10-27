package runtime

import (
	"crypto/rand"
	"fmt"
	"github.com/camelliavv/license-contract"
	"time"
)

// NewActivationRequest creates a client activation request and its act. token.
func NewActivationRequest(hardwareID, recipientKeyID string, recipientPublicKey []byte, now time.Time) (contract.ActivationRequest, error) {
	if hardwareID == "" || recipientKeyID == "" || len(recipientPublicKey) != 32 {
		return contract.ActivationRequest{}, ErrRecipientKeyRequired
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return contract.ActivationRequest{}, err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	request := contract.ActivationRequest{FormatVersion: contract.FormatVersionV1, RequestID: encodeBase64(idBytes[:]), HardwareID: hardwareID, RecipientKeyID: recipientKeyID, RecipientPublicKey: encodeBase64(recipientPublicKey), CreatedAt: now.UTC().Round(0)}
	return request, nil
}

func NewActivationRequestToken(hardwareID, recipientKeyID string, recipientPublicKey []byte, now time.Time) ([]byte, error) {
	request, err := NewActivationRequest(hardwareID, recipientKeyID, recipientPublicKey, now)
	if err != nil {
		return nil, err
	}
	return contract.EncodeActivationRequestToken(request)
}

func EncodeActivationRequestCBOR(request contract.ActivationRequest) ([]byte, error) {
	return contract.EncodeActivationRequestCBOR(request)
}
func DecodeActivationRequestCBOR(raw []byte) (contract.ActivationRequest, error) {
	return contract.DecodeActivationRequestCBOR(raw)
}

// ActivationRequestFromToken is provided for diagnostics and compatibility. The
// issuer must still validate the request against its own policy.
func ActivationRequestFromToken(token []byte) (contract.ActivationRequest, error) {
	return contract.ParseActivationRequestToken(token)
}

func validateRecipientKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("%w: X25519 key must be 32 bytes", ErrRecipientKeyRequired)
	}
	return nil
}
