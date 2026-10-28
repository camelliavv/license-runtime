package runtime

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/camelliavv/license-contract"
)

// NewActivationRequest creates a client activation request with the current UTC time.
func NewActivationRequest(hardwareID, recipientKeyID string, recipientPublicKey []byte) (contract.ActivationRequest, error) {
	if hardwareID == "" || recipientKeyID == "" || len(recipientPublicKey) != 32 {
		return contract.ActivationRequest{}, contract.ErrRecipientKeyRequired
	}
	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return contract.ActivationRequest{}, err
	}
	request := contract.ActivationRequest{FormatVersion: contract.FormatVersionV1, RequestID: encodeBase64(idBytes[:]), HardwareID: hardwareID, RecipientKeyID: recipientKeyID, RecipientPublicKey: encodeBase64(recipientPublicKey), CreatedAt: time.Now().UTC().Round(0)}
	return request, nil
}

// NewActivationRequestToken creates and encodes a client activation request token.
func NewActivationRequestToken(hardwareID, recipientKeyID string, recipientPublicKey []byte) ([]byte, error) {
	request, err := NewActivationRequest(hardwareID, recipientKeyID, recipientPublicKey)
	if err != nil {
		return nil, err
	}
	return contract.EncodeActivationRequestToken(request)
}

// EncodeActivationRequestCBOR encodes an activation request in its CBOR wire format.
func EncodeActivationRequestCBOR(request contract.ActivationRequest) ([]byte, error) {
	return contract.EncodeActivationRequestCBOR(request)
}

// DecodeActivationRequestCBOR decodes an activation request from CBOR.
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
		return fmt.Errorf("%w: X25519 key must be 32 bytes", contract.ErrRecipientKeyRequired)
	}
	return nil
}
