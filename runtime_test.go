package runtime

import (
	"testing"

	"github.com/camelliavv/license-contract"
)

func TestNewActivationRequest(t *testing.T) {
	keys, err := GenerateEncryptionKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := DeriveEncryptionKeyID(keys.Public)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewActivationRequest("hw-test", keyID, keys.Public)
	if err != nil {
		t.Fatal(err)
	}
	if request.FormatVersion != contract.FormatVersionV1 || request.HardwareID != "hw-test" || request.RecipientKeyID != keyID || request.CreatedAt.IsZero() {
		t.Fatalf("unexpected request: %#v", request)
	}
	if _, err := NewActivationRequestToken("hw-test", keyID, keys.Public); err != nil {
		t.Fatal(err)
	}
}
