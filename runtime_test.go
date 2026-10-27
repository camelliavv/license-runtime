package runtime

import (
	"testing"
	"time"
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
	request, err := NewActivationRequest("hw-test", keyID, keys.Public, time.Unix(1700000000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if request.FormatVersion != FormatVersionV1 || request.HardwareID != "hw-test" || request.RecipientKeyID != keyID {
		t.Fatalf("unexpected request: %#v", request)
	}
	if _, err := NewActivationRequestToken("hw-test", keyID, keys.Public, request.CreatedAt); err != nil {
		t.Fatal(err)
	}
}
