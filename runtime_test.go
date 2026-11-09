package runtime

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/camelliavv/license-contract"
)

func TestVerifierClockSkew(t *testing.T) {
	start := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	payload := contract.LicensePayload{HardwareID: "device", NotBefore: start, ExpiresAt: start.Add(time.Hour)}
	for _, tc := range []struct {
		name                  string
		skew                  time.Duration
		early, late, rollback error
	}{
		{"zero", 0, contract.ErrNotYetValid, contract.ErrExpired, ErrClockRollback},
		{"positive", time.Second, nil, nil, nil},
		{"negative", -time.Second, contract.ErrNotYetValid, contract.ErrExpired, ErrClockRollback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVerifier(VerifierOptions{
				RootPublicKeys:       map[string][]byte{"root": make([]byte, ed25519.PublicKeySize)},
				DecryptionPrivateKey: make([]byte, 32),
				HardwareID:           payload.HardwareID,
				ClockSkew:            tc.skew,
			})
			if err != nil {
				t.Fatal(err)
			}
			policy := v.Policy()
			for _, edge := range []struct {
				now  time.Time
				want error
			}{
				{payload.NotBefore.Add(-time.Nanosecond), tc.early},
				{payload.NotBefore, nil},
				{payload.ExpiresAt, nil},
				{payload.ExpiresAt.Add(time.Nanosecond), tc.late},
			} {
				policy.Now = edge.now
				if err := validatePayload(payload, policy); !errors.Is(err, edge.want) {
					t.Errorf("at %s: got %v, want %v", edge.now, err, edge.want)
				}
			}
			clock := verificationClock{base: start, sample: func() (time.Time, time.Duration) {
				return start, time.Nanosecond
			}}
			if _, err := clock.now(policy.ClockSkew); !errors.Is(err, tc.rollback) {
				t.Errorf("1ns clock lag: got %v, want %v", err, tc.rollback)
			}
		})
	}
}

func TestNewActivationRequest(t *testing.T) {
	keys, err := GenerateEncryptionKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := DeriveEncryptionKeyID(keys.Public)
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewActivationRequest("hw-test", keys.Public)
	if err != nil {
		t.Fatal(err)
	}
	if request.FormatVersion != contract.FormatVersionV1 || request.HardwareID != "hw-test" || request.RecipientKeyID != keyID || request.CreatedAt.IsZero() {
		t.Fatalf("unexpected request: %#v", request)
	}
	if _, err := NewActivationRequestToken("hw-test", keys.Public); err != nil {
		t.Fatal(err)
	}
}
