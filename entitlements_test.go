package runtime

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/camelliavv/license-contract"
)

func TestLicenseTypedEntitlements(t *testing.T) {
	license := License{payload: contract.LicensePayload{
		Features: []contract.Feature{contract.FeatureSCT, contract.Feature("custom-feature")},
		Limits: map[contract.Limit]uint64{
			contract.LimitUserTotal:       10,
			contract.LimitEqualProtection: 0,
		},
	}}
	for _, feature := range []contract.Feature{contract.FeatureSCT, contract.Feature("custom-feature")} {
		if !license.HasFeature(feature) || !HasFeature(license.Payload(), feature) {
			t.Fatalf("licensed feature %q is missing", feature)
		}
		if err := license.Authorize(feature); err != nil {
			t.Fatalf("licensed feature %q was rejected: %v", feature, err)
		}
	}
	if license.HasFeature(contract.FeatureCPS) || HasFeature(license.Payload(), contract.FeatureCPS) {
		t.Fatal("unlicensed feature was found")
	}
	if err := license.Authorize(contract.FeatureCPS); !errors.Is(err, ErrFeatureNotLicensed) {
		t.Fatalf("expected ErrFeatureNotLicensed, got %v", err)
	}

	for name, lookup := range map[string]func(contract.Limit) (uint64, bool){
		"license":           license.Limit,
		"entitlement":       license.Entitlement().Limit,
		"empty license":     (License{}).Limit,
		"empty entitlement": (Entitlement{}).Limit,
	} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				key   contract.Limit
				value uint64
				found bool
			}{
				{contract.LimitUserTotal, 10, true},
				{contract.LimitEqualProtection, 0, true},
				{contract.LimitCryptoAssessment, 0, false},
			} {
				if name == "empty license" || name == "empty entitlement" {
					tc.value, tc.found = 0, false
				}
				if value, found := lookup(tc.key); value != tc.value || found != tc.found {
					t.Errorf("Limit(%q) = (%d, %t), want (%d, %t)", tc.key, value, found, tc.value, tc.found)
				}
			}
		})
	}
}

func TestEntitlementCopiesDoNotChangeLicense(t *testing.T) {
	license := License{payload: contract.LicensePayload{
		Features: []contract.Feature{contract.FeatureSCT},
		Limits:   map[contract.Limit]uint64{contract.LimitUserTotal: 10},
	}}
	payload := license.Payload()
	payload.Features[0] = contract.FeatureCPS
	payload.Limits[contract.LimitUserTotal] = 100
	payload.Limits[contract.LimitEqualProtection] = 1

	for _, entitlement := range []Entitlement{license.Entitlement(), ToEntitlement(license.payload)} {
		entitlement.Features[0] = contract.FeatureCPS
		entitlement.Limits[contract.LimitUserTotal] = 100
		entitlement.Limits[contract.LimitEqualProtection] = 1
	}
	if !license.HasFeature(contract.FeatureSCT) || license.HasFeature(contract.FeatureCPS) {
		t.Fatal("modifying a copy changed the license features")
	}
	if value, found := license.Limit(contract.LimitUserTotal); !found || value != 10 {
		t.Fatal("modifying a copy changed the license limit")
	}
	if _, found := license.Limit(contract.LimitEqualProtection); found {
		t.Fatal("modifying a copy added a license limit")
	}
}

func TestEntitlementJSONPreservesStringValuesAndKeys(t *testing.T) {
	const wire = `{"license_id":"lic-test","issued_at":"2026-01-01T00:00:00Z","product":"example","hardware_id":"hw-test","features":["CPS","SCT"],"limits":{"equal_protection":0,"user_total":10},"expires_at":"2026-01-02T00:00:00Z"}`
	var payload contract.LicensePayload
	if err := json.Unmarshal([]byte(wire), &payload); err != nil {
		t.Fatal(err)
	}
	entitlement := ToEntitlement(payload)
	if !reflect.DeepEqual(entitlement.Features, []contract.Feature{contract.FeatureCPS, contract.FeatureSCT}) {
		t.Fatalf("unexpected typed features: %v", entitlement.Features)
	}
	if !reflect.DeepEqual(entitlement.Limits, map[contract.Limit]uint64{contract.LimitEqualProtection: 0, contract.LimitUserTotal: 10}) {
		t.Fatalf("unexpected typed limits: %v", entitlement.Limits)
	}
	raw, err := json.Marshal(entitlement)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != wire {
		t.Fatalf("entitlement JSON changed:\n got %s\nwant %s", raw, wire)
	}
	var decoded Entitlement
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, entitlement) {
		t.Fatal("entitlements changed after a JSON round trip")
	}
}
