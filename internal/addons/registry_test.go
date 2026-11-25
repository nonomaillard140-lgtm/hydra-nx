package addons

import (
	"context"
	"strings"
	"testing"
)

func TestOfflineValidation(t *testing.T) {
	registry := NewRegistry()
	if len(registry.List()) < 20 {
		t.Fatal("registre incomplet")
	}
	result := registry.Validate(context.Background(), Evidence{Service: "stripe", Redacted: "STRIPE_KEY=<redacted>", Hash: "abc", Value: "sk_live_4eC39HqLyjWDarjtT1zdp7dc"})
	if result.Status != StatusPlausible || !strings.Contains(result.Action, "Révoquer") || result.Quota != "non interrogé" {
		t.Fatalf("analyse locale inattendue: %+v", result)
	}
}

func TestOfflineValidationEmpty(t *testing.T) {
	registry := NewRegistry()
	result := registry.Validate(context.Background(), Evidence{Service: "stripe"})
	if result.Status != StatusInvalid || !strings.Contains(result.Reason, "absente") {
		t.Fatalf("valeur absente mal classee: %+v", result)
	}
}
