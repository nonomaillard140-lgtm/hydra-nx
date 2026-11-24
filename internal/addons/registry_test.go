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
	result := registry.Validate(context.Background(), Evidence{Service: "stripe", Redacted: "STRIPE_KEY=<redacted>", Hash: "abc"})
	if result.Status != StatusDetected || !strings.Contains(result.Action, "Révoquer") || result.Quota != "non interrogé" {
		t.Fatalf("analyse locale inattendue: %+v", result)
	}
}
