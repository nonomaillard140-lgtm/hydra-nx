package fuzz

import (
	"strings"
	"testing"
)

func TestVariantsAreCanonical(t *testing.T) {
	variants := Variants("/.env")
	if len(variants) < 2 || variants[0].Path != "/.env" {
		t.Fatalf("variantes inattendues: %v", variants)
	}
	for _, variant := range variants {
		if strings.Contains(variant.Path, "%00") || strings.Contains(variant.Path, "%252") || len(variant.Path) > 8192 {
			t.Fatalf("contournement non défensif produit: %s", variant.Path)
		}
	}
}

func TestDifferentialAndHoneypot(t *testing.T) {
	baseline := Response{Status: 404, Body: []byte("not found")}
	candidate := Response{Status: 200, Body: []byte("DB_PASSWORD=<redacted-proof> with enough bytes")}
	if !Compare(baseline, candidate).Divergent {
		t.Fatal("divergence réelle non détectée")
	}
	if Compare(baseline, Response{Status: 200, Body: []byte("not found")}).Divergent {
		t.Fatal("corps identique détecté comme exposition")
	}
	if Compare(baseline, Response{Status: 200, Body: []byte("short")}).Divergent {
		t.Fatal("réponse trop courte acceptée")
	}
	responses := []Response{{Status: 200, Body: []byte("same regular body")}, {Status: 200, Body: []byte("same regular body")}, {Status: 200, Body: []byte("same regular body")}}
	if !RegularResponses(responses) {
		t.Fatal("leurres réguliers non détectés")
	}
}

func TestNormalizeDynamicValues(t *testing.T) {
	a := Normalize([]byte(`{"request_id":"abcdef123456","ok":true}`))
	b := Normalize([]byte(`{"request_id":"098765fedcba","ok":true}`))
	if string(a) != string(b) {
		t.Fatalf("valeurs dynamiques non normalisées: %s != %s", a, b)
	}
}
