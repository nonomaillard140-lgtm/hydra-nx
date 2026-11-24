package discover

import (
	"slices"
	"testing"
)

func TestNormalizeAndMerge(t *testing.T) {
	value, err := NormalizeTarget(" HTTPS://WWW.Example.COM/path ", "L7")
	if err != nil || value != "www.example.com" {
		t.Fatalf("normalisation L7: %q %v", value, err)
	}
	if _, err := NormalizeTarget("*.example.com", "L7"); err == nil {
		t.Fatal("wildcard accepté")
	}
	if _, err := NormalizeTarget("localhost", "L7"); err == nil {
		t.Fatal("cible non qualifiée acceptée")
	}
	values, err := MergeAndNormalize("L7", []string{"a.example.com", "b.example.com"}, []string{"a.example.com"})
	if err != nil || !slices.Equal(values, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("fusion: %v %v", values, err)
	}
	ip, err := NormalizeTarget("2001:db8::1", "L4")
	if err != nil || ip != "2001:db8::1" {
		t.Fatalf("normalisation IPv6: %q %v", ip, err)
	}
}

func TestPTRShuffleAndFingerprint(t *testing.T) {
	values := FilterPTR([]string{"1.0.0.127.in-addr.arpa", "static.1.2.3.4.clients.provider.net", "www.example.com"})
	if !slices.Equal(values, []string{"www.example.com"}) {
		t.Fatalf("PTR non filtrés: %v", values)
	}
	original := []string{"a", "b", "c", "d"}
	if !slices.Equal(Shuffle(original, 42), Shuffle(original, 42)) {
		t.Fatal("mélange non déterministe avec la même graine")
	}
	if ScopeFingerprint([]string{"b", "a"}) != ScopeFingerprint([]string{"a", "b"}) {
		t.Fatal("empreinte de périmètre dépendante de l'ordre")
	}
}
