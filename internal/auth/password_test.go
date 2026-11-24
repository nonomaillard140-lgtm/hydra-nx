package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("une-passphrase-longue")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") || !VerifyPassword(hash, "une-passphrase-longue") {
		t.Fatal("le mot de passe valide n'est pas reconnu")
	}
	if VerifyPassword(hash, "incorrect") || VerifyPassword("invalide", "une-passphrase-longue") {
		t.Fatal("un mot de passe invalide a été accepté")
	}
	if _, err := HashPassword("court"); err == nil {
		t.Fatal("mot de passe court accepté")
	}
}

func TestTOTPRFCVectorAndRecovery(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := TOTPCode(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" || !VerifyTOTP(secret, code, time.Unix(59, 0)) {
		t.Fatalf("code RFC inattendu: %s", code)
	}
	codes, hashes, err := NewRecoveryCodes()
	if err != nil || len(codes) != 8 {
		t.Fatalf("récupérations invalides: %v", err)
	}
	updated, ok := ConsumeRecoveryCode(hashes, codes[0])
	if !ok {
		t.Fatal("code de récupération refusé")
	}
	if _, ok := ConsumeRecoveryCode(updated, codes[0]); ok {
		t.Fatal("code de récupération rejoué")
	}
}
