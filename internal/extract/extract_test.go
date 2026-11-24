package extract

import (
	"strings"
	"testing"
)

func TestParseEnvRedactsAndHashes(t *testing.T) {
	raw := []byte("# comment\nDB_PASSWORD=super-secret-value\nSTRIPE_SECRET_KEY=sk_live_123456789012345678\nAPP_NAME=hydra\nexport MAIL_USERNAME=\"mailer@hydra.internal\"\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	findings := ParseEnv(raw)
	if len(findings) != 3 {
		t.Fatalf("nombre de constats inattendu: %v", findings)
	}
	for _, finding := range findings {
		if finding.ValueHash == "" || !strings.Contains(finding.Redacted, "<redacted>") || strings.Contains(finding.Redacted, "super-secret") || strings.Contains(finding.Redacted, "123456789") {
			t.Fatalf("valeur insuffisamment rédigée: %+v", finding)
		}
	}
	if findings[1].Service == "generic" && findings[1].Variable == "MAIL_USERNAME" {
		t.Fatal("service SMTP non classé")
	}
}

func TestWPSourceMapAndGit(t *testing.T) {
	wp := ParseWPConfig([]byte(`define('DB_PASSWORD', 'private-value'); define('AUTH_KEY', 'another-private-key');`))
	if len(wp) != 2 || strings.Contains(wp[0].Redacted, "private") {
		t.Fatalf("wp-config non rédigé: %v", wp)
	}
	sources, ok := ParseSourceMap([]byte(`{"version":3,"sources":["src/app.ts"],"sourcesContent":["secret"]}`))
	if !ok || len(sources) != 1 {
		t.Fatal("source map valide non reconnue")
	}
	if _, ok := ParseGitHEAD([]byte("ref: refs/heads/main\n")); !ok {
		t.Fatal("HEAD Git valide non reconnu")
	}
}

func TestDetectAndEntropy(t *testing.T) {
	exposure, ok := Detect("/.env", []byte("DB_PASSWORD=super-secret-value"))
	if !ok || exposure.Vuln != "env_exposure" || len(exposure.Findings) != 1 {
		t.Fatalf("exposition env non détectée: %+v", exposure)
	}
	if ShannonEntropy("aaaaaaaaaaaaaaaa") >= 1 || ShannonEntropy("aB3dE5gH7jK9mN1pQ4rS6tU8vW0xY2z") < 4 {
		t.Fatal("calcul d'entropie incohérent")
	}
	if !IsPublicExample("AKIAIOSFODNN7EXAMPLE") || IsPublicExample("real-private-value") {
		t.Fatal("liste noire d'exemples incorrecte")
	}
}
