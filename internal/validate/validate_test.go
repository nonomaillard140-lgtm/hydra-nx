package validate

import "testing"

func TestRejectsExampleKey(t *testing.T) {
	if r := Check("aws", "AKIAIOSFODNN7EXAMPLE"); r.Verdict != Invalid {
		t.Fatalf("clé d'exemple acceptée: %s", r.Verdict)
	}
}

func TestAcceptsAWSShape(t *testing.T) {
	if r := Check("aws", "AKIA4T7QZ2M8XK1L9P3D"); r.Verdict != Plausible {
		t.Fatalf("clé plausible rejetée: %s (%s)", r.Verdict, r.Reason)
	}
}

func TestFormatMismatch(t *testing.T) {
	if r := Check("sendgrid", "SG.abc"); r.Verdict != Invalid {
		t.Fatalf("format incorrect accepté: %s", r.Verdict)
	}
}

func TestPlaceholderRejected(t *testing.T) {
	if r := Check("stripe", "sk_live_changeme"); r.Verdict != Invalid {
		t.Fatalf("placeholder accepté: %s", r.Verdict)
	}
}

func TestEmptyIsInvalid(t *testing.T) {
	if r := Check("aws", "  "); r.Verdict != Invalid {
		t.Fatal("valeur vide acceptée")
	}
}
