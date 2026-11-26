package send_test

import (
	"testing"

	"hydra/internal/send"
)

func TestDeriveTransportFromFoundIdentity(t *testing.T) {
	config, err := send.DeriveTransport("bob@exemple.tld", send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "smtp.exemple.tld" || config.Username != "bob@exemple.tld" || config.From != "bob@exemple.tld" || config.Port != 587 {
		t.Fatalf("derivation inattendue: %+v", config)
	}
}

func TestDeriveTransportManualOverride(t *testing.T) {
	request := send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps", Host: "mail.exemple.tld", Port: 465, Username: "bot", From: "bot@exemple.tld"}
	config, err := send.DeriveTransport("secret-123", request)
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "mail.exemple.tld" || config.Port != 465 || config.Username != "bot" || config.From != "bot@exemple.tld" {
		t.Fatalf("surcharge ignoree: %+v", config)
	}
}

func TestDeriveTransportNeedsIdentity(t *testing.T) {
	if _, err := send.DeriveTransport("secret-123", send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps"}); err == nil {
		t.Fatal("hote manquant accepte")
	}
}

func TestDeriveTransportRejectsBadRecipient(t *testing.T) {
	if _, err := send.DeriveTransport("bob@exemple.tld", send.SendRequest{To: "dest", Subject: "test", Body: "corps"}); err == nil {
		t.Fatal("destinataire invalide accepte")
	}
}
