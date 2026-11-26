package send_test

import (
	"context"
	"errors"
	"testing"

	"hydra/internal/send"
)

func TestDeriveTransportFromFoundIdentity(t *testing.T) {
	config, err := send.DeriveTransport(context.Background(), nil, "bob@exemple.tld", send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "smtp.exemple.tld" || config.Username != "bob@exemple.tld" || config.From != "bob@exemple.tld" || config.Port != 587 {
		t.Fatalf("derivation inattendue: %+v", config)
	}
}

func TestDeriveTransportManualOverride(t *testing.T) {
	request := send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps", Host: "mail.exemple.tld", Port: 465, Username: "bot", From: "bot@exemple.tld"}
	config, err := send.DeriveTransport(context.Background(), nil, "secret-123", request)
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "mail.exemple.tld" || config.Port != 465 || config.Username != "bot" || config.From != "bot@exemple.tld" {
		t.Fatalf("surcharge ignoree: %+v", config)
	}
}

func TestDeriveTransportNeedsIdentity(t *testing.T) {
	if _, err := send.DeriveTransport(context.Background(), nil, "secret-123", send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps"}); err == nil {
		t.Fatal("hote manquant accepte")
	}
}

func TestDeriveTransportRejectsBadRecipient(t *testing.T) {
	if _, err := send.DeriveTransport(context.Background(), nil, "bob@exemple.tld", send.SendRequest{To: "dest", Subject: "test", Body: "corps"}); err == nil {
		t.Fatal("destinataire invalide accepte")
	}
}

func TestDeriveTransportUsesMX(t *testing.T) {
	resolver := &fakeResolver{hosts: []string{"mx1.exemple.tld.", "mx2.exemple.tld."}}
	config, err := send.DeriveTransport(context.Background(), resolver, "bob@exemple.tld", send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "mx1.exemple.tld" || config.Port != 25 || resolver.calls != 1 || resolver.domain != "exemple.tld" {
		t.Fatalf("mx non utilise: %+v %+v", config, resolver)
	}
}

func TestDeriveTransportExplicitHostSkipsResolver(t *testing.T) {
	resolver := &fakeResolver{hosts: []string{"mx.exemple.tld"}}
	config, err := send.DeriveTransport(context.Background(), resolver, "bob@exemple.tld", send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps", Host: "mail.exemple.tld"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "mail.exemple.tld" || resolver.calls != 0 {
		t.Fatalf("surcharge ignoree: %+v", config)
	}
}

func TestDeriveTransportResolverFailureFallsBackToProvider(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("pas de mx")}
	config, err := send.DeriveTransport(context.Background(), resolver, "bob@ovh.net", send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps"})
	if err != nil {
		t.Fatal(err)
	}
	if config.Host != "ssl0.ovh.net" || config.Port != 465 {
		t.Fatalf("table de secours inutilisee: %+v", config)
	}
}

func TestDeriveTransportRejectsHeaderInjection(t *testing.T) {
	if _, err := send.DeriveTransport(context.Background(), nil, "bob@exemple.tld", send.SendRequest{To: "dest@exemple.tld", Subject: "test", Body: "corps", Host: "mail.exemple.tld\r\nX: 1"}); err == nil {
		t.Fatal("hote injecte accepte")
	}
}
