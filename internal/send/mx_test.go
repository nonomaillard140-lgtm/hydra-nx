package send_test

import (
	"context"
	"errors"
	"net"
	"net/textproto"
	"testing"

	"hydra/internal/auth"
	"hydra/internal/send"
	"hydra/internal/store"
)

type fakeResolver struct {
	hosts  []string
	err    error
	calls  int
	domain string
}

func (f *fakeResolver) Lookup(_ context.Context, domain string) ([]string, error) {
	f.calls++
	f.domain = domain
	return f.hosts, f.err
}

func TestResolveHostUsesFirstMX(t *testing.T) {
	resolver := &fakeResolver{hosts: []string{"mx1.exemple.tld.", "mx2.exemple.tld."}}
	host, port, err := send.ResolveHost(context.Background(), resolver, "bob@exemple.tld", "")
	if err != nil {
		t.Fatal(err)
	}
	if host != "mx1.exemple.tld" || port != 587 || resolver.calls != 1 || resolver.domain != "exemple.tld" {
		t.Fatalf("resolution inattendue: %s %d %+v", host, port, resolver)
	}
}

func TestResolveHostFallsBackToProvider(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("pas de mx")}
	host, port, err := send.ResolveHost(context.Background(), resolver, "bob@ovh.net", "")
	if err != nil {
		t.Fatal(err)
	}
	if host != "ssl0.ovh.net" || port != 465 {
		t.Fatalf("table de secours inattendue: %s %d", host, port)
	}
}

func TestResolveHostProviderTemplate(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("pas de mx")}
	host, port, err := send.ResolveHost(context.Background(), resolver, "bob@o2switch.net", "")
	if err != nil {
		t.Fatal(err)
	}
	if host != "mail.o2switch.net" || port != 465 {
		t.Fatalf("gabarit inattendu: %s %d", host, port)
	}
}

func TestResolveHostConvention(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("pas de mx")}
	host, port, err := send.ResolveHost(context.Background(), resolver, "bob@inconnu.tld", "")
	if err != nil {
		t.Fatal(err)
	}
	if host != "smtp.inconnu.tld" || port != 587 {
		t.Fatalf("convention inattendue: %s %d", host, port)
	}
}

func TestResolveHostDomainBoundary(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("pas de mx")}
	host, _, err := send.ResolveHost(context.Background(), resolver, "bob@notgmail.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if host != "smtp.notgmail.com" {
		t.Fatalf("collision de suffixe: %s", host)
	}
}

func TestResolveHostExplicitHostSkipsResolver(t *testing.T) {
	resolver := &fakeResolver{hosts: []string{"mx.exemple.tld"}}
	host, port, err := send.ResolveHost(context.Background(), resolver, "bob@exemple.tld", "mail.exemple.tld")
	if err != nil {
		t.Fatal(err)
	}
	if host != "mail.exemple.tld" || port != 587 || resolver.calls != 0 {
		t.Fatalf("surcharge ignoree: %s %d %d", host, port, resolver.calls)
	}
}

func TestResolveHostRejectsIdentityWithoutDomain(t *testing.T) {
	if _, _, err := send.ResolveHost(context.Background(), &fakeResolver{}, "bob", ""); err == nil {
		t.Fatal("identifiant sans domaine accepte")
	}
}

func TestResolveHostSkipsEmptyMX(t *testing.T) {
	resolver := &fakeResolver{hosts: []string{"", " . ", "mx.exemple.tld."}}
	host, _, err := send.ResolveHost(context.Background(), resolver, "bob@exemple.tld", "")
	if err != nil {
		t.Fatal(err)
	}
	if host != "mx.exemple.tld" {
		t.Fatalf("mx vide retenu: %q", host)
	}
}

func TestClassifySMTPError(t *testing.T) {
	cases := []struct {
		err   error
		code  string
		field string
		kind  string
	}{
		{&textproto.Error{Code: 535, Msg: "auth"}, "auth_refusee", "username", "configuration"},
		{&textproto.Error{Code: 550, Msg: "relay"}, "relais_refuse", "from", "configuration"},
		{&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connexion refusee")}, "hote_injoignable", "host", "network"},
		{&net.DNSError{Err: "i/o timeout", Name: "x.tld", IsTimeout: true}, "timeout", "host", "network"},
		{errors.New("STARTTLS absent avant AUTH"), "tls_refuse", "port", "configuration"},
	}
	for _, item := range cases {
		classified := send.ClassifySMTPError(item.err)
		if classified == nil || classified.Code != item.code || classified.Field != item.field || classified.Kind != item.kind {
			t.Fatalf("classification inattendue pour %v: %+v", item.err, classified)
		}
		if !errors.Is(classified, item.err) {
			t.Fatalf("cause perdue pour %v", item.err)
		}
	}
	if send.ClassifySMTPError(nil) != nil {
		t.Fatal("erreur nulle mal classee")
	}
}

func TestRecordSendKeepsTransport(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("journal-passphrase")
	user, err := st.CreateUser(ctx, "journal@example.com", "journal", hash, "user")
	if err != nil {
		t.Fatal(err)
	}
	record := store.Send{UserID: user.ID, Transport: "smtp", From: "a@exemple.tld", To: "b@exemple.tld", Subject: "s", Status: "failed", Error: "timeout: delai depasse", SMTPHost: "smtp.exemple.tld", SMTPPort: "587", SMTPUser: "a@exemple.tld"}
	if err := st.RecordSend(ctx, record); err != nil {
		t.Fatal(err)
	}
	items, err := st.Sends(ctx, user.ID)
	if err != nil || len(items) != 1 {
		t.Fatalf("journal inattendu: %+v %v", items, err)
	}
	if items[0].SMTPHost != "smtp.exemple.tld" || items[0].SMTPPort != "587" || items[0].SMTPUser != "a@exemple.tld" {
		t.Fatalf("transport non journalise: %+v", items[0])
	}
	if items[0].HitID != 0 {
		t.Fatalf("hit_id nul mal lu: %d", items[0].HitID)
	}
}
