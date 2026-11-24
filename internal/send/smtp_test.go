package send_test

import (
	"context"
	"strings"
	"testing"

	"hydra/internal/send"
	"hydra/internal/store"
)

func TestSMTPConfigEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	manager := send.NewManager(st)
	config := send.SMTPConfig{Host: "smtp.example.com", Port: 587, Username: "operator", Password: "private-password", From: "from@example.com", ControlAddress: "control@example.com"}
	if err := manager.Configure(ctx, config); err != nil {
		t.Fatal(err)
	}
	raw, err := st.Setting(ctx, "smtp_control_config")
	if err != nil || !strings.HasPrefix(raw, "enc:") || strings.Contains(raw, config.Password) {
		t.Fatalf("configuration non chiffrée: %s", raw)
	}
	loaded, err := manager.Config(ctx)
	if err != nil || loaded.ControlAddress != config.ControlAddress || loaded.Password != config.Password {
		t.Fatalf("configuration restaurée incorrecte: %+v %v", loaded, err)
	}
	if err := manager.Configure(ctx, send.SMTPConfig{Host: "bad host", From: "invalid"}); err == nil {
		t.Fatal("configuration invalide acceptée")
	}
}
