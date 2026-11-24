package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hydra/internal/api"
	"hydra/internal/auth"
	"hydra/internal/scan"
	"hydra/internal/store"
)

func TestLoginAndAuthorizedInventory(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("admin-passphrase")
	_, err = st.CreateUser(ctx, "admin@example.com", "admin", hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	scheduler := scan.NewScheduler(st, 1, 2, 2)
	server := httptest.NewServer(api.NewServer(st, auth.NewService(st), scheduler, false).Router())
	defer server.Close()
	response, err := http.Get(server.URL + "/login")
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("/login: %d %v", response.StatusCode, err)
	}
	response.Body.Close()
	body := bytes.NewBufferString(`{"identity":"admin","password":"admin-passphrase","device_fingerprint":"test-device"}`)
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/api/auth/login", body)
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %v", response.StatusCode, err)
	}
	cookies := response.Cookies()
	response.Body.Close()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		t.Fatalf("cookie de session absent ou non HttpOnly: %v", cookies)
	}
	listBody := bytes.NewBufferString(`{"name":"lab","kind":"L7","items":["example.com"],"authorized":true}`)
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/api/lists", listBody)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Requested-With", "XMLHttpRequest")
	request.AddCookie(cookies[0])
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusCreated {
		t.Fatalf("création liste: %d %v", response.StatusCode, err)
	}
	var list store.List
	if err := json.NewDecoder(response.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if list.Size != 1 || !list.Authorized {
		t.Fatalf("liste créée incorrecte: %+v", list)
	}
	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/paths", nil)
	request.AddCookie(cookies[0])
	response, err = http.DefaultClient.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("corpus: %d %v", response.StatusCode, err)
	}
	response.Body.Close()
}

func TestPublicDownloadsNeedNoJavaScript(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := store.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	scheduler := scan.NewScheduler(st, 1, 2, 2)
	server := httptest.NewServer(api.NewServer(st, auth.NewService(st), scheduler, false).Router())
	defer server.Close()
	response, err := http.Get(server.URL + "/lists")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("page publique invalide: %d %s", response.StatusCode, response.Header.Get("Content-Type"))
	}
}
