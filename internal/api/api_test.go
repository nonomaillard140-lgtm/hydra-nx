package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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

func TestClearScansEndpoint(t *testing.T) {
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
	user, err := st.CreateUser(ctx, "admin@example.com", "admin", hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	scheduler := scan.NewScheduler(st, 1, 2, 2)
	server := httptest.NewServer(api.NewServer(st, auth.NewService(st), scheduler, false).Router())
	defer server.Close()
	call := func(method, path, body string, cookie *http.Cookie) *http.Response {
		var reader io.Reader
		if body != "" {
			reader = bytes.NewBufferString(body)
		}
		request, _ := http.NewRequest(method, server.URL+path, reader)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Requested-With", "XMLHttpRequest")
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	login := call(http.MethodPost, "/api/auth/login", `{"identity":"admin","password":"admin-passphrase","device_fingerprint":"test-device"}`, nil)
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", login.StatusCode)
	}
	cookie := login.Cookies()[0]
	login.Body.Close()
	created := call(http.MethodPost, "/api/lists", `{"name":"lab","kind":"L7","items":["example.com"],"authorized":true}`, cookie)
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("liste: %d", created.StatusCode)
	}
	var list store.List
	if err := json.NewDecoder(created.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	created.Body.Close()
	probe := call(http.MethodPost, "/api/paths", `{"raw":"/.env","tags":"config"}`, cookie)
	if probe.StatusCode != http.StatusCreated {
		t.Fatalf("chemin: %d", probe.StatusCode)
	}
	var path store.Path
	if err := json.NewDecoder(probe.Body).Decode(&path); err != nil {
		t.Fatal(err)
	}
	probe.Body.Close()
	crack, err := st.CreateCrack(ctx, user.ID, list.ID, path.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetCrackStatus(ctx, crack.ID, "completed", "{}"); err != nil {
		t.Fatal(err)
	}
	purge := call(http.MethodDelete, "/api/scans", "", cookie)
	if purge.StatusCode != http.StatusOK {
		t.Fatalf("purge: %d", purge.StatusCode)
	}
	purge.Body.Close()
	history := call(http.MethodGet, "/api/scans", "", cookie)
	defer history.Body.Close()
	var scans []store.Crack
	if err := json.NewDecoder(history.Body).Decode(&scans); err != nil {
		t.Fatal(err)
	}
	if len(scans) != 0 {
		t.Fatalf("historique résiduel: %d", len(scans))
	}
	remove := call(http.MethodDelete, "/api/lists/1", "", cookie)
	defer remove.Body.Close()
	if remove.StatusCode != http.StatusOK {
		t.Fatalf("suppression liste: %d", remove.StatusCode)
	}
}
