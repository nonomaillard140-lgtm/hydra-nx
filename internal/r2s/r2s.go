package r2s

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// CVE-2025-55182 / CVE-2025-66478 — React2Shell.
// Sonde sûre : aucun code n'est exécuté sur la cible, seule la
// notation $1:a:a appliquée à un objet vide provoque l'exception
// 500 sur les versions vulnérables de React Server Components.

const boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

const routerStateTree = "%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"

var markers = []string{"/_next/static/", "self.__next_f", "__next_data__"}

// NextJS reconnaît une page servie par Next.js à partir de son HTML.
func NextJS(body []byte) bool {
	lower := bytes.ToLower(body)
	for _, marker := range markers {
		if bytes.Contains(lower, []byte(marker)) {
			return true
		}
	}
	return false
}

// Payload construit le corps multipart attendu par le protocole RSC.
func Payload() string {
	var body strings.Builder
	body.WriteString("--" + boundary + "\r\n")
	body.WriteString("Content-Disposition: form-data; name=\"1\"\r\n\r\n")
	body.WriteString("{}\r\n")
	body.WriteString("--" + boundary + "\r\n")
	body.WriteString("Content-Disposition: form-data; name=\"0\"\r\n\r\n")
	body.WriteString("[\"$1:a:a\"]\r\n")
	body.WriteString("--" + boundary + "--\r\n")
	return body.String()
}

// Result porte la preuve observée. Vulnerable n'est vrai que sur la
// combinaison stricte 500 + text/x-component + digest.
type Result struct {
	Vulnerable bool
	Status     int
	Digest     string
}

func Probe(ctx context.Context, client *http.Client, target *url.URL) (Result, error) {
	if client == nil || target == nil {
		return Result{}, errors.New("client ou cible absent")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), strings.NewReader(Payload()))
	if err != nil {
		return Result{}, err
	}
	request.Header.Set("User-Agent", "Hydra-Defensive-Scanner/1.0")
	request.Header.Set("Accept", "text/x-component")
	request.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	request.Header.Set("Next-Action", "x")
	request.Header.Set("Next-Router-State-Tree", routerStateTree)
	request.Header.Set("X-Nextjs-Request-Id", "b5dce965")
	request.Header.Set("X-Nextjs-Html-Request-Id", "SSTMXm7OJ_g0Ncx6jpQt9")
	response, err := client.Do(request)
	if err != nil {
		return Result{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return Result{}, err
	}
	result := Result{Status: response.StatusCode}
	if response.StatusCode != http.StatusInternalServerError {
		return result, nil
	}
	if !strings.Contains(response.Header.Get("Content-Type"), "text/x-component") {
		return result, nil
	}
	offset := bytes.Index(raw, []byte("E{\"digest\""))
	if offset < 0 {
		return result, nil
	}
	result.Vulnerable = true
	result.Digest = digest(raw[offset:])
	return result, nil
}

func digest(chunk []byte) string {
	text := string(chunk)
	start := strings.Index(text, "\"digest\":\"")
	if start < 0 {
		return ""
	}
	rest := text[start+len("\"digest\":\""):]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return ""
	}
	if end > 40 {
		end = 40
	}
	return rest[:end]
}
