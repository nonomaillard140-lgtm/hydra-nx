package fuzz

import (
	"crypto/sha256"
	"regexp"
	"strings"
)

type Response struct {
	Status int
	Body   []byte
}

type Signature struct {
	Status int    `json:"status"`
	Length int    `json:"length"`
	Hash   string `json:"hash"`
}

type Decision struct {
	Divergent bool
	Reason    string
}

var dynamicTokens = regexp.MustCompile(`(?i)(?:nonce|csrf|request[_-]?id|timestamp)["'\s:=]+[a-z0-9._-]{8,}`)

func Normalize(body []byte) []byte {
	normalized := dynamicTokens.ReplaceAll(body, []byte("dynamic-value"))
	return []byte(strings.Join(strings.Fields(string(normalized)), " "))
}

func Sign(response Response) Signature {
	normalized := Normalize(response.Body)
	return Signature{Status: response.Status, Length: len(normalized), Hash: stringHash(normalized)}
}

func stringHash(body []byte) string {
	sum := sha256.Sum256(body)
	return string(sum[:])
}

func Compare(baseline, candidate Response) Decision {
	base := Sign(baseline)
	probe := Sign(candidate)
	if candidate.Status != 200 {
		return Decision{Reason: "statut non exposé"}
	}
	if baseline.Status != 403 && baseline.Status != 404 {
		return Decision{Reason: "référence non concluante"}
	}
	if base.Hash == probe.Hash {
		return Decision{Reason: "corps identique à la référence"}
	}
	if len(Normalize(candidate.Body)) < 24 {
		return Decision{Reason: "réponse trop courte, leur présumé"}
	}
	return Decision{Divergent: true, Reason: "exposition différente de la référence"}
}

func RegularResponses(responses []Response) bool {
	if len(responses) < 3 {
		return false
	}
	seen := make(map[Signature]int)
	for _, response := range responses {
		seen[Sign(response)]++
	}
	for _, count := range seen {
		if count == len(responses) {
			return true
		}
	}
	return false
}
