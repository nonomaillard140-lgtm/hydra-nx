package jsintel

import (
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const MaxScripts = 12

var (
	scriptPattern   = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	mapPattern      = regexp.MustCompile(`(?i)sourcemappingurl=([^\s*]+)`)
	endpointPattern = regexp.MustCompile("[\"'\x60](/(?:api|v1|v2|graphql|rest|admin|internal|auth)[a-zA-Z0-9_\\-/.]*)[\"'\x60]")
)

func absolute(base *url.URL, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return "", false
	}
	parsed, err := base.Parse(ref)
	if err != nil || parsed.Host != base.Host {
		return "", false
	}
	parsed.Fragment = ""
	return parsed.String(), true
}

func Scripts(page []byte, base *url.URL) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, MaxScripts)
	for _, match := range scriptPattern.FindAllSubmatch(page, 200) {
		full, ok := absolute(base, string(match[1]))
		if !ok {
			continue
		}
		if _, duplicate := seen[full]; duplicate {
			continue
		}
		seen[full] = struct{}{}
		out = append(out, full)
		if len(out) >= MaxScripts {
			break
		}
	}
	sort.Strings(out)
	return out
}

func Maps(body []byte, base *url.URL) []string {
	out := make([]string, 0, 4)
	for _, match := range mapPattern.FindAllSubmatch(body, 8) {
		if full, ok := absolute(base, string(match[1])); ok {
			out = append(out, full)
		}
	}
	return out
}

func Endpoints(body []byte) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 32)
	for _, match := range endpointPattern.FindAllSubmatch(body, 400) {
		path := string(match[1])
		if len(path) < 5 || len(path) > 120 {
			continue
		}
		if _, duplicate := seen[path]; duplicate {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
		if len(out) >= 50 {
			break
		}
	}
	sort.Strings(out)
	return out
}

type Library struct {
	Name       string
	Version    string
	Vulnerable bool
	Note       string
}

type rule struct {
	name    string
	pattern *regexp.Regexp
	fixed   string
	note    string
}

var rules = []rule{
	{"jquery", regexp.MustCompile(`(?i)jquery[/@-]?v?(\d+\.\d+\.\d+)`), "3.5.0", "CVE-2020-11022 et 11023"},
	{"lodash", regexp.MustCompile(`(?i)lodash[/@-]?v?(\d+\.\d+\.\d+)`), "4.17.21", "CVE-2021-23337"},
	{"bootstrap", regexp.MustCompile(`(?i)bootstrap[/@-]?v?(\d+\.\d+\.\d+)`), "3.4.1", "CVE-2019-8331"},
	{"moment", regexp.MustCompile(`(?i)moment[/@-]?v?(\d+\.\d+\.\d+)`), "2.29.4", "CVE-2022-31129"},
	{"angular", regexp.MustCompile(`(?i)angular[/@-]?v?(1\.\d+\.\d+)`), "1.8.0", "CVE-2020-7676"},
}

func Libraries(body []byte) []Library {
	out := make([]Library, 0, 4)
	seen := make(map[string]struct{})
	for _, entry := range rules {
		for _, match := range entry.pattern.FindAllSubmatch(body, 5) {
			version := string(match[1])
			if _, duplicate := seen[entry.name+version]; duplicate {
				continue
			}
			seen[entry.name+version] = struct{}{}
			out = append(out, Library{Name: entry.name, Version: version, Vulnerable: less(version, entry.fixed), Note: entry.note})
		}
	}
	return out
}

func less(a, b string) bool {
	left := strings.Split(a, ".")
	right := strings.Split(b, ".")
	for i := 0; i < len(left) && i < len(right); i++ {
		x, _ := strconv.Atoi(left[i])
		y, _ := strconv.Atoi(right[i])
		if x != y {
			return x < y
		}
	}
	return len(left) < len(right)
}
