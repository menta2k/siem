package cfrules_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/menta2k/siem/internal/cfrules"
)

func testClient(t *testing.T, handler http.HandlerFunc) *cfrules.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return cfrules.NewClient("test-token", server.URL)
}

func TestZonesAreListedAcrossPages(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page == "1" {
			_, _ = fmt.Fprint(w, `{"success":true,"result":[{"id":"z1","name":"Example.com"}],
				"result_info":{"page":1,"total_pages":2}}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"success":true,"result":[{"id":"z2","name":"shop.example.net"}],
			"result_info":{"page":2,"total_pages":2}}`)
	})

	zones, err := client.Zones(context.Background())
	if err != nil {
		t.Fatalf("Zones(): %v", err)
	}

	if len(zones) != 2 {
		t.Fatalf("got %d zones, want 2 — the second page was dropped: %+v", len(zones), zones)
	}
	// Lower-cased, because the events carry the zone name as Cloudflare logs it and a
	// case difference would silently resolve nothing.
	if zones[0].Name != "example.com" {
		t.Errorf("zone name = %q, want it normalised to lower case", zones[0].Name)
	}
}

func TestRulesCarryTheDescription(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"success":true,"result":{"rules":[
			{"id":"r1","description":"SQLi - Body detection","action":"block",
			 "ref":"ref1","categories":["sqli","owasp"]},
			{"id":"r2","description":" Custom - block scrapers ","action":"managed_challenge"}
		]}}`)
	})

	rules, err := client.Rules(context.Background(), "z1", "rs1")
	if err != nil {
		t.Fatalf("Rules(): %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Description != "SQLi - Body detection" || rules[0].Action != "block" {
		t.Errorf("first rule = %+v", rules[0])
	}
	if len(rules[0].Categories) != 2 || rules[0].Ref != "ref1" {
		t.Errorf("managed rule lost its ref or categories: %+v", rules[0])
	}
	// Trimmed: a stray space in a customer's description becomes a stray space in the
	// console, on every row the rule matched.
	if rules[1].Description != "Custom - block scrapers" {
		t.Errorf("description = %q, want it trimmed", rules[1].Description)
	}
}

func TestRulesetsAreListed(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"success":true,"result":[
			{"id":"rs1","name":"Cloudflare Managed Ruleset","kind":"managed",
			 "phase":"http_request_firewall_managed"},
			{"id":"rs2","name":"default","kind":"zone","phase":"http_request_firewall_custom"}
		]}`)
	})

	rulesets, err := client.Rulesets(context.Background(), "z1")
	if err != nil {
		t.Fatalf("Rulesets(): %v", err)
	}

	if len(rulesets) != 2 || rulesets[0].Kind != "managed" || rulesets[1].Phase == "" {
		t.Errorf("rulesets = %+v", rulesets)
	}
}

// Cloudflare reports a permission failure INSIDE a 200 as often as by status code. A
// client that checks only the status reads "your token cannot see this" as "this zone
// has no rules", and the console would then show an empty table for a token that simply
// lacks Zone WAF Read.
func TestAnErrorInsideASuccessfulResponseIsAnError(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],
			"result":null}`)
	})

	_, err := client.Zones(context.Background())
	if err == nil {
		t.Fatal("Zones() reported success on an authentication error")
	}
	if !strings.Contains(err.Error(), "Authentication error") {
		t.Errorf("error = %v, want Cloudflare's own message", err)
	}
}

func TestAnHTTPErrorIsReported(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	if _, err := client.Rulesets(context.Background(), "z1"); err == nil {
		t.Fatal("Rulesets() ignored a 403")
	}
}

// The token authorises reading a customer's WAF configuration. It must reach the API
// and appear nowhere else — least of all in an error string that gets logged.
func TestTheTokenIsSentAsABearerAndNeverInAnError(t *testing.T) {
	var seen string
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := client.Zones(context.Background())
	if err == nil {
		t.Fatal("expected an error")
	}
	if seen != "Bearer test-token" {
		t.Errorf("Authorization = %q, want a bearer token", seen)
	}
	if strings.Contains(err.Error(), "test-token") {
		t.Errorf("the token leaked into an error string: %v", err)
	}
}
