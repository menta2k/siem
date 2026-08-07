package receiver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func request(t *testing.T, url, authHeader string) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, url, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	return req
}

func TestTheAuthorizationHeaderIsUsedWhenPresent(t *testing.T) {
	got, ok := credentialFrom(request(t, "/ingest/v1/datadome/abc", "Bearer header-token"))

	if !ok || got != "header-token" {
		t.Errorf("credentialFrom = %q, %v; want the header token", got, ok)
	}
}

// The reason this exists: DataDome's webhook configuration has no field for a custom
// header — only a name, a URL, a payload format and severity filters. Without a query
// fallback that vendor cannot authenticate at all.
func TestAQueryTokenIsAcceptedWhenNoHeaderIsPossible(t *testing.T) {
	got, ok := credentialFrom(request(t, "/ingest/v1/datadome/abc?token=query-token", ""))

	if !ok || got != "query-token" {
		t.Errorf("credentialFrom = %q, %v; want the query token", got, ok)
	}
}

// A vendor that can send a header must never be silently downgraded to the weaker
// channel just because a query parameter happens to be present too.
func TestTheHeaderWinsOverTheQueryParameter(t *testing.T) {
	got, ok := credentialFrom(
		request(t, "/ingest/v1/datadome/abc?token=query-token", "Bearer header-token"))

	if !ok || got != "header-token" {
		t.Errorf("credentialFrom = %q; the query parameter must not override the header", got)
	}
}

func TestNoCredentialAnywhereIsRejected(t *testing.T) {
	for name, url := range map[string]string{
		"nothing at all": "/ingest/v1/datadome/abc",
		"empty token":    "/ingest/v1/datadome/abc?token=",
		"other params":   "/ingest/v1/datadome/abc?foo=bar",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := credentialFrom(request(t, url, "")); ok {
				t.Error("a request with no credential was accepted")
			}
		})
	}
}

// A malformed Authorization header must fall through to the query parameter rather than
// failing outright — otherwise a vendor sending a stray header locks itself out.
func TestAMalformedHeaderFallsBackToTheQueryToken(t *testing.T) {
	got, ok := credentialFrom(
		request(t, "/ingest/v1/datadome/abc?token=query-token", "NotBearer whatever"))

	if !ok || got != "query-token" {
		t.Errorf("credentialFrom = %q, %v; want the query token", got, ok)
	}
}
