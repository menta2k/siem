package service

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTheRefreshCookieIsReadFromTheRequest(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: "the-token"})

	if got := refreshCookieFrom(req); got != "the-token" {
		t.Errorf("refreshCookieFrom = %q, want the-token", got)
	}
}

func TestAnAbsentCookieReadsAsEmpty(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/auth/refresh", nil)

	if got := refreshCookieFrom(req); got != "" {
		t.Errorf("refreshCookieFrom = %q, want empty", got)
	}
	if got := refreshCookieFrom(nil); got != "" {
		t.Errorf("a nil request gave %q, want empty", got)
	}
}

// The attributes ARE the security model. httpOnly is what keeps the long-lived
// credential out of reach of injected script — without it this change would be strictly
// worse than the in-memory token it replaces, because a refresh token mints access
// tokens and outlives every one of them.
func TestTheCookieCarriesItsSecurityAttributes(t *testing.T) {
	rendered := newRefreshCookie("t", time.Now().Add(time.Hour)).String()

	for _, attr := range []string{"HttpOnly", "Secure", "SameSite=Strict", "Path=/"} {
		if !strings.Contains(rendered, attr) {
			t.Errorf("cookie is missing %s: %s", attr, rendered)
		}
	}
}

// The __Host- prefix is enforced by the BROWSER: it refuses the cookie unless it is
// Secure, carries no Domain and uses Path=/. That makes the attributes above impossible
// to weaken later by editing one of them, and stops a subdomain overwriting the cookie.
func TestTheCookieUsesTheHostPrefix(t *testing.T) {
	if !strings.HasPrefix(refreshCookieName, "__Host-") {
		t.Errorf("cookie name %q lacks the __Host- prefix", refreshCookieName)
	}
	rendered := newRefreshCookie("t", time.Now().Add(time.Hour)).String()
	if strings.Contains(rendered, "Domain=") {
		t.Errorf("a __Host- cookie must carry no Domain: %s", rendered)
	}
}

// Sign-out must actually expire it. Revoking server-side while leaving the cookie has
// the browser present a dead credential on every reload — a slow failure rather than an
// immediate one.
func TestClearingTheCookieExpiresIt(t *testing.T) {
	cookie := newRefreshCookie("", time.Time{})
	cookie.MaxAge = -1

	rendered := cookie.String()
	if !strings.Contains(rendered, "Max-Age=0") {
		t.Errorf("cleared cookie does not expire: %s", rendered)
	}
}

// The refresh token's own expiry, not the access token's. A cookie dated with the
// access expiry would evict itself within minutes and log the user out exactly as if no
// cookie existed — which is the bug this whole change exists to fix.
func TestTheCookieOutlivesTheAccessToken(t *testing.T) {
	refreshExpiry := time.Now().Add(168 * time.Hour)
	cookie := newRefreshCookie("t", refreshExpiry)

	if cookie.Expires.Before(time.Now().Add(time.Hour)) {
		t.Errorf("cookie expires at %s, too soon to survive a session", cookie.Expires)
	}
}
