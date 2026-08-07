package service

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kratos/kratos/v2/transport"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

// refreshCookieName is the cookie carrying the refresh token.
//
// The __Host- prefix is enforced by the browser: it refuses the cookie unless it is
// Secure, has no Domain, and has Path=/. That makes the guarantees below impossible to
// weaken later by editing one attribute — a subdomain cannot set or overwrite it, which
// matters because a refresh token mints access tokens.
const refreshCookieName = "__Host-siem_refresh"

// setRefreshCookie stores the refresh token where JavaScript cannot read it.
//
// This is what lets a session survive a browser reload. The access token deliberately
// stays in memory and dies with the page — but the refresh token has to outlive it, and
// the only place it can do that safely is an httpOnly cookie: localStorage would put the
// LONGER-lived and more valuable credential somewhere any XSS can read it, in a console
// that renders vendor-controlled strings.
//
// SameSite=Strict is the CSRF defence for the refresh endpoint: the browser will not
// attach the cookie to a cross-site request, so another origin cannot mint tokens with
// it. Path is / because the __Host- prefix requires it — narrowing the path to the auth
// routes would be tidier but the browser would then reject the cookie outright.
func setRefreshCookie(ctx context.Context, token string, expiresAt time.Time) {
	writeCookie(ctx, newRefreshCookie(token, expiresAt))
}

// clearRefreshCookie removes the cookie on sign-out.
//
// A logout that revokes the token server-side but leaves the cookie in place would have
// the browser keep presenting a dead credential on every refresh attempt.
func clearRefreshCookie(ctx context.Context) {
	// gosec cannot see through newRefreshCookie to the composite literal, so it reports
	// the attributes as missing. They are set there — HttpOnly, Secure, SameSite=Strict —
	// and TestTheCookieCarriesItsSecurityAttributes asserts every one of them on the
	// rendered header, so the property this rule protects is checked, just not here.
	//nolint:gosec // attributes are set and asserted in newRefreshCookie
	cookie := newRefreshCookie("", time.Time{})
	cookie.MaxAge = -1
	writeCookie(ctx, cookie)
}

// refreshCookie reads the refresh token the browser sent.
func refreshCookie(ctx context.Context) string {
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		return ""
	}
	ht, ok := tr.(khttp.Transporter)
	if !ok {
		return ""
	}
	return refreshCookieFrom(ht.Request())
}

// refreshCookieFrom reads the cookie off a request.
//
// Split from refreshCookie so the behaviour can be exercised against a plain
// *http.Request rather than a kratos transport, whose fields cannot be constructed
// outside the package that owns it.
func refreshCookieFrom(req *http.Request) string {
	if req == nil {
		return ""
	}
	cookie, err := req.Cookie(refreshCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// newRefreshCookie builds the cookie separately from writing it, so its attributes can
// be asserted directly — they ARE the security model here.
func newRefreshCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

// writeCookie appends a Set-Cookie header to the reply.
//
// Added rather than set: a reply may legitimately carry more than one cookie, and
// overwriting the header would silently drop the others.
func writeCookie(ctx context.Context, cookie *http.Cookie) {
	tr, ok := transport.FromServerContext(ctx)
	if !ok {
		return
	}
	tr.ReplyHeader().Add("Set-Cookie", cookie.String())
}
