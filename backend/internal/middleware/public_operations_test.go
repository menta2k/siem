package middleware

import (
	"testing"

	siemv1 "github.com/menta2k/siem/api/gen/siem/v1"
)

// THE BUG THIS CATCHES. The allow-list was hand-written as a string literal and named an
// operation — "/siem.v1.Auth/RefreshToken" — that the proto does not define; the RPC is
// Refresh. A key that matches nothing fails SILENTLY and in the safe direction: the route
// simply stayed authenticated, so nothing broke until a caller with no access token used
// it. That caller is session restore after a page reload, where the httpOnly refresh
// cookie is the only surviving credential and there is no bearer token by definition.
//
// Comparing against the generated constants is what makes the drift impossible: rename an
// RPC and this fails to compile rather than quietly re-closing a route that is meant to be
// open.
func TestEveryPublicOperationNamesARealRPC(t *testing.T) {
	defined := map[string]bool{
		siemv1.OperationAuthLogin:         true,
		siemv1.OperationAuthVerifyMFA:     true,
		siemv1.OperationAuthRefresh:       true,
		siemv1.OperationAuthLogout:        true,
		siemv1.OperationAuthMe:            true,
		siemv1.OperationAuthPreviewInvite: true,
		siemv1.OperationAuthRedeemInvite:  true,
	}

	for operation := range publicOperations {
		if !defined[operation] {
			t.Errorf("public operation %q matches no RPC — the route is still authenticated",
				operation)
		}
	}
}

// Refresh in particular MUST be public: it is the one endpoint whose entire purpose is to
// be called without a valid access token.
func TestRefreshIsReachableWithoutAnAccessToken(t *testing.T) {
	if !publicOperations[siemv1.OperationAuthRefresh] {
		t.Error("Refresh requires a bearer token, so no session can be restored from the cookie")
	}
}

// The opposite guarantee. The allow-list bypasses authentication AND the role policy, so
// an entry added by accident is an unauthenticated route. Only the pre-sign-in steps
// belong here — Me and Logout both run with a live access token.
//
// The two invite operations qualify on the same test: a setup token is redeemed by
// someone who has no account to sign in to yet. They are listed one by one rather than
// admitted by a path prefix, so the next /api/v1/auth/* route added is authenticated
// until somebody deliberately decides otherwise here.
func TestOnlyThePreSignInStepsArePublic(t *testing.T) {
	expected := map[string]bool{
		siemv1.OperationAuthLogin:         true,
		siemv1.OperationAuthVerifyMFA:     true,
		siemv1.OperationAuthRefresh:       true,
		siemv1.OperationAuthPreviewInvite: true,
		siemv1.OperationAuthRedeemInvite:  true,
	}

	if len(publicOperations) != len(expected) {
		t.Errorf("public operations = %v, want exactly %v", publicOperations, expected)
	}
	for operation := range publicOperations {
		if !expected[operation] {
			t.Errorf("%q is reachable with no authentication at all", operation)
		}
	}
}
