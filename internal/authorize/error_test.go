package authorize

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestRedirectionErrorAs(t *testing.T) {
	// Given.
	redirectErr := newRedirectionError(goidc.ErrorCodeAccessDenied, "", goidc.AuthorizationParameters{})
	var oidcErr goidc.Error

	// When.
	ok := errors.As(redirectErr, &oidcErr)

	// Then.
	if !ok {
		t.Fatal()
	}

	if oidcErr.Code != goidc.ErrorCodeAccessDenied {
		t.Errorf("got %s, want access_denied", oidcErr.Code)
	}
}
