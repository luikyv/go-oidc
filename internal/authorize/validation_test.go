package authorize

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestValidateRequest(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)

	req := request{
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
			Scopes:       client.ScopeIDs,
			State:        "random_state",
			Nonce:        "random_nonce",
		},
	}

	// When.
	err := validateRequest(ctx, req, client)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_InvalidResponseType(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.ResponseTypes = nil

	req := request{
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
			Scopes:       client.ScopeIDs,
			State:        "random_state",
			Nonce:        "random_nonce",
		},
	}

	// When.
	err := validateRequest(ctx, req, client)

	// Then.
	if err == nil {
		t.Fatalf("no error for invalid response type")
	}

	var redirectErr redirectionError
	if !errors.As(err, &redirectErr) {
		t.Fatalf("the error should be redirected")
	}

	if redirectErr.Code() != goidc.ErrorCodeInvalidRequest {
		t.Errorf("code = %s, want %s", redirectErr.Code(), goidc.ErrorCodeInvalidRequest)
	}
}

func TestValidateRequest_InvalidScope(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)

	req := request{
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
			Scopes:       "invalid_scope",
			State:        "random_state",
			Nonce:        "random_nonce",
		},
	}

	// When.
	err := validateRequest(ctx, req, client)

	// Then.
	if err == nil {
		t.Fatalf("no error for invalid scope")
	}

	var redirectErr redirectionError
	if !errors.As(err, &redirectErr) {
		t.Fatalf("the error should be redirected")
	}

	if redirectErr.Code() != goidc.ErrorCodeInvalidScope {
		t.Errorf("code = %s, want %s", redirectErr.Code(), goidc.ErrorCodeInvalidScope)
	}
}

func TestValidateRequest_InvalidRedirectURI(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)

	req := request{
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  "https://invalid.com",
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
			Scopes:       client.ScopeIDs,
			State:        "random_state",
			Nonce:        "random_nonce",
		},
	}

	// When.
	err := validateRequest(ctx, req, client)

	// Then.
	if err == nil {
		t.Fatalf("no error for invalid redirect uri")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("the error should not be redirected")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
		t.Errorf("code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
	}
}

func TestValidateRequest_ResourceIndicator(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.ResourceIndicatorsIsEnabled = true
	ctx.Resources = []string{"https://resource.com"}
	client, _ := oidctest.NewClient(t)

	req := request{
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			ResponseType: goidc.ResponseTypeCode,
			Scopes:       client.ScopeIDs,
			Resources:    []string{"https://resource.com"},
		},
	}

	// When.
	err := validateRequest(ctx, req, client)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_ResourceIndicator_InvalidResource(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.ResourceIndicatorsIsEnabled = true
	ctx.Resources = []string{"https://resource.com"}
	client, _ := oidctest.NewClient(t)

	req := request{
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			ResponseType: goidc.ResponseTypeCode,
			Scopes:       client.ScopeIDs,
			Resources:    []string{"https://invalid.com"},
		},
	}

	// When.
	err := validateRequest(ctx, req, client)

	// Then.
	if err == nil {
		t.Fatalf("no error for invalid redirect uri")
	}

	var redirectErr redirectionError
	if !errors.As(err, &redirectErr) {
		t.Fatalf("the error should be redirected")
	}

	if redirectErr.Code() != goidc.ErrorCodeInvalidTarget {
		t.Errorf("code = %s, want %s", redirectErr.Code(), goidc.ErrorCodeInvalidTarget)
	}
}

func TestValidateRequest_PAR(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	session := &goidc.AuthnSession{
		ClientID:           client.ID,
		ExpiresAtTimestamp: timeutil.TimestampNow() + 10,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			ResponseType: goidc.ResponseTypeCodeAndIDToken,
		},
	}
	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			Scopes:       goidc.ScopeOpenID.ID,
			Nonce:        "random_nonce",
			ResponseType: goidc.ResponseTypeCodeAndIDToken,
		},
	}

	// When.
	err := validateRequestWithPAR(ctx, req, session, client)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_JAR(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  client.RedirectURIs[0],
			ResponseType: goidc.ResponseTypeCode,
			ResponseMode: goidc.ResponseModeQuery,
			Scopes:       client.ScopeIDs,
			Nonce:        "random_nonce",
		},
	}
	jar := request{
		ClientID:                client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{},
	}

	// When.
	err := validateRequestWithJAR(ctx, req, jar, client)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_JAR_InvalidClientID(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)

	req := request{
		ClientID: client.ID,
	}
	jar := request{
		ClientID: "invalid_client_id",
	}

	// When.
	err := validateRequestWithJAR(ctx, req, jar, client)

	// Then.
	if err == nil {
		t.Fatalf("no error for invalid client id")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("the error should not be redirected")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestValidatePushedRequest(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	client.RedirectURIs = append(client.RedirectURIs, "https://example.com")

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  "https://example.com",
			ResponseType: goidc.ResponseTypeCode,
			State:        "random_state",
		},
	}

	// When.
	err := validatePushedRequest(ctx, req, client)

	// Then.
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidatePushedRequest_RedirectURIIsRequiredForFAPI2(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.Profile = goidc.ProfileFAPI2
	client, _ := oidctest.NewClient(t)
	client.RedirectURIs = append(client.RedirectURIs, "https://example.com")

	req := request{
		ClientID: client.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			RedirectURI:  "https://example.com",
			ResponseType: goidc.ResponseTypeCode,
		},
	}

	// When.
	err := validatePushedRequest(ctx, req, client)

	// Then.
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidatePushedRequest_RedirectURIIsRequiredForFAPI2_RedirectURINotInformed(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.Profile = goidc.ProfileFAPI2
	client, _ := oidctest.NewClient(t)
	client.RedirectURIs = append(client.RedirectURIs, "https://example.com")

	req := request{}

	// When.
	err := validatePushedRequest(ctx, req, client)

	// Then.
	if err == nil {
		t.Error("the redirect uri was not informed")
	}
}

// RFC 8252 - OAuth 2.0 for Native Apps tests

func TestIsRedirectURIAllowed_ExactMatch(t *testing.T) {
	// Given.
	client, _ := oidctest.NewClient(t)
	client.RedirectURIs = []string{"https://example.com/callback"}

	// When.
	allowed := isRedirectURIAllowed(client, "https://example.com/callback")

	// Then.
	if !allowed {
		t.Error("exact match should be allowed")
	}
}

func TestIsRedirectURIAllowed_LoopbackIPv4WithPort(t *testing.T) {
	// Given.
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeNative
	client.RedirectURIs = []string{"http://127.0.0.1/callback"}

	// When.
	allowed := isRedirectURIAllowed(client, "http://127.0.0.1:8080/callback")

	// Then.
	if !allowed {
		t.Error("loopback IPv4 with port should be allowed for native apps")
	}
}

func TestIsRedirectURIAllowed_LoopbackIPv6WithPort(t *testing.T) {
	// Given.
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeNative
	client.RedirectURIs = []string{"http://[::1]/callback"}

	// When.
	allowed := isRedirectURIAllowed(client, "http://[::1]:9000/callback")

	// Then.
	if !allowed {
		t.Error("loopback IPv6 with port should be allowed for native apps")
	}
}

func TestIsRedirectURIAllowed_LoopbackNotRegistered(t *testing.T) {
	// Given.
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeNative
	client.RedirectURIs = []string{"https://example.com/callback"}

	// When.
	allowed := isRedirectURIAllowed(client, "http://127.0.0.1:8080/callback")

	// Then.
	if allowed {
		t.Error("loopback should not be allowed if base URI is not registered")
	}
}

func TestIsRedirectURIAllowed_LoopbackNonNativeApp(t *testing.T) {
	// Given.
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeWeb
	client.RedirectURIs = []string{"http://127.0.0.1/callback"}

	// When.
	allowed := isRedirectURIAllowed(client, "http://127.0.0.1:8080/callback")

	// Then.
	if allowed {
		t.Error("loopback with port should not be allowed for web apps")
	}
}

func TestIsRedirectURIAllowed_PrivateScheme(t *testing.T) {
	// Given.
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeNative
	client.RedirectURIs = []string{"com.example.app://callback"}

	// When.
	allowed := isRedirectURIAllowed(client, "com.example.app://callback")

	// Then.
	if !allowed {
		t.Error("private-use URI scheme should be allowed for native apps")
	}
}

func TestIsRedirectURIAllowed_InvalidURI(t *testing.T) {
	// Given.
	client, _ := oidctest.NewClient(t)
	client.ApplicationType = goidc.ApplicationTypeNative
	client.RedirectURIs = []string{"http://127.0.0.1/callback"}

	// When.
	allowed := isRedirectURIAllowed(client, "://invalid")

	// Then.
	if allowed {
		t.Error("invalid URI should not be allowed")
	}
}
