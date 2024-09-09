package authorize

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidcerr"
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

	if redirectErr.code != oidcerr.CodeInvalidRequest {
		t.Errorf("code = %s, want %s", redirectErr.code, oidcerr.CodeInvalidRequest)
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

	if redirectErr.code != oidcerr.CodeInvalidScope {
		t.Errorf("code = %s, want %s", redirectErr.code, oidcerr.CodeInvalidScope)
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

	var oidcErr oidcerr.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("the error should not be redirected")
	}

	if oidcErr.Code != oidcerr.CodeInvalidRedirectURI {
		t.Errorf("code = %s, want %s", oidcErr.Code, oidcerr.CodeInvalidRedirectURI)
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

	if redirectErr.code != oidcerr.CodeInvalidTarget {
		t.Errorf("code = %s, want %s", redirectErr.code, oidcerr.CodeInvalidTarget)
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
			Scopes: goidc.ScopeOpenID.ID,
			Nonce:  "random_nonce",
		},
	}

	// When.
	err := validateRequestWithPAR(ctx, req, session, client)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRequest_PAR_OutterParamsRequired(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.OutterAuthParamsRequired = true
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
	ctx.OutterAuthParamsRequired = true
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
	ctx.OutterAuthParamsRequired = true
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

	var oidcErr oidcerr.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("the error should not be redirected")
	}

	if oidcErr.Code != oidcerr.CodeInvalidClient {
		t.Errorf("code = %s, want %s", oidcErr.Code, oidcerr.CodeInvalidClient)
	}
}
