package dcr

import (
	"context"
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestCreate(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)

	// When.
	resp, err := create(ctx, "", &c.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error creating the client: %v", err)
	}

	if resp.ID == "" {
		t.Errorf("the client id in the response cannot be empty")
	}

	expectedRegURI := ctx.BaseURL() + ctx.DCREndpoint + "/" + resp.ID
	if resp.RegistrationURI != expectedRegURI {
		t.Errorf("RegistrationURI = %s, want %s", resp.RegistrationURI, expectedRegURI)
	}

	_, err = ctx.Client(resp.ID)
	if err != nil {
		t.Errorf("fetching the new client resulted in error: %v", err)
	}
}

func TestUpdate(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)
	ctx.DCRTokenRotationIsEnabled = false

	// When.
	resp, err := update(ctx, client.ID, regToken, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error updating the client: %v", err)
	}

	if resp.ID != client.ID {
		t.Errorf("ID = %s, want %s", resp.ID, client.ID)
	}

	if resp.RegistrationToken != "" {
		t.Error("token rotation is not enabled, the registration token shouldn't be present")
	}
}

func TestUpdate_TokenRotation(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)
	ctx.DCRTokenRotationIsEnabled = true

	// When.
	resp, err := update(ctx, client.ID, regToken, &client.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error updating the client: %v", err)
	}

	if resp.ID != client.ID {
		t.Errorf("ID = %s, want %s", resp.ID, client.ID)
	}

	if resp.RegistrationToken == "" {
		t.Error("token rotation is enabled, the registration token should be present")
	}
}

func TestFetch(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)

	// When.
	resp, err := fetch(ctx, client.ID, regToken)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error fetching the client: %v", err)
	}

	if resp.ID != client.ID {
		t.Errorf("ID = %s, want %s", resp.ID, client.ID)
	}
}

func TestFetch_InvalidToken(t *testing.T) {
	// Given.
	ctx, client, _ := setUp(t)

	// When.
	_, err := fetch(ctx, client.ID, "invalid_token")

	// Then.
	if err == nil {
		t.Error("fetching the client with an invalid token should result in failure")
	}
}

func TestDeleteClient(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)

	// When.
	err := remove(ctx, client.ID, regToken)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error deleting the client: %v", err)
	}

	clients := oidctest.Clients(t, ctx)
	if len(clients) != 0 {
		t.Errorf("len(clients) = %d, want 0", len(clients))
	}
}

func TestDeleteClient_InvalidToken(t *testing.T) {
	// Given.
	ctx, client, _ := setUp(t)

	// When.
	err := remove(ctx, client.ID, "invalid_token")

	// Then.
	if err == nil {
		t.Error("deleting the client with an invalid token should result in failure")
	}
}

func TestCreate_InvalidInitialToken(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	ctx.DCRValidateInitialTokenFunc = func(_ context.Context, _ string) error {
		return errors.New("invalid token")
	}

	// When.
	_, err := create(ctx, "bad_token", &c.ClientMeta)

	// Then.
	if err == nil {
		t.Fatal("expected error for invalid initial access token")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeAccessDenied {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeAccessDenied)
	}
}

func TestCreate_SecretGeneration(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	c.TokenAuthnMethod = goidc.AuthnMethodSecretBasic

	// When.
	resp, err := create(ctx, "", &c.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Secret == "" {
		t.Error("expected a non-empty secret for secret_basic authn method")
	}
}

func TestCreate_NoSecretForPublicClient(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	c.TokenAuthnMethod = goidc.AuthnMethodNone
	// Public clients cannot use client_credentials.
	c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
	c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}

	// When.
	resp, err := create(ctx, "", &c.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Secret != "" {
		t.Errorf("expected empty secret for public client, got %s", resp.Secret)
	}
}

func TestUpdate_InvalidToken(t *testing.T) {
	// Given.
	ctx, client, _ := setUp(t)

	// When.
	_, err := update(ctx, client.ID, "wrong_token", &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatal("expected error for invalid registration token")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeAccessDenied {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeAccessDenied)
	}
}

func TestUpdate_ClientNotFound(t *testing.T) {
	// Given.
	ctx, _, regToken := setUp(t)

	// When.
	_, err := update(ctx, "nonexistent_client", regToken, &goidc.ClientMeta{})

	// Then.
	if err == nil {
		t.Fatal("expected error for non-existent client")
	}
}

func TestFetch_ClientNotFound(t *testing.T) {
	// Given.
	ctx, _, regToken := setUp(t)

	// When.
	_, err := fetch(ctx, "nonexistent_client", regToken)

	// Then.
	if err == nil {
		t.Fatal("expected error for non-existent client")
	}
}

func TestCreate_SecretForSecretJWT(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	c.TokenAuthnMethod = goidc.AuthnMethodSecretJWT

	// When.
	resp, err := create(ctx, "", &c.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Secret == "" {
		t.Error("expected a non-empty secret for secret_jwt authn method")
	}
}

func TestDelete_ClientNotFound(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)

	// When.
	err := remove(ctx, "nonexistent_client", "some_token")

	// Then.
	if err == nil {
		t.Fatal("expected error for non-existent client")
	}
}

func TestCreate_HandleDynamicClientError(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	ctx.DCRHandleClientFunc = func(_ context.Context, _ string, _ *goidc.ClientMeta) error {
		return errors.New("handler error")
	}

	// When.
	_, err := create(ctx, "", &c.ClientMeta)

	// Then.
	if err == nil {
		t.Fatal("expected error from HandleDynamicClient")
	}
}

func TestCreate_SecretForSecretPost(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	c.TokenAuthnMethod = goidc.AuthnMethodSecretPost

	// When.
	resp, err := create(ctx, "", &c.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Secret == "" {
		t.Error("expected a non-empty secret for secret_post authn method")
	}
}

func TestCreate_SecretForIntrospectionAuthn(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	ctx.TokenIntrospectionIsEnabled = true
	ctx.TokenIntrospectionAuthnMethods = []goidc.AuthnMethod{goidc.AuthnMethodSecretBasic}
	c.TokenAuthnMethod = goidc.AuthnMethodNone
	c.TokenIntrospectionAuthnMethod = goidc.AuthnMethodSecretBasic
	// Public clients cannot use client_credentials.
	c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
	c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}

	// When.
	resp, err := create(ctx, "", &c.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Secret == "" {
		t.Error("expected a non-empty secret when introspection authn requires it")
	}
}

func TestCreate_SecretForRevocationAuthn(t *testing.T) {
	// Given.
	c, _ := oidctest.NewClient(t)
	ctx := oidctest.NewContext(t)
	ctx.TokenRevocationIsEnabled = true
	ctx.TokenRevocationAuthnMethods = []goidc.AuthnMethod{goidc.AuthnMethodSecretBasic}
	c.TokenAuthnMethod = goidc.AuthnMethodNone
	c.TokenRevocationAuthnMethod = goidc.AuthnMethodSecretBasic
	// Public clients cannot use client_credentials.
	c.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
	c.ResponseTypes = []goidc.ResponseType{goidc.ResponseTypeCode}

	// When.
	resp, err := create(ctx, "", &c.ClientMeta)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Secret == "" {
		t.Error("expected a non-empty secret when revocation authn requires it")
	}
}

func TestUpdate_HandleDynamicClientError(t *testing.T) {
	// Given.
	ctx, client, regToken := setUp(t)
	ctx.DCRHandleClientFunc = func(_ context.Context, _ string, _ *goidc.ClientMeta) error {
		return errors.New("handler error")
	}

	// When.
	_, err := update(ctx, client.ID, regToken, &client.ClientMeta)

	// Then.
	if err == nil {
		t.Fatal("expected error from HandleDynamicClient")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidClientMetadata {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClientMetadata)
	}
}

func setUp(t *testing.T) (ctx oidc.Context, client *goidc.Client, regToken string) {
	t.Helper()

	ctx = oidctest.NewContext(t)

	regToken = "registration_token"
	client, _ = oidctest.NewClient(t)
	client.RegistrationToken = regToken
	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("unexpected error creating the client: %v", err)
	}

	return ctx, client, regToken
}
