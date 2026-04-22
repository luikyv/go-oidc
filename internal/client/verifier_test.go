package client_test

import (
	"context"
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

// TestAuthenticated_SecretPost_CustomVerifier_Success pins that a verifier
// returning nil allows authentication to succeed.
func TestAuthenticated_SecretPost_CustomVerifier_Success(t *testing.T) {

	// Given.
	ctx := oidctest.NewContext(t)
	const hashedAtRest = "stored-hash-value"
	const presentedPlaintext = "hunter2"

	c := &goidc.Client{
		ID: "random_client_id",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodSecretPost,
		},
		Secret: hashedAtRest,
	}
	if err := ctx.SaveClient(c); err != nil {
		t.Fatalf("error saving client: %v", err)
	}

	var called bool
	ctx.ClientSecretVerifierFunc = func(_ context.Context, stored, presented string) error {
		called = true
		if stored != hashedAtRest {
			t.Errorf("verifier received stored = %q, want %q", stored, hashedAtRest)
		}
		if presented != presentedPlaintext {
			t.Errorf("verifier received presented = %q, want %q", presented, presentedPlaintext)
		}
		return nil
	}

	ctx.Request.PostForm = map[string][]string{
		"client_id":     {c.ID},
		"client_secret": {presentedPlaintext},
	}

	// When.
	_, err := client.Authenticated(ctx, client.AuthnContextToken)

	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}
	if !called {
		t.Error("the custom verifier was not called")
	}
}

// TestAuthenticated_SecretPost_CustomVerifier_Failure pins that a verifier
// returning an error causes authentication to fail with
// goidc.ErrorCodeInvalidClient, wrapping the verifier's error.
func TestAuthenticated_SecretPost_CustomVerifier_Failure(t *testing.T) {

	// Given.
	ctx := oidctest.NewContext(t)

	c := &goidc.Client{
		ID: "random_client_id",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodSecretPost,
		},
		Secret: "stored",
	}
	if err := ctx.SaveClient(c); err != nil {
		t.Fatalf("error saving client: %v", err)
	}

	verifierErr := errors.New("mismatch")
	ctx.ClientSecretVerifierFunc = func(_ context.Context, _, _ string) error {
		return verifierErr
	}

	ctx.Request.PostForm = map[string][]string{
		"client_id":     {c.ID},
		"client_secret": {"presented"},
	}

	// When.
	_, err := client.Authenticated(ctx, client.AuthnContextToken)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}

	if !errors.Is(err, verifierErr) {
		t.Errorf("verifier error not wrapped into the returned error: want %v, got %v",
			verifierErr, err)
	}
}

// TestAuthenticated_SecretBasic_CustomVerifier_Success pins that the
// verifier fires for client_secret_basic, not just client_secret_post.
func TestAuthenticated_SecretBasic_CustomVerifier_Success(t *testing.T) {

	// Given.
	ctx := oidctest.NewContext(t)

	c := &goidc.Client{
		ID: "random_client_id",
		ClientMeta: goidc.ClientMeta{
			TokenAuthnMethod: goidc.AuthnMethodSecretBasic,
		},
		Secret: "stored",
	}
	if err := ctx.SaveClient(c); err != nil {
		t.Fatalf("error saving client: %v", err)
	}

	var called bool
	ctx.ClientSecretVerifierFunc = func(_ context.Context, _, _ string) error {
		called = true
		return nil
	}

	ctx.Request.SetBasicAuth(c.ID, "presented")

	// When.
	_, err := client.Authenticated(ctx, client.AuthnContextToken)

	// Then.
	if err != nil {
		t.Errorf("The client should be authenticated, but error was found: %v", err)
	}
	if !called {
		t.Error("the custom verifier was not called for client_secret_basic")
	}
}
