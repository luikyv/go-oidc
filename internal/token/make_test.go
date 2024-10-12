package token_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestMakeIDToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	idTokenOptions := token.IDTokenOptions{
		Subject: "random_subject",
		AdditionalIDTokenClaims: map[string]any{
			"random_claim": "random_value",
		},
	}

	// When.
	idToken, err := token.MakeIDToken(ctx, client, idTokenOptions)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := oidctest.SafeClaims(idToken, ctx.PrivateJWKS.Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Host,
		"sub":          idTokenOptions.Subject,
		"aud":          client.ID,
		"random_claim": "random_value",
		"iat":          float64(now),
		"exp":          float64(now + ctx.IDTokenLifetimeSecs),
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestMakeToken_JWTToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)
	grantInfo := goidc.GrantInfo{
		Subject:  "random_subject",
		ClientID: client.ID,
		AdditionalTokenClaims: map[string]any{
			"random_claim": "random_value",
		},
	}

	// When.
	token, err := token.Make(ctx, grantInfo)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.Format != goidc.TokenFormatJWT {
		t.Errorf("Format = %s, want %s", token.Format, goidc.TokenFormatJWT)
	}

	claims, err := oidctest.SafeClaims(token.Value, ctx.PrivateJWKS.Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Host,
		"sub":          grantInfo.Subject,
		"client_id":    client.ID,
		"scope":        grantInfo.GrantedScopes,
		"exp":          float64(now + 60),
		"iat":          float64(now),
		"random_claim": "random_value",
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
			return k == "jti"
		}),
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}

}

func TestMakeToken_OpaqueToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.TokenOptionsFunc = func(
		grantInfo goidc.GrantInfo,
	) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(10, 60)
	}
	grantInfo := goidc.GrantInfo{
		Subject: "random_subject",
	}

	// When.
	token, err := token.Make(ctx, grantInfo)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.Format != goidc.TokenFormatOpaque {
		t.Errorf("Format = %s, want %s", token.Format, goidc.TokenFormatOpaque)
	}

	if token.ID != token.Value {
		t.Errorf("ID = %s, want %s", token.ID, token.Value)
	}
}
