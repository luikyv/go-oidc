package token_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/joseutil"
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

	claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Issuer(),
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

func TestMakeIDToken_Unsigned(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.IDTokenSigAlgs = append(ctx.IDTokenSigAlgs, goidc.None)

	client, _ := oidctest.NewClient(t)
	client.IDTokenSigAlg = goidc.None
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

	claims, err := oidctest.UnsafeClaims(idToken, goidc.None)
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Issuer(),
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

func TestMakeIDToken_PairwiseSub(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
	ctx.GeneratePairwiseSubIDFunc = func(ctx context.Context, sub string, client *goidc.Client) string {
		parseURL, _ := url.Parse(client.SectorIdentifierURI)
		return parseURL.Hostname() + "_" + sub
	}

	client, _ := oidctest.NewClient(t)
	client.SubIdentifierType = goidc.SubIdentifierPairwise
	client.SectorIdentifierURI = "https://example.com/redirect_uris.json"

	idTokenOptions := token.IDTokenOptions{
		Subject: "random_subject",
	}

	// When.
	idToken, err := token.MakeIDToken(ctx, client, idTokenOptions)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := oidctest.SafeClaims(idToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss": ctx.Issuer(),
		"sub": "example.com_random_subject",
		"aud": client.ID,
		"iat": float64(now),
		"exp": float64(now + ctx.IDTokenLifetimeSecs),
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
	token, err := token.Make(ctx, grantInfo, client)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.Format != goidc.TokenFormatJWT {
		t.Errorf("Format = %s, want %s", token.Format, goidc.TokenFormatJWT)
	}

	claims, err := oidctest.SafeClaims(token.Value, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":          ctx.Issuer(),
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
	ctx.TokenOptionsFunc = func(_ context.Context, grantInfo goidc.GrantInfo, client *goidc.Client) goidc.TokenOptions {
		return goidc.NewOpaqueTokenOptions(10, 60)
	}
	grantInfo := goidc.GrantInfo{
		Subject: "random_subject",
	}
	client := &goidc.Client{}

	// When.
	token, err := token.Make(ctx, grantInfo, client)

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

func TestMakeToken_UnsignedJWTToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.TokenOptionsFunc = func(
		_ context.Context,
		grantInfo goidc.GrantInfo,
		client *goidc.Client,
	) goidc.TokenOptions {
		return goidc.NewJWTTokenOptions(goidc.None, 60)
	}
	client, _ := oidctest.NewClient(t)
	grantInfo := goidc.GrantInfo{
		Subject:  "random_subject",
		ClientID: client.ID,
		AdditionalTokenClaims: map[string]any{
			"random_claim": "random_value",
		},
	}

	// When.
	token, err := token.Make(ctx, grantInfo, client)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if token.Format != goidc.TokenFormatJWT {
		t.Errorf("Format = %s, want %s", token.Format, goidc.TokenFormatJWT)
	}

	if !joseutil.IsUnsignedJWT(token.Value) {
		t.Errorf("got %s, want unsigned", token.Value)
	}
}
