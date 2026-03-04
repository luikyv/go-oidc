package userinfo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestHandleUserInfoRequest(t *testing.T) {
	// Given.
	ctx, _, _ := setUp(t)

	// When.
	resp, err := handleUserInfoRequest(ctx)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := response{
		claims: map[string]any{
			"sub":          "random_subject",
			"random_claim": "random_value",
		},
	}
	if diff := cmp.Diff(
		resp,
		want,
		cmp.AllowUnexported(response{}),
	); diff != "" {
		t.Error(diff)
	}
}

func TestHandleUserInfoRequest_SignedResponse(t *testing.T) {
	// Given.
	ctx, client, _ := setUp(t)
	client.UserInfoSigAlg = goidc.SignatureAlgorithm(oidctest.PrivateJWKS(t, ctx).Keys[0].Algorithm)

	// When.
	resp, err := handleUserInfoRequest(ctx)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantedResp := response{jwtClaims: resp.jwtClaims}
	if diff := cmp.Diff(
		resp,
		wantedResp,
		cmp.AllowUnexported(response{}),
	); diff != "" {
		t.Error(diff)
	}

	if resp.jwtClaims == "" {
		t.Fatalf("the user info response must be a jwt")
	}

	claims, err := oidctest.SafeClaims(resp.jwtClaims, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	wantedClaims := map[string]any{
		"iss":          ctx.Issuer(),
		"sub":          "random_subject",
		"aud":          client.ID,
		"random_claim": "random_value",
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
	); diff != "" {
		t.Error(diff)
	}
}

func TestHandleUserInfoRequest_UnsignedResponse(t *testing.T) {
	// Given.
	ctx, client, _ := setUp(t)
	ctx.UserInfoSigAlgs = append(ctx.UserInfoSigAlgs, goidc.None)

	client.UserInfoSigAlg = goidc.None

	// When.
	resp, err := handleUserInfoRequest(ctx)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantedResp := response{jwtClaims: resp.jwtClaims}
	if diff := cmp.Diff(
		resp,
		wantedResp,
		cmp.AllowUnexported(response{}),
	); diff != "" {
		t.Error(diff)
	}

	if resp.jwtClaims == "" {
		t.Fatalf("the user info response must be a jwt")
	}

	claims, err := oidctest.UnsafeClaims(resp.jwtClaims, goidc.None)
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	wantedClaims := map[string]any{
		"iss":          ctx.Issuer(),
		"sub":          "random_subject",
		"aud":          client.ID,
		"random_claim": "random_value",
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
	); diff != "" {
		t.Error(diff)
	}
}

func TestHandleUserInfoRequest_PairwiseSub(t *testing.T) {
	// Given.
	ctx, client, _ := setUp(t)
	ctx.SubIdentifierTypes = []goidc.SubIdentifierType{goidc.SubIdentifierPairwise}
	ctx.GeneratePairwiseSubIDFunc = func(ctx context.Context, sub string, client *goidc.Client) string {
		parseURL, _ := url.Parse(client.SectorIdentifierURI)
		return parseURL.Hostname() + "_" + sub
	}

	client.SubIdentifierType = goidc.SubIdentifierPairwise
	client.SectorIdentifierURI = "https://example.com/redirect_uris.json"

	// When.
	resp, err := handleUserInfoRequest(ctx)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := response{
		claims: map[string]any{
			"sub":          "example.com_random_subject",
			"random_claim": "random_value",
		},
	}
	if diff := cmp.Diff(
		resp,
		want,
		cmp.AllowUnexported(response{}),
	); diff != "" {
		t.Error(diff)
	}
}

func TestHandleUserInfoRequest_InvalidPoP(t *testing.T) {
	// Given.
	ctx, _, tokenEntity := setUp(t)
	tokenEntity.JWKThumbprint = "random_jkt"

	// When.
	_, err := handleUserInfoRequest(ctx)

	// Then.
	if err == nil {
		t.Fatal("request should result in error")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Errorf("invalid error information: %v", err)
	}
}

func TestHandleUserInfoRequest_ExpiredToken(t *testing.T) {
	// Given.
	ctx, _, tokenEntity := setUp(t)
	tokenEntity.ExpiresAtTimestamp = timeutil.TimestampNow() - 10

	// When.
	_, err := handleUserInfoRequest(ctx)

	// Then.
	if err == nil {
		t.Fatal("expected error for expired token")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeAccessDenied {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeAccessDenied)
	}
}

func TestHandleUserInfoRequest_MissingOpenIDScope(t *testing.T) {
	// Given.
	ctx, _, tokenEntity := setUp(t)
	tokenEntity.Scopes = "scope1"

	// When.
	_, err := handleUserInfoRequest(ctx)

	// Then.
	if err == nil {
		t.Fatal("expected error for missing openid scope")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeAccessDenied {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeAccessDenied)
	}
}

func TestHandleUserInfoRequest_NoToken(t *testing.T) {
	// Given.
	ctx, _, _ := setUp(t)
	ctx.Request.Header.Del("Authorization")

	// When.
	_, err := handleUserInfoRequest(ctx)

	// Then.
	if err == nil {
		t.Fatal("expected error when no token is provided")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidToken {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidToken)
	}
}

func TestHandleUserInfoRequest_TokenNotFound(t *testing.T) {
	// Given.
	ctx, _, _ := setUp(t)
	ctx.Request.Header.Set("Authorization", "Bearer nonexistent_token")

	// When.
	_, err := handleUserInfoRequest(ctx)

	// Then.
	if err == nil {
		t.Fatal("expected error when token is not found in storage")
	}
}

func setUp(t *testing.T) (oidc.Context, *goidc.Client, *goidc.Token) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)

	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error saving the client during setup: %v", err)
	}

	tokenID := "opaque_token"
	grantID := "random_grant_id"
	now := timeutil.TimestampNow()

	grant := &goidc.Grant{
		ID:                 grantID,
		ClientID:           client.ID,
		Subject:            "random_subject",
		CreatedAtTimestamp: now,
		Store: map[string]any{
			"userinfo_claims": map[string]any{
				"random_claim": "random_value",
			},
		},
	}
	if err := ctx.SaveGrant(grant); err != nil {
		t.Fatalf("error saving the grant during setup: %v", err)
	}

	ctx.UserInfoClaimsFunc = func(_ context.Context, g *goidc.Grant) map[string]any {
		claims, _ := g.Store["userinfo_claims"].(map[string]any)
		return claims
	}

	tokenEntity := &goidc.Token{
		ID:                 tokenID,
		GrantID:            grantID,
		ClientID:           client.ID,
		Subject:            "random_subject",
		CreatedAtTimestamp: now,
		ExpiresAtTimestamp: now + 60,
		Scopes:             goidc.ScopeOpenID.ID,
	}

	if err := ctx.SaveToken(tokenEntity); err != nil {
		t.Fatalf("error saving the token during setup: %v", err)
	}
	ctx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenID))

	return ctx, client, tokenEntity
}
