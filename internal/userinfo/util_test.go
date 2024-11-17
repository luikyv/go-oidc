package userinfo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
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
	client.UserInfoSigAlg = jose.SignatureAlgorithm(oidctest.PrivateJWKS(t, ctx).Keys[0].Algorithm)

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
		"iss":          ctx.Host,
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
	ctx.UserSigAlgs = append(ctx.UserSigAlgs, goidc.NoneSignatureAlgorithm)

	client.UserInfoSigAlg = goidc.NoneSignatureAlgorithm

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

	claims, err := oidctest.UnsafeClaims(resp.jwtClaims, goidc.NoneSignatureAlgorithm)
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	wantedClaims := map[string]any{
		"iss":          ctx.Host,
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
	ctx.GeneratePairwiseSubIDFunc = func(ctx context.Context, sub string, client *goidc.Client) (string, error) {
		parseURL, _ := url.Parse(client.SectorIdentifierURI)
		return parseURL.Hostname() + "_" + sub, nil
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
	ctx, _, grantSession := setUp(t)
	grantSession.JWKThumbprint = "random_jkt"

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

func setUp(t *testing.T) (oidc.Context, *goidc.Client, *goidc.GrantSession) {
	t.Helper()

	ctx := oidctest.NewContext(t)
	client, _ := oidctest.NewClient(t)

	if err := ctx.SaveClient(client); err != nil {
		t.Fatalf("error saving the client during setup: %v", err)
	}

	token := "opaque_token"
	now := timeutil.TimestampNow()
	grantSession := &goidc.GrantSession{
		TokenID:                     token,
		CreatedAtTimestamp:          now,
		ExpiresAtTimestamp:          now + 60,
		LastTokenExpiresAtTimestamp: now + 60,
		GrantInfo: goidc.GrantInfo{
			ActiveScopes: goidc.ScopeOpenID.ID,
			Subject:      "random_subject",
			ClientID:     client.ID,
			AdditionalUserInfoClaims: map[string]any{
				"random_claim": "random_value",
			},
		},
	}

	if err := ctx.SaveGrantSession(grantSession); err != nil {
		t.Fatalf("error saving the grant session during setup: %v", err)
	}
	ctx.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	return ctx, client, grantSession
}
