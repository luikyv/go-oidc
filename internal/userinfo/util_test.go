package userinfo

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestUserInfo(t *testing.T) {
	// Given.
	ctx, _ := setUp(t)

	// When.
	resp, err := userInfo(ctx)

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

func TestUserInfo_SignedResponse(t *testing.T) {
	// Given.
	ctx, client := setUp(t)
	client.UserInfoSigAlg = jose.SignatureAlgorithm(ctx.PrivateJWKS.Keys[0].Algorithm)

	// When.
	resp, err := userInfo(ctx)

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

	claims, err := oidctest.SafeClaims(resp.jwtClaims, ctx.PrivateJWKS.Keys[0])
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

func setUp(t *testing.T) (*oidc.Context, *goidc.Client) {
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

	return ctx, client
}
