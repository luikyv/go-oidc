package token

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestIntrospect_OpaqueToken(t *testing.T) {
	// Given.
	ctx, client := setUpIntrospection(t)

	accessToken := "opaque_token"
	now := timeutil.TimestampNow()
	tokenEntity := &goidc.Token{
		ID:                 accessToken,
		GrantID:            "random_grant_id",
		ClientID:           client.ID,
		ExpiresAtTimestamp: now + 60,
		Scopes:       goidc.ScopeOpenID.ID,
	}
	_ = ctx.SaveToken(tokenEntity)

	tokenReq := queryRequest{
		token: accessToken,
	}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokenInfo.ExpiresAtTimestamp-(now+60) > 1 {
		t.Errorf("ExpiresAtTimestamp = %d, want %d", tokenInfo.ExpiresAtTimestamp, now+60)
	}

	want := goidc.TokenInfo{
		GrantID:            "random_grant_id",
		IsActive:           true,
		ClientID:           client.ID,
		Scopes:             goidc.ScopeOpenID.ID,
		ExpiresAtTimestamp: tokenInfo.ExpiresAtTimestamp,
		Type:               goidc.TokenHintAccess,
	}
	if diff := cmp.Diff(tokenInfo, want); diff != "" {
		t.Error(diff)
	}
}

func TestIntrospect_RefreshToken(t *testing.T) {
	// Given.
	ctx, client := setUpIntrospection(t)
	ctx.RefreshTokenLifetimeSecs = 60

	now := timeutil.TimestampNow()
	refreshToken := strutil.Random(100)
	grantSession := &goidc.Grant{
		RefreshToken:       refreshToken,
		CreatedAtTimestamp: now,
		ClientID:           client.ID,
		Scopes:             goidc.ScopeOpenID.ID,
	}
	_ = ctx.SaveGrant(grantSession)

	tokenReq := queryRequest{
		token: refreshToken,
	}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokenInfo.ExpiresAtTimestamp-(now+60) > 1 {
		t.Errorf("ExpiresAtTimestamp = %d, want %d", tokenInfo.ExpiresAtTimestamp, now+60)
	}

	want := goidc.TokenInfo{
		IsActive:           true,
		ClientID:           client.ID,
		Scopes:             goidc.ScopeOpenID.ID,
		ExpiresAtTimestamp: tokenInfo.ExpiresAtTimestamp,
		Type:               goidc.TokenHintRefresh,
	}
	if diff := cmp.Diff(tokenInfo, want); diff != "" {
		t.Error(diff)
	}
}

func setUpIntrospection(t *testing.T) (ctx oidc.Context, client *goidc.Client) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.TokenIntrospectionIsEnabled = true
	ctx.IsClientAllowedTokenIntrospectionFunc = func(_ *goidc.Client, _ goidc.TokenInfo) bool {
		return true
	}

	client, secret := oidctest.NewClient(t)
	client.TokenIntrospectionAuthnMethod = goidc.AuthnMethodSecretPost
	_ = ctx.SaveClient(client)

	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	return ctx, client
}
