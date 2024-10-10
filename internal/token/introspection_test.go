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
	grantSession := &goidc.GrantSession{
		TokenID:                     accessToken,
		LastTokenExpiresAtTimestamp: timeutil.TimestampNow() + 60,
		GrantInfo: goidc.GrantInfo{
			ActiveScopes: goidc.ScopeOpenID.ID,
			ClientID:     client.ID,
		},
	}
	_ = ctx.SaveGrantSession(grantSession)

	tokenReq := queryRequest{
		token: accessToken,
	}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	now := timeutil.TimestampNow()
	if tokenInfo.ExpiresAtTimestamp-(now+60) > 1 {
		t.Errorf("ExpiresAtTimestamp = %d, want %d", tokenInfo.ExpiresAtTimestamp, now+60)
	}

	want := goidc.TokenInfo{
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

	expiryTime := timeutil.TimestampNow() + 60
	refreshToken := strutil.Random(goidc.RefreshTokenLength)
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: expiryTime,
		GrantInfo: goidc.GrantInfo{
			ClientID:      client.ID,
			GrantedScopes: goidc.ScopeOpenID.ID,
		},
	}
	_ = ctx.SaveGrantSession(grantSession)

	tokenReq := queryRequest{
		token: refreshToken,
	}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	now := timeutil.TimestampNow()
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
	ctx.IsClientAllowedTokenIntrospectionFunc = func(c *goidc.Client) bool {
		return true
	}

	client, secret := oidctest.NewClient(t)
	client.TokenIntrospectionAuthnMethod = goidc.ClientAuthnSecretPost
	_ = ctx.SaveClient(client)

	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	return ctx, client
}
