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
		TokenID:                    accessToken,
		LastTokenIssuedAtTimestamp: timeutil.TimestampNow(),
		ActiveScopes:               goidc.ScopeOpenID.ID,
		ClientID:                   client.ID,
		TokenOptions: goidc.TokenOptions{
			LifetimeSecs: 60,
		},
	}
	_ = ctx.SaveGrantSession(grantSession)

	tokenReq := introspectionRequest{
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
	refreshToken, _ := strutil.Random(goidc.RefreshTokenLength)
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: expiryTime,
		ClientID:           client.ID,
		GrantedScopes:      goidc.ScopeOpenID.ID,
	}
	_ = ctx.SaveGrantSession(grantSession)

	tokenReq := introspectionRequest{
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

func setUpIntrospection(t *testing.T) (ctx *oidc.Context, client *goidc.Client) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantIntrospection)
	_ = ctx.SaveClient(client)

	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	return ctx, client
}
