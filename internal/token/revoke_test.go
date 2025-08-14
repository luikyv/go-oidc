package token

import (
	"errors"
	"testing"

	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestRevoke_OpaqueToken(t *testing.T) {
	// Given.
	ctx, client := setUpRevocation(t)

	accessToken := "opaque_token"
	now := timeutil.TimestampNow()
	grantSession := &goidc.GrantSession{
		TokenID:                     accessToken,
		LastTokenExpiresAtTimestamp: now + 10,
		GrantInfo: goidc.GrantInfo{
			ClientID: client.ID,
		},
	}
	_ = ctx.SaveGrantSession(grantSession)

	tokenReq := queryRequest{
		token: accessToken,
	}

	// When.
	err := revoke(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 0 {
		t.Errorf("len(grantSessions) = %d, want 0", len(grantSessions))
	}
}

func TestRevoke_RefreshToken(t *testing.T) {
	// Given.
	ctx, client := setUpRevocation(t)

	refreshToken := strutil.Random(goidc.RefreshTokenLength)
	now := timeutil.TimestampNow()
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: now + 10,
		GrantInfo: goidc.GrantInfo{
			ClientID: client.ID,
		},
	}
	_ = ctx.SaveGrantSession(grantSession)

	tokenReq := queryRequest{
		token: refreshToken,
	}

	// When.
	err := revoke(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 0 {
		t.Errorf("len(grantSessions) = %d, want 0", len(grantSessions))
	}
}

func TestRevoke_InvalidToken(t *testing.T) {
	// Given.
	ctx, _ := setUpRevocation(t)

	tokenReq := queryRequest{
		token: "invalid_token",
	}

	// When.
	err := revoke(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRevoke_TokenNotIssuedToClient(t *testing.T) {
	// Given.
	ctx, _ := setUpRevocation(t)

	accessToken := "opaque_token"
	now := timeutil.TimestampNow()
	grantSession := &goidc.GrantSession{
		TokenID:                     accessToken,
		LastTokenExpiresAtTimestamp: now + 10,
		GrantInfo: goidc.GrantInfo{
			ClientID: "another_client_id",
		},
	}
	_ = ctx.SaveGrantSession(grantSession)

	tokenReq := queryRequest{
		token: accessToken,
	}

	// When.
	err := revoke(ctx, tokenReq)

	// Then.
	if err == nil {
		t.Fatal("an error must be returned")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("invalid error")
	}

	if oidcErr.Code != goidc.ErrorCodeAccessDenied {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeAccessDenied)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
}

func setUpRevocation(t *testing.T) (ctx oidc.Context, client *goidc.Client) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.TokenRevocationIsEnabled = true
	ctx.IsClientAllowedTokenRevocationFunc = func(c *goidc.Client) bool {
		return true
	}

	client, secret := oidctest.NewClient(t)
	client.TokenRevocationAuthnMethod = goidc.ClientAuthnSecretPost
	_ = ctx.SaveClient(client)

	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	return ctx, client
}
