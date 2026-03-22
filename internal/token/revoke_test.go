package token

import (
	"context"
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
	grantSession := &goidc.Grant{
		ID:                 "random_grant_id",
		CreatedAtTimestamp: now,
		ClientID:           client.ID,
	}
	_ = ctx.SaveGrant(grantSession)

	tokenEntity := &goidc.Token{
		ID:                 accessToken,
		GrantID:            grantSession.ID,
		ClientID:           client.ID,
		ExpiresAtTimestamp: now + 10,
	}
	_ = ctx.SaveToken(tokenEntity)

	tokenReq := queryRequest{
		token: accessToken,
	}

	// When.
	err := revoke(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 0 {
		t.Errorf("len(grantSessions) = %d, want 0", len(grantSessions))
	}

	tokens := oidctest.Tokens(t, ctx)
	if len(tokens) != 0 {
		t.Errorf("len(tokens) = %d, want 0", len(tokens))
	}
}

func TestRevoke_RefreshToken(t *testing.T) {
	// Given.
	ctx, client := setUpRevocation(t)

	refreshToken := strutil.Random(100)
	now := timeutil.TimestampNow()
	grantSession := &goidc.Grant{
		ID:                 "random_grant_id",
		RefreshToken:       refreshToken,
		CreatedAtTimestamp: now,
		ClientID:           client.ID,
	}
	_ = ctx.SaveGrant(grantSession)

	tokenReq := queryRequest{
		token: refreshToken,
	}

	// When.
	err := revoke(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grantSessions := oidctest.Grants(t, ctx)
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
	grantSession := &goidc.Grant{
		ID:                 "random_grant_id",
		CreatedAtTimestamp: now,
		ClientID:           "another_client_id",
	}
	_ = ctx.SaveGrant(grantSession)

	tokenEntity := &goidc.Token{
		ID:                 accessToken,
		GrantID:            grantSession.ID,
		ClientID:           "another_client_id",
		ExpiresAtTimestamp: now + 10,
	}
	_ = ctx.SaveToken(tokenEntity)

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

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
}

func TestRevoke_ClientNotAllowed(t *testing.T) {
	// Given.
	ctx, client := setUpRevocation(t)
	ctx.IsClientAllowedTokenRevocationFunc = func(_ context.Context, _ *goidc.Client) bool {
		return false
	}

	accessToken := "opaque_token"
	now := timeutil.TimestampNow()
	grantSession := &goidc.Grant{
		ID:                 "random_grant_id",
		CreatedAtTimestamp: now,
		ClientID:           client.ID,
	}
	_ = ctx.SaveGrant(grantSession)

	tokenEntity := &goidc.Token{
		ID:                 accessToken,
		GrantID:            grantSession.ID,
		ClientID:           client.ID,
		ExpiresAtTimestamp: now + 10,
	}
	_ = ctx.SaveToken(tokenEntity)

	tokenReq := queryRequest{
		token: accessToken,
	}

	// When.
	err := revoke(ctx, tokenReq)

	// Then.
	if err == nil {
		t.Fatal("expected error for disallowed client")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeAccessDenied {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeAccessDenied)
	}

	// Grant should NOT be deleted.
	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
}

func TestRevoke_RefreshTokenDeletesTokens(t *testing.T) {
	// Given.
	ctx, client := setUpRevocation(t)

	refreshToken := strutil.Random(100)
	now := timeutil.TimestampNow()
	grantSession := &goidc.Grant{
		ID:                 "random_grant_id",
		RefreshToken:       refreshToken,
		CreatedAtTimestamp: now,
		ClientID:           client.ID,
	}
	_ = ctx.SaveGrant(grantSession)

	// Also create an associated access token.
	tokenEntity := &goidc.Token{
		ID:                 "associated_access_token",
		GrantID:            grantSession.ID,
		ClientID:           client.ID,
		ExpiresAtTimestamp: now + 60,
	}
	_ = ctx.SaveToken(tokenEntity)

	tokenReq := queryRequest{
		token: refreshToken,
	}

	// When.
	err := revoke(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 0 {
		t.Errorf("len(grantSessions) = %d, want 0", len(grantSessions))
	}

	tokens := oidctest.Tokens(t, ctx)
	if len(tokens) != 0 {
		t.Errorf("len(tokens) = %d, want 0", len(tokens))
	}
}

func TestRevoke_ExpiredToken(t *testing.T) {
	// Given.
	ctx, _ := setUpRevocation(t)

	// Use a token value that doesn't exist in storage, simulating a fully
	// expired/purged token. IntrospectionInfo will return an error (not found),
	// so revoke returns nil without deleting anything.
	tokenReq := queryRequest{
		token: "purged_expired_token",
	}

	grantSession := &goidc.Grant{
		ID:                 "random_grant_id",
		CreatedAtTimestamp: timeutil.TimestampNow(),
		ClientID:           "some_client",
	}
	_ = ctx.SaveGrant(grantSession)

	// When.
	err := revoke(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Grant should still exist since the token was not found.
	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
}

func setUpRevocation(t *testing.T) (ctx oidc.Context, client *goidc.Client) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.TokenRevocationIsEnabled = true
	ctx.IsClientAllowedTokenRevocationFunc = func(_ context.Context, c *goidc.Client) bool {
		return true
	}

	client, secret := oidctest.NewClient(t)
	client.TokenRevocationAuthnMethod = goidc.AuthnMethodSecretPost
	_ = ctx.SaveClient(client)

	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	return ctx, client
}
