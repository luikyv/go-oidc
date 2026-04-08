package token

import (
	"context"
	"encoding/json"
	"errors"
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
		CreatedAtTimestamp: now,
		ExpiresAtTimestamp: now + 60,
		Scopes:             goidc.ScopeOpenID.ID,
		Type:               goidc.TokenTypeBearer,
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
	if tokenInfo.IssuedAtTimestamp == 0 {
		t.Error("IssuedAtTimestamp must be set for active tokens")
	}
	if tokenInfo.NotBeforeTimestamp == 0 {
		t.Error("NotBeforeTimestamp must be set for active tokens")
	}
	if tokenInfo.Issuer == "" {
		t.Error("Issuer must be set for active tokens")
	}

	want := goidc.TokenInfo{
		GrantID:            "random_grant_id",
		IsActive:           true,
		ClientID:           client.ID,
		Scopes:             goidc.ScopeOpenID.ID,
		ExpiresAtTimestamp: tokenInfo.ExpiresAtTimestamp,
		Type:               goidc.TokenTypeBearer,
		Issuer:             "https://example.com",
		IssuedAtTimestamp:  tokenInfo.IssuedAtTimestamp,
		NotBeforeTimestamp: tokenInfo.NotBeforeTimestamp,
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
	if tokenInfo.IssuedAtTimestamp == 0 {
		t.Error("IssuedAtTimestamp must be set for active tokens")
	}
	if tokenInfo.NotBeforeTimestamp == 0 {
		t.Error("NotBeforeTimestamp must be set for active tokens")
	}
	if tokenInfo.Issuer == "" {
		t.Error("Issuer must be set for active tokens")
	}

	want := goidc.TokenInfo{
		IsActive:           true,
		ClientID:           client.ID,
		Scopes:             goidc.ScopeOpenID.ID,
		ExpiresAtTimestamp: tokenInfo.ExpiresAtTimestamp,
		Type:               goidc.TokenTypeBearer,
		Issuer:             "https://example.com",
		IssuedAtTimestamp:  tokenInfo.IssuedAtTimestamp,
		NotBeforeTimestamp: tokenInfo.NotBeforeTimestamp,
	}
	if diff := cmp.Diff(tokenInfo, want); diff != "" {
		t.Error(diff)
	}
}

func TestIntrospect_ExpiredOpaqueToken(t *testing.T) {
	// Given.
	ctx, client := setUpIntrospection(t)

	accessToken := "opaque_token"
	now := timeutil.TimestampNow()
	tokenEntity := &goidc.Token{
		ID:                 accessToken,
		GrantID:            "random_grant_id",
		ClientID:           client.ID,
		ExpiresAtTimestamp: now - 10,
		Scopes:             goidc.ScopeOpenID.ID,
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

	if tokenInfo.IsActive {
		t.Error("expired token should not be active")
	}
}

func TestIntrospect_TokenWithConfirmation(t *testing.T) {
	// Given.
	ctx, client := setUpIntrospection(t)

	accessToken := "opaque_token"
	now := timeutil.TimestampNow()
	tokenEntity := &goidc.Token{
		ID:                   accessToken,
		GrantID:              "random_grant_id",
		ClientID:             client.ID,
		ExpiresAtTimestamp:   now + 60,
		Scopes:               goidc.ScopeOpenID.ID,
		JWKThumbprint:        "thumbprint_jwk",
		ClientCertThumbprint: "thumbprint_cert",
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

	if !tokenInfo.IsActive {
		t.Fatal("token should be active")
	}

	if tokenInfo.Confirmation == nil {
		t.Fatal("Confirmation should not be nil")
	}

	if tokenInfo.Confirmation.JWKThumbprint != "thumbprint_jwk" {
		t.Errorf("JWKThumbprint = %s, want thumbprint_jwk", tokenInfo.Confirmation.JWKThumbprint)
	}

	if tokenInfo.Confirmation.ClientCertThumbprint != "thumbprint_cert" {
		t.Errorf("ClientCertThumbprint = %s, want thumbprint_cert", tokenInfo.Confirmation.ClientCertThumbprint)
	}
}

func TestIntrospect_ClientNotAllowed(t *testing.T) {
	// Given.
	ctx, client := setUpIntrospection(t)
	ctx.IsClientAllowedTokenIntrospectionFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
		return false
	}

	accessToken := "opaque_token"
	now := timeutil.TimestampNow()
	tokenEntity := &goidc.Token{
		ID:                 accessToken,
		GrantID:            "random_grant_id",
		ClientID:           client.ID,
		ExpiresAtTimestamp: now + 60,
		Scopes:             goidc.ScopeOpenID.ID,
	}
	_ = ctx.SaveToken(tokenEntity)

	tokenReq := queryRequest{
		token: accessToken,
	}

	// When.
	_, err := introspect(ctx, tokenReq)

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
}

func TestIntrospect_RefreshTokenExpired(t *testing.T) {
	// Given.
	ctx, client := setUpIntrospection(t)
	ctx.RefreshTokenLifetimeSecs = 10

	now := timeutil.TimestampNow()
	refreshToken := strutil.Random(100)
	grantSession := &goidc.Grant{
		RefreshToken:       refreshToken,
		CreatedAtTimestamp: now - 20,
		ExpiresAtTimestamp: now - 10,
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

	if tokenInfo.IsActive {
		t.Error("expired refresh token should not be active")
	}
}

func TestIntrospect_RefreshTokenNoLifetime(t *testing.T) {
	// Given.
	ctx, client := setUpIntrospection(t)
	ctx.RefreshTokenLifetimeSecs = 0

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

	if !tokenInfo.IsActive {
		t.Error("refresh token with no lifetime should be active")
	}

	if tokenInfo.ExpiresAtTimestamp != 0 {
		t.Errorf("ExpiresAtTimestamp = %d, want 0", tokenInfo.ExpiresAtTimestamp)
	}
}

func TestIntrospect_MissingToken(t *testing.T) {
	// Given.
	ctx, _ := setUpIntrospection(t)

	tokenReq := queryRequest{
		token: "",
	}

	// When.
	_, err := introspect(ctx, tokenReq)

	// Then.
	if err == nil {
		t.Fatal("expected error for missing token")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
	}
}

func TestIntrospect_RefreshTokenWithConfirmation(t *testing.T) {
	// Given.
	ctx, client := setUpIntrospection(t)

	now := timeutil.TimestampNow()
	refreshToken := strutil.Random(100)
	grantSession := &goidc.Grant{
		RefreshToken:         refreshToken,
		CreatedAtTimestamp:   now,
		ClientID:             client.ID,
		Scopes:               goidc.ScopeOpenID.ID,
		JWKThumbprint:        "dpop_thumbprint",
		ClientCertThumbprint: "tls_thumbprint",
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

	if !tokenInfo.IsActive {
		t.Fatal("token should be active")
	}
	if tokenInfo.Confirmation == nil {
		t.Fatal("Confirmation should not be nil")
	}
	if tokenInfo.Confirmation.JWKThumbprint != "dpop_thumbprint" {
		t.Errorf("JWKThumbprint = %s, want dpop_thumbprint", tokenInfo.Confirmation.JWKThumbprint)
	}
	if tokenInfo.Confirmation.ClientCertThumbprint != "tls_thumbprint" {
		t.Errorf("ClientCertThumbprint = %s, want tls_thumbprint", tokenInfo.Confirmation.ClientCertThumbprint)
	}
}

func TestIntrospect_TokenNotFound(t *testing.T) {
	// Given.
	ctx, _ := setUpIntrospection(t)

	tokenReq := queryRequest{
		token: "nonexistent_token",
	}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokenInfo.IsActive {
		t.Error("nonexistent token should not be active")
	}
}

func TestIntrospect_DPoPToken(t *testing.T) {
	// Given.
	ctx, client := setUpIntrospection(t)

	accessToken := "dpop_token"
	now := timeutil.TimestampNow()
	tokenEntity := &goidc.Token{
		ID:                 accessToken,
		GrantID:            "dpop_grant_id",
		ClientID:           client.ID,
		ExpiresAtTimestamp: now + 60,
		Scopes:             goidc.ScopeOpenID.ID,
		Type:               goidc.TokenTypeDPoP,
	}
	_ = ctx.SaveToken(tokenEntity)

	tokenReq := queryRequest{token: accessToken}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokenInfo.Type != goidc.TokenTypeDPoP {
		t.Errorf("Type = %s, want %s", tokenInfo.Type, goidc.TokenTypeDPoP)
	}
}

func TestIntrospect_ClientNotAllowed_UnknownToken(t *testing.T) {
	// Given.
	ctx, _ := setUpIntrospection(t)
	ctx.IsClientAllowedTokenIntrospectionFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
		return false
	}

	tokenReq := queryRequest{token: "nonexistent_token"}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then: unknown token → 200 {active:false}, NOT an access_denied error.
	if err != nil {
		t.Fatalf("expected no error for unknown token with restrictive client, got: %v", err)
	}
	if tokenInfo.IsActive {
		t.Error("unknown token must not be active")
	}
}

func TestIntrospect_InactiveTokenJSON(t *testing.T) {
	// Verify RFC 7662 §2.2: inactive token response MUST NOT include other
	// fields. We marshal TokenInfo{IsActive:false} and check the JSON.
	info := goidc.TokenInfo{IsActive: false}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}
	got := string(b)
	want := `{"active":false}`
	if got != want {
		t.Errorf("inactive TokenInfo JSON = %s, want %s", got, want)
	}
}

func setUpIntrospection(t *testing.T) (ctx oidc.Context, client *goidc.Client) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.TokenIntrospectionIsEnabled = true
	ctx.IsClientAllowedTokenIntrospectionFunc = func(_ context.Context, _ *goidc.Client, _ goidc.TokenInfo) bool {
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
