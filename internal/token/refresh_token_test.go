package token

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

const (
	testRefreshToken string = "random_refresh_token"
)

func TestGenerateGrant_RefreshTokenGrant(t *testing.T) {

	// Given.
	ctx, client, grantSession := setUpRefreshTokenGrant(t)

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: testRefreshToken,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the refresh token grant: %v", err)
	}

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Issuer(),
		"sub":       grantSession.Subject,
		"client_id": client.ID,
		"scope":     grantSession.Scopes,
		"exp":       float64(now + 60),
		"iat":       float64(now),
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

	if tokenResp.RefreshToken != "" {
		t.Error("refresh token rotation is not enabled, so a new refresh token shouldn't be returned")
	}

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}

	tokens := oidctest.Tokens(t, ctx)
	if len(tokens) != 1 {
		t.Fatalf("len(tokens) = %d, want 1", len(tokens))
	}
	if tokens[0].ID != claims["jti"] {
		t.Errorf("Token.ID = %s, want %s", tokens[0].ID, claims["jti"])
	}
}

func TestGenerateGrant_RefreshTokenGrant_AuthDetails(t *testing.T) {

	// Given.
	ctx, client, grantSession := setUpRefreshTokenGrant(t)
	ctx.RARIsEnabled = true
	ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
	ctx.RARCompareDetailsFunc = func(_ context.Context, _, _ []goidc.AuthDetail) error {
		return nil
	}
	authDetails := []goidc.AuthDetail{
		{
			"type":         "type1",
			"random_claim": "random_value",
		},
		{
			"type":         "type2",
			"random_claim": "random_value",
		},
	}
	grantSession.AuthDetails = authDetails

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: testRefreshToken,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the refresh token grant: %v", err)
	}

	grantSessions := oidctest.Grants(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession = grantSessions[0]
	if diff := cmp.Diff(grantSession.AuthDetails, authDetails); diff != "" {
		t.Error(diff)
	}

	tokens := oidctest.Tokens(t, ctx)
	if len(tokens) != 1 {
		t.Fatalf("len(tokens) = %d, want 1", len(tokens))
	}
	tokenEntity := tokens[0]
	if diff := cmp.Diff(tokenEntity.AuthDetails, authDetails); diff != "" {
		t.Error(diff)
	}

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Issuer(),
		"sub":       grantSession.Subject,
		"client_id": client.ID,
		"scope":     grantSession.Scopes,
		"exp":       float64(tokenEntity.ExpiresAtTimestamp),
		"iat":       float64(now),
		"jti":       tokenEntity.ID,
		"authorization_details": []any{
			map[string]any{
				"type":         "type1",
				"random_claim": "random_value",
			},
			map[string]any{
				"type":         "type2",
				"random_claim": "random_value",
			},
		},
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestGenerateGrant_RefreshTokenGrant_AuthDetails_ClientRequestsSubset(t *testing.T) {

	// Given.
	ctx, client, grantSession := setUpRefreshTokenGrant(t)
	ctx.RARIsEnabled = true
	ctx.RARDetailTypes = []goidc.AuthDetailType{"type1", "type2"}
	ctx.RARCompareDetailsFunc = func(_ context.Context, granted, requested []goidc.AuthDetail) error {
		return nil
	}
	authDetails := []goidc.AuthDetail{
		{
			"type":         "type1",
			"random_claim": "random_value",
		},
		{
			"type":         "type2",
			"random_claim": "random_value",
		},
	}
	grantSession.AuthDetails = authDetails

	authDetailsSubSet := []goidc.AuthDetail{
		map[string]any{
			"type":         "type1",
			"random_claim": "random_value",
		},
	}
	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: testRefreshToken,
		authDetails:  authDetailsSubSet,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the refresh token grant: %v", err)
	}

	grantSession = oidctest.Grants(t, ctx)[0]
	if diff := cmp.Diff(grantSession.AuthDetails, authDetails); diff != "" {
		t.Error(diff)
	}

	tokens := oidctest.Tokens(t, ctx)
	if len(tokens) != 1 {
		t.Fatalf("len(tokens) = %d, want 1", len(tokens))
	}
	tokenEntity := tokens[0]
	if diff := cmp.Diff(tokenEntity.AuthDetails, authDetailsSubSet); diff != "" {
		t.Error(diff)
	}

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Issuer(),
		"sub":       grantSession.Subject,
		"client_id": client.ID,
		"scope":     grantSession.Scopes,
		"exp":       float64(tokenEntity.ExpiresAtTimestamp),
		"iat":       float64(now),
		"jti":       tokenEntity.ID,
		"authorization_details": []any{
			map[string]any{
				"type":         "type1",
				"random_claim": "random_value",
			},
		},
	}
	if diff := cmp.Diff(
		claims,
		wantedClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestGenerateGrant_ExpiredRefreshToken(t *testing.T) {

	// When
	ctx, _, grantSession := setUpRefreshTokenGrant(t)
	grantSession.CreatedAtTimestamp = timeutil.TimestampNow() - 20
	grantSession.ExpiresAtTimestamp = grantSession.CreatedAtTimestamp + 10
	ctx.RefreshTokenLifetimeSecs = 10

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: testRefreshToken,
	}

	// Then
	_, err := generateGrant(ctx, req)

	// Assert
	if err == nil {
		t.Error("an expired grant session should result in failure")
	}
}

func TestGenerateGrant_RefreshTokenGrant_ScopeNarrowing(t *testing.T) {
	// Given.
	ctx, _, grantSession := setUpRefreshTokenGrant(t)

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: testRefreshToken,
		scopes:       goidc.ScopeOpenID.ID,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokenResp.Scopes != goidc.ScopeOpenID.ID {
		t.Errorf("Scopes = %s, want %s", tokenResp.Scopes, goidc.ScopeOpenID.ID)
	}

	// The grant should retain its original scopes.
	grants := oidctest.Grants(t, ctx)
	if len(grants) != 1 {
		t.Fatalf("len(grants) = %d, want 1", len(grants))
	}
	if grants[0].Scopes != grantSession.Scopes {
		t.Errorf("grant.Scopes = %s, want %s", grants[0].Scopes, grantSession.Scopes)
	}
}

func TestGenerateGrant_RefreshTokenGrant_InvalidScope(t *testing.T) {
	// Given.
	ctx, _, _ := setUpRefreshTokenGrant(t)

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: testRefreshToken,
		scopes:       "not_granted_scope",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for invalid scope")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidScope {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidScope)
	}
}

func TestGenerateGrant_RefreshTokenGrant_TokenRotation(t *testing.T) {
	// Given.
	ctx, _, _ := setUpRefreshTokenGrant(t)
	ctx.RefreshTokenRotationIsEnabled = true

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: testRefreshToken,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokenResp.RefreshToken == "" {
		t.Error("expected a new refresh token when rotation is enabled")
	}

	if tokenResp.RefreshToken == testRefreshToken {
		t.Error("rotated refresh token should differ from the original")
	}

	// The grant should have the new refresh token.
	grants := oidctest.Grants(t, ctx)
	if len(grants) != 1 {
		t.Fatalf("len(grants) = %d, want 1", len(grants))
	}
	if grants[0].RefreshToken != tokenResp.RefreshToken {
		t.Errorf("grant.RefreshToken = %s, want %s", grants[0].RefreshToken, tokenResp.RefreshToken)
	}
}

func TestGenerateGrant_RefreshTokenGrant_ClientMismatch(t *testing.T) {
	// Given.
	ctx, _, grantSession := setUpRefreshTokenGrant(t)
	grantSession.ClientID = "different_client"
	_ = ctx.SaveGrant(grantSession)

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: testRefreshToken,
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for client mismatch")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidGrant {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidGrant)
	}
}

func TestGenerateGrant_RefreshTokenGrant_ClientLacksGrantType(t *testing.T) {
	// Given.
	ctx, client, _ := setUpRefreshTokenGrant(t)
	client.GrantTypes = []goidc.GrantType{goidc.GrantAuthorizationCode}
	_ = ctx.SaveClient(client)

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: testRefreshToken,
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error when client lacks refresh_token grant type")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}

	if oidcErr.Code != goidc.ErrorCodeUnauthorizedClient {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeUnauthorizedClient)
	}
}

func TestGenerateGrant_RefreshTokenGrant_MissingRefreshToken(t *testing.T) {
	// Given.
	ctx, _, _ := setUpRefreshTokenGrant(t)

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: "",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for missing refresh token")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
	}
}

func TestGenerateGrant_RefreshTokenGrant_InvalidRefreshToken(t *testing.T) {
	// Given.
	ctx, _, _ := setUpRefreshTokenGrant(t)

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: "nonexistent_token",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("expected error for invalid refresh token")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("expected goidc.Error, got %v", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
		t.Errorf("Code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
	}
}

func setUpRefreshTokenGrant(t testing.TB) (ctx oidc.Context, client *goidc.Client, grantSession *goidc.Grant) {
	t.Helper()

	ctx = oidctest.NewContext(t)

	client, secret := oidctest.NewClient(t)
	if err := ctx.SaveClient(client); err != nil {
		t.Errorf("error while creating the client: %v", err)
	}
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	now := timeutil.TimestampNow()
	grantSession = &goidc.Grant{
		RefreshToken:       testRefreshToken,
		CreatedAtTimestamp: now,
		Subject:            "random_user",
		ClientID:           client.ID,
		Scopes:             client.ScopeIDs,
	}
	if err := ctx.SaveGrant(grantSession); err != nil {
		t.Errorf("error while creating the grant session: %v", err)
	}

	return ctx, client, grantSession
}
