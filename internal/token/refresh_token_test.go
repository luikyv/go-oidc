package token

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGenerateGrant_RefreshTokenGrant(t *testing.T) {

	// Given.
	ctx, client, grantSession := setUpRefreshTokenGrant(t)

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: grantSession.RefreshToken,
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
		"iss":       ctx.Host,
		"sub":       grantSession.Subject,
		"client_id": client.ID,
		"scope":     grantSession.GrantedScopes,
		"exp":       float64(grantSession.LastTokenExpiresAtTimestamp),
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

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}

	if grantSessions[0].TokenID != claims["jti"] {
		t.Errorf("TokenID = %s, want %s", grantSessions[0].TokenID, claims["jti"])
	}
}

func TestGenerateGrant_RefreshTokenGrant_AuthDetails(t *testing.T) {

	// Given.
	ctx, client, grantSession := setUpRefreshTokenGrant(t)
	ctx.AuthDetailsIsEnabled = true
	ctx.AuthDetailTypes = []string{"type1", "type2"}
	authDetails := []goidc.AuthorizationDetail{
		{
			"type":         "type1",
			"random_claim": "random_value",
		},
		{
			"type":         "type2",
			"random_claim": "random_value",
		},
	}
	grantSession.ActiveAuthDetails = authDetails
	grantSession.GrantedAuthDetails = authDetails

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: grantSession.RefreshToken,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the refresh token grant: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession = grantSessions[0]
	if diff := cmp.Diff(grantSession.GrantedAuthDetails, authDetails); diff != "" {
		t.Error(diff)
	}
	if diff := cmp.Diff(grantSession.ActiveAuthDetails, authDetails); diff != "" {
		t.Error(diff)
	}

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Host,
		"sub":       grantSession.Subject,
		"client_id": client.ID,
		"scope":     grantSession.GrantedScopes,
		"exp":       float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat":       float64(now),
		"jti":       grantSession.TokenID,
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
	ctx.AuthDetailsIsEnabled = true
	ctx.AuthDetailTypes = []string{"type1", "type2"}
	authDetails := []goidc.AuthorizationDetail{
		{
			"type":         "type1",
			"random_claim": "random_value",
		},
		{
			"type":         "type2",
			"random_claim": "random_value",
		},
	}
	grantSession.ActiveAuthDetails = authDetails
	grantSession.GrantedAuthDetails = authDetails

	authDetailsSubSet := []goidc.AuthorizationDetail{
		map[string]any{
			"type":         "type1",
			"random_claim": "random_value",
		},
	}
	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: grantSession.RefreshToken,
		authDetails:  authDetailsSubSet,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the refresh token grant: %v", err)
	}

	grantSession = oidctest.GrantSessions(t, ctx)[0]
	if diff := cmp.Diff(grantSession.GrantedAuthDetails, authDetails); diff != "" {
		t.Error(diff)
	}
	if diff := cmp.Diff(grantSession.ActiveAuthDetails, authDetailsSubSet); diff != "" {
		t.Error(diff)
	}

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Host,
		"sub":       grantSession.Subject,
		"client_id": client.ID,
		"scope":     grantSession.GrantedScopes,
		"exp":       float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat":       float64(now),
		"jti":       grantSession.TokenID,
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
	grantSession.ExpiresAtTimestamp = timeutil.TimestampNow() - 10

	req := request{
		grantType:    goidc.GrantRefreshToken,
		refreshToken: grantSession.RefreshToken,
	}

	// Then
	_, err := generateGrant(ctx, req)

	// Assert
	if err == nil {
		t.Error("an expired grant session should result in failure")
	}
}

func setUpRefreshTokenGrant(t testing.TB) (
	ctx oidc.Context,
	client *goidc.Client,
	grantSession *goidc.GrantSession,
) {
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
	grantSession = &goidc.GrantSession{
		RefreshToken:       "random_refresh_token",
		ExpiresAtTimestamp: now + 600,
		GrantInfo: goidc.GrantInfo{
			ActiveScopes:  client.ScopeIDs,
			Subject:       "random_user",
			ClientID:      client.ID,
			GrantedScopes: client.ScopeIDs,
		},
	}
	if err := ctx.SaveGrantSession(grantSession); err != nil {
		t.Errorf("error while creating the grant session: %v", err)
	}

	return ctx, client, grantSession
}
