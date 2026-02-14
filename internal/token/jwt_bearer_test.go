package token

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestHandleGrantCreation_JWTBearerGrant(t *testing.T) {
	// Given.
	ctx, client := setUpJWTBearerGrant(t, "random_subject")

	reqScopes := strings.Join([]string{oidctest.Scope1.ID, goidc.ScopeOpenID.ID}, " ")
	req := request{
		grantType: goidc.GrantJWTBearer,
		scopes:    reqScopes,
		assertion: "random_assertion",
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]

	tokenClaims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedTokenClaims := map[string]any{
		"iss":       ctx.Issuer(),
		"sub":       "random_subject",
		"scope":     reqScopes,
		"client_id": client.ID,
		"exp":       float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat":       float64(now),
	}
	if diff := cmp.Diff(
		tokenClaims,
		wantedTokenClaims,
		cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
			return k == "jti"
		}),
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}

	idTokenClaims, err := oidctest.SafeClaims(tokenResp.IDToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	wantedIDTokenClaims := map[string]any{
		"iss": ctx.Issuer(),
		"sub": "random_subject",
		"aud": client.ID,
		"exp": float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat": float64(now),
	}
	if diff := cmp.Diff(
		idTokenClaims,
		wantedIDTokenClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestHandleGrantCreation_JWTBearerGrant_NoClientIdentified(t *testing.T) {
	// Given.
	ctx, _ := setUpJWTBearerGrant(t, "random_subject")
	ctx.Request.PostForm = map[string][]string{}

	reqScopes := strings.Join([]string{oidctest.Scope1.ID, goidc.ScopeOpenID.ID}, " ")
	req := request{
		grantType: goidc.GrantJWTBearer,
		scopes:    reqScopes,
		assertion: "random_assertion",
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the authorization code grant: %v", err)
	}

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
	grantSession := grantSessions[0]

	tokenClaims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	now := timeutil.TimestampNow()
	wantedTokenClaims := map[string]any{
		"iss":   ctx.Issuer(),
		"sub":   "random_subject",
		"scope": reqScopes,
		"exp":   float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat":   float64(now),
	}
	if diff := cmp.Diff(
		tokenClaims,
		wantedTokenClaims,
		cmpopts.IgnoreMapEntries(func(k string, _ any) bool {
			return k == "jti"
		}),
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}

	idTokenClaims, err := oidctest.SafeClaims(tokenResp.IDToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}
	wantedIDTokenClaims := map[string]any{
		"iss": ctx.Issuer(),
		"sub": "random_subject",
		"exp": float64(grantSession.LastTokenExpiresAtTimestamp),
		"iat": float64(now),
	}
	if diff := cmp.Diff(
		idTokenClaims,
		wantedIDTokenClaims,
		cmpopts.EquateApprox(0, 1),
	); diff != "" {
		t.Error(diff)
	}
}

func TestHandleGrantCreation_JWTBearerGrant_InvalidCredentials(t *testing.T) {
	// Given.
	ctx, client := setUpJWTBearerGrant(t, "random_subject")
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {"invalid_secret"},
	}

	reqScopes := strings.Join([]string{oidctest.Scope1.ID, goidc.ScopeOpenID.ID}, " ")
	req := request{
		grantType: goidc.GrantJWTBearer,
		scopes:    reqScopes,
		assertion: "random_assertion",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if err == nil {
		t.Fatal("The client should not be authenticated")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatal("invalid error type")
	}

	if oidcErr.Code != goidc.ErrorCodeInvalidClient {
		t.Errorf("error code = %s, want %s", oidcErr.Code, goidc.ErrorCodeInvalidClient)
	}
}

func TestHandleGrantCreation_JWTBearerGrant_ClientAuthnIsRequired(t *testing.T) {
	// Given.
	ctx, _ := setUpJWTBearerGrant(t, "random_subject")
	ctx.JWTBearerGrantClientAuthnIsRequired = true
	ctx.Request.PostForm = map[string][]string{}

	reqScopes := strings.Join([]string{oidctest.Scope1.ID, goidc.ScopeOpenID.ID}, " ")
	req := request{
		grantType: goidc.GrantJWTBearer,
		scopes:    reqScopes,
		assertion: "random_assertion",
	}

	// When.
	_, err := generateGrant(ctx, req)

	// Then.
	if !errors.Is(err, client.ErrClientNotIdentified) {
		t.Fatalf("error not as expected: %v", err)
	}

}

func setUpJWTBearerGrant(t *testing.T, sub string) (
	ctx oidc.Context,
	client *goidc.Client,
) {
	t.Helper()

	ctx = oidctest.NewContext(t)
	ctx.GrantTypes = append(ctx.GrantTypes, goidc.GrantJWTBearer)
	ctx.HandleJWTBearerGrantAssertionFunc = func(
		r *http.Request,
		assertion string,
	) (
		goidc.JWTBearerGrantInfo,
		error,
	) {
		return goidc.JWTBearerGrantInfo{
			Subject: sub,
		}, nil
	}

	client, secret := oidctest.NewClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantJWTBearer)
	if err := ctx.SaveClient(client); err != nil {
		t.Errorf("error while creating the client: %v", err)
	}
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	return ctx, client
}
