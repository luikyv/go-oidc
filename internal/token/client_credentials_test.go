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

func TestHandleGrantCreation_ClientCredentialsGrant(t *testing.T) {
	// Given.
	ctx, client := setUpClientCredentialsGrant(t)

	req := request{
		grantType: goidc.GrantClientCredentials,
		scopes:    oidctest.Scope1.ID,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the client credentials grant: %v", err)
	}

	now := timeutil.TimestampNow()
	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, ctx.PrivateJWKS.Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	wantedClaims := map[string]any{
		"iss":       ctx.Host,
		"sub":       client.ID,
		"client_id": client.ID,
		"scope":     req.scopes,
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

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
}

func TestHandleGrantCreation_ClientCredentialsGrant_ResourceIndicators(t *testing.T) {
	// Given.
	ctx, client := setUpClientCredentialsGrant(t)
	ctx.ResourceIndicatorsIsEnabled = true
	ctx.Resources = []string{"https://resource.com"}

	req := request{
		grantType: goidc.GrantClientCredentials,
		scopes:    oidctest.Scope1.ID,
		resources: []string{"https://resource.com"},
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("error generating the client credentials grant: %v", err)
	}

	now := timeutil.TimestampNow()
	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, ctx.PrivateJWKS.Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	wantedClaims := map[string]any{
		"iss":       ctx.Host,
		"sub":       client.ID,
		"client_id": client.ID,
		"scope":     req.scopes,
		"aud":       "https://resource.com",
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

	grantSessions := oidctest.GrantSessions(t, ctx)
	if len(grantSessions) != 1 {
		t.Errorf("len(grantSessions) = %d, want 1", len(grantSessions))
	}
}

func setUpClientCredentialsGrant(t testing.TB) (
	ctx oidc.Context,
	client *goidc.Client,
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

	return ctx, client
}
