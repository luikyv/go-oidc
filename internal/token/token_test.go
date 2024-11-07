package token

import (
	"errors"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/timeutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
)

func TestGenerateGrant_ClientNotFound(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	ctx.Request.PostForm = map[string][]string{
		"client_id": {"invalid_client_id"},
	}

	// When.
	_, err := generateGrant(ctx, request{
		grantType: goidc.GrantClientCredentials,
		scopes:    "scope1",
	})

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

func TestGenerateGrant_UnauthenticatedClient(t *testing.T) {
	// Given.
	client, _ := oidctest.NewClient(t)

	ctx := oidctest.NewContext(t)
	_ = ctx.SaveClient(client)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {"invalid_secret"},
	}

	// When.
	_, err := generateGrant(ctx, request{
		grantType: goidc.GrantClientCredentials,
		scopes:    client.ScopeIDs,
	})

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

func TestGenerateGrantWithDPoP(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, secret := oidctest.NewClient(t)
	_ = ctx.SaveClient(client)
	ctx.Request.PostForm = map[string][]string{
		"client_id":     {client.ID},
		"client_secret": {secret},
	}

	ctx.Host = "https://example.com"
	ctx.DPoPIsEnabled = true
	ctx.DPoPLifetimeSecs = 9999999999999
	ctx.DPoPSigAlgs = []jose.SignatureAlgorithm{jose.ES256}
	ctx.Request.Header.Set(goidc.HeaderDPoP, "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYVRtMk95eXFmaHFfZk5GOVVuZXlrZG0yX0dCZnpZVldDNEI1Wlo1SzNGUSIsInkiOiI4eFRhUERFTVRtNXM1d1MzYmFvVVNNcU01R0VJWDFINzMwX1hqV2lRaGxRIn19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iLCJpYXQiOjE1NjIyNjUyOTZ9.AzzSCVYIimNZyJQefZq7cF252PukDvRrxMqrrcH6FFlHLvpXyk9j8ybtS36GHlnyH_uuy2djQphfyHGeDfxidQ")
	ctx.Request.Method = http.MethodPost
	ctx.Request.RequestURI = "/token"

	req := request{
		grantType: goidc.GrantClientCredentials,
		scopes:    client.ScopeIDs,
	}

	// When.
	tokenResp, err := generateGrant(ctx, req)

	// Then.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims, err := oidctest.SafeClaims(tokenResp.AccessToken, oidctest.PrivateJWKS(t, ctx).Keys[0])
	if err != nil {
		t.Fatalf("error parsing claims: %v", err)
	}

	now := timeutil.TimestampNow()
	wantedClaims := map[string]any{
		"iss":       ctx.Host,
		"sub":       client.ID,
		"client_id": client.ID,
		"scope":     req.scopes,
		"exp":       float64(now + 60),
		"iat":       float64(now),
		"cnf": map[string]any{
			"jkt": "BABEGlQNVH1K8KXO7qLKtvUFhAadQ5-dVGBfDfelwhQ",
		},
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
}
