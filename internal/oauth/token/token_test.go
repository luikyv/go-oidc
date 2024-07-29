package token_test

import (
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oauth/token"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGrantCreationShouldNotFindClient(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)

	// When.
	_, err := token.HandleTokenCreation(ctx, utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID: "invalid_client_id",
		},
		GrantType: goidc.GrantClientCredentials,
		Scopes:    "scope1",
	})

	// Then.
	assert.NotNil(t, err, "the client should not be found")
}

func TestHandleGrantCreationShouldRejectUnauthenticatedClient(t *testing.T) {
	// Given.
	client := utils.NewTestClient(t)
	client.AuthnMethod = goidc.ClientAuthnSecretPost

	ctx := utils.NewTestContext(t)
	require.Nil(t, ctx.SaveClient(client))

	// When.
	_, err := token.HandleTokenCreation(ctx, utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     client.ID,
			ClientSecret: "invalid_password",
		},
		GrantType: goidc.GrantClientCredentials,
		Scopes:    "scope1",
	})

	// Then.
	require.NotNil(t, err, "the client should not be authenticated")

	var oauthErr goidc.OAuthBaseError
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, goidc.ErrorCodeInvalidClient, oauthErr.ErrorCode, "invalid error code")
}

func TestHandleGrantCreationWithDPoP(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	ctx.Host = "https://example.com"
	ctx.DPoPIsEnabled = true
	ctx.DPoPLifetimeSecs = 9999999999999
	ctx.DPoPSignatureAlgorithms = []jose.SignatureAlgorithm{jose.ES256}
	ctx.Request().Header.Set(goidc.HeaderDPoP, "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYVRtMk95eXFmaHFfZk5GOVVuZXlrZG0yX0dCZnpZVldDNEI1Wlo1SzNGUSIsInkiOiI4eFRhUERFTVRtNXM1d1MzYmFvVVNNcU01R0VJWDFINzMwX1hqV2lRaGxRIn19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iLCJpYXQiOjE1NjIyNjUyOTZ9.AzzSCVYIimNZyJQefZq7cF252PukDvRrxMqrrcH6FFlHLvpXyk9j8ybtS36GHlnyH_uuy2djQphfyHGeDfxidQ")
	ctx.Request().Method = http.MethodPost
	ctx.Request().RequestURI = "/token"

	req := utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     utils.TestClientID,
			ClientSecret: utils.TestClientSecret,
		},
		GrantType: goidc.GrantClientCredentials,
		Scopes:    "scope1",
	}

	// When.
	tokenResp, err := token.HandleTokenCreation(ctx, req)

	// Then.
	assert.Nil(t, err)
	claims := utils.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})

	require.Contains(t, claims, "cnf")
	confirmation := claims["cnf"].(map[string]any)
	require.Contains(t, confirmation, "jkt")
	assert.Equal(t, "BABEGlQNVH1K8KXO7qLKtvUFhAadQ5-dVGBfDfelwhQ", confirmation["jkt"])
}
