package token_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/oauth/token"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestHandleGrantCreationShouldNotFindClient(t *testing.T) {
	// When
	ctx := utils.GetTestInMemoryContext()

	// Then
	_, err := token.HandleTokenCreation(ctx, utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID: "invalid_client_id",
		},
		GrantType: goidc.ClientCredentialsGrant,
		Scopes:    "scope1",
	})

	// Assert
	if err == nil {
		t.Error("the should not be found")
		return
	}
}

func TestHandleGrantCreationShouldRejectUnauthenticatedClient(t *testing.T) {
	// When
	client := utils.GetTestClient()
	client.AuthnMethod = goidc.ClientSecretPostAuthn

	ctx := utils.GetTestInMemoryContext()
	ctx.CreateOrUpdateClient(client)

	// Then
	_, err := token.HandleTokenCreation(ctx, utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     client.ID,
			ClientSecret: "invalid_password",
		},
		GrantType: goidc.ClientCredentialsGrant,
		Scopes:    "scope1",
	})

	// Assert
	var oauthErr goidc.OAuthBaseError
	if err == nil || !errors.As(err, &oauthErr) {
		t.Error("the client should not be authenticated")
		return
	}
	if oauthErr.ErrorCode != goidc.InvalidClient {
		t.Errorf("invalid error code: %s", oauthErr.ErrorCode)
		return
	}
}

func TestHandleGrantCreationWithDPOP(t *testing.T) {
	// When
	client := utils.GetTestClient()

	ctx := utils.GetTestInMemoryContext()
	ctx.Host = "https://example.com"
	ctx.DPOPIsEnabled = true
	ctx.DPOPLifetimeSecs = 9999999999999
	ctx.DPOPSignatureAlgorithms = []jose.SignatureAlgorithm{jose.ES256}
	ctx.Request.Header.Set(goidc.DPOPHeader, "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiYVRtMk95eXFmaHFfZk5GOVVuZXlrZG0yX0dCZnpZVldDNEI1Wlo1SzNGUSIsInkiOiI4eFRhUERFTVRtNXM1d1MzYmFvVVNNcU01R0VJWDFINzMwX1hqV2lRaGxRIn19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdG9rZW4iLCJpYXQiOjE1NjIyNjUyOTZ9.AzzSCVYIimNZyJQefZq7cF252PukDvRrxMqrrcH6FFlHLvpXyk9j8ybtS36GHlnyH_uuy2djQphfyHGeDfxidQ")
	ctx.CreateOrUpdateClient(client)
	ctx.Request.Method = http.MethodPost

	req := utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID: client.ID,
		},
		GrantType: goidc.ClientCredentialsGrant,
		Scopes:    "scope1",
	}

	// Then
	tokenResp, err := token.HandleTokenCreation(ctx, req)

	// Assert
	if err != nil {
		t.Errorf("no error should be returned: %s", err.Error())
		return
	}

	parsedToken, err := jwt.ParseSigned(tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	if err != nil {
		t.Error("invalid token")
		return
	}

	var claims map[string]any
	err = parsedToken.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		t.Error("could not read claims")
		return
	}

	confirmation := claims["cnf"].(map[string]any)
	jkt := confirmation["jkt"].(string)
	if jkt != "BABEGlQNVH1K8KXO7qLKtvUFhAadQ5-dVGBfDfelwhQ" {
		t.Errorf("invalid jwk thumbprint. actual: %s", jkt)
		return
	}
}
