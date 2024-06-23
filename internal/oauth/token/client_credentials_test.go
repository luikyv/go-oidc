package token_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/oauth/token"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestHandleGrantCreation_ClientCredentialsHappyPath(t *testing.T) {
	// When
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.CreateClient(client)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId: client.Id,
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

	if claims["client_id"].(string) != client.Id {
		t.Error("the token was assigned to a different client")
		return
	}

	if claims["sub"].(string) != models.TestClientId {
		t.Error("the token subject should be the client")
		return
	}

	sessions := utils.GetGrantSessionsFromTestContext(ctx)
	if len(sessions) != 1 {
		t.Error("there should be one token session")
		return
	}
}
