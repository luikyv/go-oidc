package token_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/constants"
	"github.com/luikymagno/goidc/internal/models"
	"github.com/luikymagno/goidc/internal/oauth/token"
	"github.com/luikymagno/goidc/internal/unit"
	"github.com/luikymagno/goidc/internal/utils"
)

func TestHandleGrantCreation_AuthorizationCodeGrantHappyPath(t *testing.T) {

	// When
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)

	authorizationCode := "random_authz_code"
	session := models.AuthnSession{
		ClientId:      models.TestClientId,
		GrantedScopes: constants.OpenIdScope,
		AuthorizationParameters: models.AuthorizationParameters{
			Scopes:      constants.OpenIdScope,
			RedirectUri: client.RedirectUris[0],
		},
		AuthorizationCode:         authorizationCode,
		Subject:                   "user_id",
		CreatedAtTimestamp:        unit.GetTimestampNow(),
		AuthorizationCodeIssuedAt: unit.GetTimestampNow(),
		ExpiresAtTimestamp:        unit.GetTimestampNow() + 60,
		Store:                     make(map[string]any),
		AdditionalTokenClaims:     make(map[string]any),
	}
	ctx.AuthnSessionManager.CreateOrUpdate(session)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId: client.Id,
		},
		GrantType:         constants.AuthorizationCodeGrant,
		RedirectUri:       client.RedirectUris[0],
		AuthorizationCode: authorizationCode,
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

	if claims["sub"].(string) != session.Subject {
		t.Error("the token subject should be the client")
		return
	}

	grantSessions := utils.GetGrantSessionsFromTestContext(ctx)
	if len(grantSessions) != 1 {
		t.Error("there should be only one grant session")
		return
	}
}
