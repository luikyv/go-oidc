package token_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/auth-server/internal/constants"
	"github.com/luikymagno/auth-server/internal/models"
	"github.com/luikymagno/auth-server/internal/oauth/token"
	"github.com/luikymagno/auth-server/internal/unit"
	"github.com/luikymagno/auth-server/internal/utils"
)

func TestHandleTokenCreation_RefreshTokenGrant(t *testing.T) {

	// When
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := models.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: unit.GetTimestampNow() + 60,
		GrantOptions: models.GrantOptions{
			CreatedAtTimestamp: unit.GetTimestampNow(),
			Subject:            username,
			ClientId:           models.TestClientId,
			GrantedScopes:      client.Scopes,
			TokenOptions: models.TokenOptions{
				TokenFormat:        constants.JwtTokenFormat,
				TokenExpiresInSecs: 60,
			},
		},
	}
	ctx.GrantSessionManager.CreateOrUpdate(grantSession)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId: client.Id,
		},
		GrantType:    constants.RefreshTokenGrant,
		RefreshToken: refreshToken,
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

	if claims["sub"].(string) != username {
		t.Error("the token subject should be the client")
		return
	}

	if tokenResp.RefreshToken == "" {
		t.Error("the new refresh token is not valid")
		return
	}

	grantSessions := utils.GetGrantSessionsFromTestContext(ctx)
	if len(grantSessions) != 1 {
		t.Error("there should be only one grant session")
		return
	}
}

func TestHandleGrantCreation_ShouldDenyExpiredRefreshToken(t *testing.T) {

	// When
	client := models.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.ClientManager.Create(client)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := models.GrantSession{
		RefreshToken:       refreshToken,
		ActiveScopes:       client.Scopes,
		ExpiresAtTimestamp: unit.GetTimestampNow() - 10,
		GrantOptions: models.GrantOptions{
			Subject:       username,
			ClientId:      models.TestClientId,
			GrantedScopes: client.Scopes,
			TokenOptions: models.TokenOptions{
				TokenExpiresInSecs: 60,
			},
		},
	}
	ctx.GrantSessionManager.CreateOrUpdate(grantSession)

	req := models.TokenRequest{
		ClientAuthnRequest: models.ClientAuthnRequest{
			ClientId: client.Id,
		},
		GrantType:    constants.RefreshTokenGrant,
		RefreshToken: refreshToken,
	}

	// Then
	_, err := token.HandleTokenCreation(ctx, req)

	// Assert
	if err == nil {
		t.Errorf("the refresh token request should be denied")
		return
	}

}
