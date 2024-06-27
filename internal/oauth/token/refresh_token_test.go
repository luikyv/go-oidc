package token_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikymagno/goidc/internal/oauth/token"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
)

func TestHandleTokenCreation_RefreshTokenGrant(t *testing.T) {

	// When
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.CreateOrUpdateClient(client)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: goidc.GetTimestampNow() + 60,
		CreatedAtTimestamp: goidc.GetTimestampNow(),
		GrantOptions: goidc.GrantOptions{
			Subject:       username,
			ClientID:      utils.TestClientID,
			GrantedScopes: client.Scopes,
			TokenOptions: goidc.TokenOptions{
				TokenFormat:       goidc.JWTTokenFormat,
				TokenLifetimeSecs: 60,
			},
		},
	}
	ctx.CreateOrUpdateGrantSession(grantSession)

	req := utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID: client.ID,
		},
		GrantType:    goidc.RefreshTokenGrant,
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

	if claims["client_id"].(string) != client.ID {
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
	client := utils.GetTestClient()
	ctx := utils.GetTestInMemoryContext()
	ctx.CreateOrUpdateClient(client)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := goidc.GrantSession{
		RefreshToken:       refreshToken,
		ActiveScopes:       client.Scopes,
		ExpiresAtTimestamp: goidc.GetTimestampNow() - 10,
		GrantOptions: goidc.GrantOptions{
			Subject:       username,
			ClientID:      utils.TestClientID,
			GrantedScopes: client.Scopes,
			TokenOptions: goidc.TokenOptions{
				TokenLifetimeSecs: 60,
			},
		},
	}
	ctx.CreateOrUpdateGrantSession(grantSession)

	req := utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID: client.ID,
		},
		GrantType:    goidc.RefreshTokenGrant,
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
