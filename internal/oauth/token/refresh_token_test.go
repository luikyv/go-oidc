package token_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/oauth/token"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleTokenCreation_RefreshTokenGrant(t *testing.T) {

	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: goidc.TimestampNow() + 60,
		CreatedAtTimestamp: goidc.TimestampNow(),
		GrantOptions: goidc.GrantOptions{
			Subject:       username,
			ClientID:      utils.TestClientID,
			GrantedScopes: client.Scopes,
			TokenOptions: goidc.TokenOptions{
				TokenFormat:       goidc.TokenFormatJWT,
				TokenLifetimeSecs: 60,
			},
		},
	}
	require.Nil(t, ctx.CreateOrUpdateGrantSession(grantSession))

	req := utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID: client.ID,
		},
		GrantType:    goidc.GrantRefreshToken,
		RefreshToken: refreshToken,
	}

	// When.
	tokenResp, err := token.HandleTokenCreation(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := utils.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, client.ID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, username, claims["sub"], "the token subject should be the client")
	assert.NotEmpty(t, tokenResp.RefreshToken, "the new refresh token is not valid")

	grantSessions := utils.GrantSessions(t, ctx)
	assert.Len(t, grantSessions, 1, "there should be only one grant session")
}

func TestHandleGrantCreation_ShouldDenyExpiredRefreshToken(t *testing.T) {

	// When
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := goidc.GrantSession{
		RefreshToken:       refreshToken,
		ActiveScopes:       client.Scopes,
		ExpiresAtTimestamp: goidc.TimestampNow() - 10,
		GrantOptions: goidc.GrantOptions{
			Subject:       username,
			ClientID:      utils.TestClientID,
			GrantedScopes: client.Scopes,
			TokenOptions: goidc.TokenOptions{
				TokenLifetimeSecs: 60,
			},
		},
	}
	require.Nil(t, ctx.CreateOrUpdateGrantSession(grantSession))

	req := utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID: utils.TestClientID,
		},
		GrantType:    goidc.GrantRefreshToken,
		RefreshToken: refreshToken,
	}

	// Then
	_, err := token.HandleTokenCreation(ctx, req)

	// Assert
	assert.NotNil(t, err, "the refresh token request should be denied")
}
