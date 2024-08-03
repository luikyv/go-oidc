package token

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/authn"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleTokenCreation_RefreshTokenGrant(t *testing.T) {

	// Given.
	ctx := oidc.NewTestContext(t)
	client, _ := ctx.Client(oidc.TestClientID)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: goidc.TimestampNow() + 60,
		CreatedAtTimestamp: goidc.TimestampNow(),
		GrantOptions: goidc.GrantOptions{
			Subject:       username,
			ClientID:      oidc.TestClientID,
			GrantedScopes: client.Scopes,
			TokenOptions: goidc.TokenOptions{
				TokenFormat:       goidc.TokenFormatJWT,
				TokenLifetimeSecs: 60,
			},
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	req := tokenRequest{
		ClientAuthnRequest: authn.ClientAuthnRequest{
			ClientID:     client.ID,
			ClientSecret: oidc.TestClientSecret,
		},
		GrantType:    goidc.GrantRefreshToken,
		RefreshToken: refreshToken,
	}

	// When.
	tokenResp, err := HandleTokenCreation(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := oidc.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, client.ID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, username, claims["sub"], "the token subject should be the client")
	assert.NotEmpty(t, tokenResp.RefreshToken, "the new refresh token is not valid")

	grantSessions := oidc.GrantSessions(t, ctx)
	assert.Len(t, grantSessions, 1, "there should be only one grant session")
}

func TestHandleGrantCreation_ShouldDenyExpiredRefreshToken(t *testing.T) {

	// When
	ctx := oidc.NewTestContext(t)
	client, _ := ctx.Client(oidc.TestClientID)

	refreshToken := "random_refresh_token"
	username := "user_id"
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ActiveScopes:       client.Scopes,
		ExpiresAtTimestamp: goidc.TimestampNow() - 10,
		GrantOptions: goidc.GrantOptions{
			Subject:       username,
			ClientID:      oidc.TestClientID,
			GrantedScopes: client.Scopes,
			TokenOptions: goidc.TokenOptions{
				TokenLifetimeSecs: 60,
			},
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	req := tokenRequest{
		ClientAuthnRequest: authn.ClientAuthnRequest{
			ClientID: oidc.TestClientID,
		},
		GrantType:    goidc.GrantRefreshToken,
		RefreshToken: refreshToken,
	}

	// Then
	_, err := HandleTokenCreation(ctx, req)

	// Assert
	assert.NotNil(t, err, "the refresh token request should be denied")
}

func TestGenerateRefreshToken(t *testing.T) {
	// When.
	token, err := refreshToken()

	// Then.
	assert.Nil(t, err)
	assert.Len(t, token, goidc.RefreshTokenLength)
}
