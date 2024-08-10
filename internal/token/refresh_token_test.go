package token

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleTokenCreation_RefreshTokenGrant(t *testing.T) {

	// Given.
	ctx := oidc.NewTestContext(t)
	c, _ := ctx.Client(oidc.TestClientID)

	refreshToken := "random_refresh_token"
	username := "user_id"
	now := time.Now().Unix()
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: now + 60,
		CreatedAtTimestamp: now,
		Subject:            username,
		ClientID:           oidc.TestClientID,
		GrantedScopes:      c.Scopes,
		TokenOptions: goidc.TokenOptions{
			TokenFormat:       goidc.TokenFormatJWT,
			TokenLifetimeSecs: 60,
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	req := tokenRequest{
		AuthnRequest: client.AuthnRequest{
			ID:     c.ID,
			Secret: oidc.TestClientSecret,
		},
		GrantType:    goidc.GrantRefreshToken,
		RefreshToken: refreshToken,
	}

	// When.
	tokenResp, err := handleTokenCreation(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := oidc.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, c.ID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, username, claims["sub"], "the token subject should be the client")
	assert.NotEmpty(t, tokenResp.RefreshToken, "the new refresh token is not valid")

	grantSessions := oidc.GrantSessions(t, ctx)
	assert.Len(t, grantSessions, 1, "there should be only one grant session")
}

func TestHandleGrantCreation_ShouldDenyExpiredRefreshToken(t *testing.T) {

	// When
	ctx := oidc.NewTestContext(t)
	c, _ := ctx.Client(oidc.TestClientID)

	refreshToken := "random_refresh_token"
	username := "user_id"
	now := time.Now().Unix()
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ActiveScopes:       c.Scopes,
		ExpiresAtTimestamp: now - 10,
		Subject:            username,
		ClientID:           oidc.TestClientID,
		GrantedScopes:      c.Scopes,
		TokenOptions: goidc.TokenOptions{
			TokenLifetimeSecs: 60,
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	req := tokenRequest{
		AuthnRequest: client.AuthnRequest{
			ID: oidc.TestClientID,
		},
		GrantType:    goidc.GrantRefreshToken,
		RefreshToken: refreshToken,
	}

	// Then
	_, err := handleTokenCreation(ctx, req)

	// Assert
	assert.NotNil(t, err, "the refresh token request should be denied")
}

func TestGenerateRefreshToken(t *testing.T) {
	// When.
	token, err := refreshToken()

	// Then.
	assert.Nil(t, err)
	assert.Len(t, token, RefreshTokenLength)
}
