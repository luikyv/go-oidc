package token_test

import (
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateGrant_RefreshTokenGrant(t *testing.T) {

	// Given.
	ctx := oidctest.NewContext(t)
	c, _ := ctx.Client(oidctest.ClientID)

	refreshToken := "random_refresh_token"
	username := "user_id"
	now := time.Now().Unix()
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: now + 60,
		CreatedAtTimestamp: now,
		Subject:            username,
		ClientID:           oidctest.ClientID,
		GrantedScopes:      c.Scopes,
		TokenOptions: goidc.TokenOptions{
			JWTSignatureKeyID: oidctest.KeyID,
			Format:            goidc.TokenFormatJWT,
			LifetimeSecs:      60,
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	req := token.Request{
		AuthnRequest: client.AuthnRequest{
			ID:     c.ID,
			Secret: oidctest.ClientSecret,
		},
		GrantType:    goidc.GrantRefreshToken,
		RefreshToken: refreshToken,
	}

	// When.
	tokenResp, err := token.GenerateGrant(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := oidctest.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, c.ID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, username, claims["sub"], "the token subject should be the client")
	assert.NotEmpty(t, tokenResp.RefreshToken, "the new refresh token is not valid")

	grantSessions := oidctest.GrantSessions(t, ctx)
	assert.Len(t, grantSessions, 1, "there should be only one grant session")
}

func TestGenerateGrant_ShouldDenyExpiredRefreshToken(t *testing.T) {

	// When
	ctx := oidctest.NewContext(t)
	c, _ := ctx.Client(oidctest.ClientID)

	refreshToken := "random_refresh_token"
	username := "user_id"
	now := time.Now().Unix()
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ActiveScopes:       c.Scopes,
		ExpiresAtTimestamp: now - 10,
		Subject:            username,
		ClientID:           oidctest.ClientID,
		GrantedScopes:      c.Scopes,
		TokenOptions: goidc.TokenOptions{
			LifetimeSecs: 60,
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	req := token.Request{
		AuthnRequest: client.AuthnRequest{
			ID: oidctest.ClientID,
		},
		GrantType:    goidc.GrantRefreshToken,
		RefreshToken: refreshToken,
	}

	// Then
	_, err := token.GenerateGrant(ctx, req)

	// Assert
	assert.NotNil(t, err, "the refresh token request should be denied")
}

func TestRefreshToken(t *testing.T) {
	// When.
	refreshToken, err := token.RefreshToken()

	// Then.
	assert.Nil(t, err)
	assert.Len(t, refreshToken, token.RefreshTokenLength)
}
