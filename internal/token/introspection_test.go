package token_test

import (
	"testing"
	"time"

	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectToken_OpaqueToken(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	c := oidc.NewTestClient(t)
	c.GrantTypes = append(c.GrantTypes, goidc.GrantIntrospection)
	require.Nil(t, ctx.SaveClient(c))

	accessToken := "opaque_token"
	grantSession := &goidc.GrantSession{
		TokenID:                    accessToken,
		LastTokenIssuedAtTimestamp: time.Now().Unix(),
		ActiveScopes:               goidc.ScopeOpenID.ID,
		ClientID:                   oidc.TestClientID,
		TokenOptions: goidc.TokenOptions{
			LifetimeSecs: 60,
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	tokenReq := token.IntrospectionRequest{
		AuthnRequest: client.AuthnRequest{
			ID:     oidc.TestClientID,
			Secret: oidc.TestClientSecret,
		},
		Token: accessToken,
	}

	// When.
	tokenInfo, err := token.Introspect(ctx, tokenReq)

	// Then.
	require.Nil(t, err)
	require.True(t, tokenInfo.IsActive)
	assert.Equal(t, goidc.ScopeOpenID.ID, tokenInfo.Scopes)
	assert.Equal(t, oidc.TestClientID, tokenInfo.ClientID)
	expiryTime := time.Now().Unix() + 60
	assert.GreaterOrEqual(t, tokenInfo.ExpiresAtTimestamp, expiryTime-5)
	assert.LessOrEqual(t, tokenInfo.ExpiresAtTimestamp, expiryTime+5)
}

func TestIntrospectToken_RefreshToken(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	c := oidc.NewTestClient(t)
	c.GrantTypes = append(c.GrantTypes, goidc.GrantIntrospection)
	require.Nil(t, ctx.SaveClient(c))

	expiryTime := time.Now().Unix() + 60
	refreshToken, err := strutil.Random(token.RefreshTokenLength)
	require.Nil(t, err)
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: expiryTime,
		ClientID:           oidc.TestClientID,
		GrantedScopes:      goidc.ScopeOpenID.ID,
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	tokenReq := token.IntrospectionRequest{
		AuthnRequest: client.AuthnRequest{
			ID:     oidc.TestClientID,
			Secret: oidc.TestClientSecret,
		},
		Token: refreshToken,
	}

	// When.
	tokenInfo, err := token.Introspect(ctx, tokenReq)

	// Then.
	require.Nil(t, err)
	require.True(t, tokenInfo.IsActive)
	assert.Equal(t, goidc.ScopeOpenID.ID, tokenInfo.Scopes)
	assert.Equal(t, oidc.TestClientID, tokenInfo.ClientID)
	assert.GreaterOrEqual(t, tokenInfo.ExpiresAtTimestamp, expiryTime-5)
	assert.LessOrEqual(t, tokenInfo.ExpiresAtTimestamp, expiryTime+5)
}
