package token

import (
	"testing"
	"time"

	"github.com/luikyv/go-oidc/internal/authn"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/strutil"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectToken_OpaqueToken(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)
	client := oidc.NewTestClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantIntrospection)
	require.Nil(t, ctx.SaveClient(client))

	token := "opaque_token"
	grantSession := &goidc.GrantSession{
		TokenID:                    token,
		LastTokenIssuedAtTimestamp: time.Now().Unix(),
		ActiveScopes:               goidc.ScopeOpenID.ID,
		ClientID:                   oidc.TestClientID,
		TokenOptions: goidc.TokenOptions{
			TokenLifetimeSecs: 60,
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	tokenReq := tokenIntrospectionRequest{
		ClientAuthnRequest: authn.ClientAuthnRequest{
			ClientID:     oidc.TestClientID,
			ClientSecret: oidc.TestClientSecret,
		},
		Token: token,
	}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

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
	client := oidc.NewTestClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantIntrospection)
	require.Nil(t, ctx.SaveClient(client))

	expiryTime := time.Now().Unix() + 60
	refreshToken, err := strutil.Random(RefreshTokenLength)
	require.Nil(t, err)
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: expiryTime,
		ClientID:           oidc.TestClientID,
		GrantedScopes:      goidc.ScopeOpenID.ID,
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	tokenReq := tokenIntrospectionRequest{
		ClientAuthnRequest: authn.ClientAuthnRequest{
			ClientID:     oidc.TestClientID,
			ClientSecret: oidc.TestClientSecret,
		},
		Token: refreshToken,
	}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then.
	require.Nil(t, err)
	require.True(t, tokenInfo.IsActive)
	assert.Equal(t, goidc.ScopeOpenID.ID, tokenInfo.Scopes)
	assert.Equal(t, oidc.TestClientID, tokenInfo.ClientID)
	assert.GreaterOrEqual(t, tokenInfo.ExpiresAtTimestamp, expiryTime-5)
	assert.LessOrEqual(t, tokenInfo.ExpiresAtTimestamp, expiryTime+5)
}
