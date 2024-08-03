package token

import (
	"testing"

	"github.com/luikyv/go-oidc/internal/authn"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectToken_OpaqueToken(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client := utils.NewTestClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantIntrospection)
	require.Nil(t, ctx.SaveClient(client))

	token := "opaque_token"
	grantSession := &goidc.GrantSession{
		TokenID:                    token,
		LastTokenIssuedAtTimestamp: goidc.TimestampNow(),
		ActiveScopes:               goidc.ScopeOpenID.ID,
		GrantOptions: goidc.GrantOptions{
			ClientID: utils.TestClientID,
			TokenOptions: goidc.TokenOptions{
				TokenLifetimeSecs: 60,
			},
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	tokenReq := tokenIntrospectionRequest{
		ClientAuthnRequest: authn.ClientAuthnRequest{
			ClientID:     utils.TestClientID,
			ClientSecret: utils.TestClientSecret,
		},
		Token: token,
	}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then.
	require.Nil(t, err)
	require.True(t, tokenInfo.IsActive)
	assert.Equal(t, goidc.ScopeOpenID.ID, tokenInfo.Scopes)
	assert.Equal(t, utils.TestClientID, tokenInfo.ClientID)
	goidc.AssertTimestampWithin(t, goidc.TimestampNow()+60, tokenInfo.ExpiresAtTimestamp)
}

func TestIntrospectToken_RefreshToken(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client := utils.NewTestClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantIntrospection)
	require.Nil(t, ctx.SaveClient(client))

	refreshToken, err := goidc.RandomString(goidc.RefreshTokenLength)
	require.Nil(t, err)
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: goidc.TimestampNow() + 60,
		GrantOptions: goidc.GrantOptions{
			ClientID:      utils.TestClientID,
			GrantedScopes: goidc.ScopeOpenID.ID,
		},
	}
	require.Nil(t, ctx.SaveGrantSession(grantSession))

	tokenReq := tokenIntrospectionRequest{
		ClientAuthnRequest: authn.ClientAuthnRequest{
			ClientID:     utils.TestClientID,
			ClientSecret: utils.TestClientSecret,
		},
		Token: refreshToken,
	}

	// When.
	tokenInfo, err := introspect(ctx, tokenReq)

	// Then.
	require.Nil(t, err)
	require.True(t, tokenInfo.IsActive)
	assert.Equal(t, goidc.ScopeOpenID.ID, tokenInfo.Scopes)
	assert.Equal(t, utils.TestClientID, tokenInfo.ClientID)
	goidc.AssertTimestampWithin(t, goidc.TimestampNow()+60, tokenInfo.ExpiresAtTimestamp)
}
