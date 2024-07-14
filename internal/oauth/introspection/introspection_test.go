package introspection_test

import (
	"testing"

	"github.com/luikymagno/goidc/internal/oauth/introspection"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntrospectToken_OpaqueToken(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client := utils.NewTestClient(t)
	client.GrantTypes = append(client.GrantTypes, goidc.GrantIntrospection)
	require.Nil(t, ctx.CreateOrUpdateClient(client))

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
	require.Nil(t, ctx.CreateOrUpdateGrantSession(grantSession))

	tokenReq := utils.TokenIntrospectionRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     utils.TestClientID,
			ClientSecret: utils.TestClientSecret,
		},
		Token: token,
	}

	// When.
	tokenInfo, err := introspection.IntrospectToken(ctx, tokenReq)

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
	require.Nil(t, ctx.CreateOrUpdateClient(client))

	refreshToken, err := utils.RefreshToken()
	require.Nil(t, err)
	grantSession := &goidc.GrantSession{
		RefreshToken:       refreshToken,
		ExpiresAtTimestamp: goidc.TimestampNow() + 60,
		GrantOptions: goidc.GrantOptions{
			ClientID:      utils.TestClientID,
			GrantedScopes: goidc.ScopeOpenID.ID,
		},
	}
	require.Nil(t, ctx.CreateOrUpdateGrantSession(grantSession))

	tokenReq := utils.TokenIntrospectionRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID:     utils.TestClientID,
			ClientSecret: utils.TestClientSecret,
		},
		Token: refreshToken,
	}

	// When.
	tokenInfo, err := introspection.IntrospectToken(ctx, tokenReq)

	// Then.
	require.Nil(t, err)
	require.True(t, tokenInfo.IsActive)
	assert.Equal(t, goidc.ScopeOpenID.ID, tokenInfo.Scopes)
	assert.Equal(t, utils.TestClientID, tokenInfo.ClientID)
	goidc.AssertTimestampWithin(t, goidc.TimestampNow()+60, tokenInfo.ExpiresAtTimestamp)
}
