package userinfo_test

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oauth/userinfo"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleUserInfoRequest_HappyPath(t *testing.T) {
	// Given.
	token := "opaque_token"
	grantSession := &goidc.GrantSession{
		TokenID:                    token,
		LastTokenIssuedAtTimestamp: goidc.TimestampNow(),
		CreatedAtTimestamp:         goidc.TimestampNow(),
		ExpiresAtTimestamp:         goidc.TimestampNow() + 60,
		ActiveScopes:               goidc.ScopeOpenID.ID,
		GrantOptions: goidc.GrantOptions{
			Subject:  "random_subject",
			ClientID: utils.TestClientID,
			AdditionalUserInfoClaims: map[string]any{
				"random_claim": "random_value",
			},
			TokenOptions: goidc.TokenOptions{
				TokenLifetimeSecs: 60,
			},
		},
	}

	ctx := utils.NewTestContext(t)
	require.Nil(t, ctx.SaveGrantSession(grantSession))
	ctx.Request().Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	// When.
	userInfo, err := userinfo.HandleUserInfoRequest(ctx)

	// Then.
	require.Nil(t, err)
	assert.Empty(t, userInfo.JWTClaims)
	assert.Equal(t, "random_subject", userInfo.Claims[goidc.ClaimSubject])
	assert.Equal(t, "random_value", userInfo.Claims["random_claim"])
}

func TestHandleUserInfoRequest_SignedResponse(t *testing.T) {
	// Given.
	token := "opaque_token"
	grantSession := &goidc.GrantSession{
		TokenID:                    token,
		ExpiresAtTimestamp:         goidc.TimestampNow() + 60,
		LastTokenIssuedAtTimestamp: goidc.TimestampNow() + 60,
		CreatedAtTimestamp:         goidc.TimestampNow(),
		ActiveScopes:               goidc.ScopeOpenID.ID,
		GrantOptions: goidc.GrantOptions{
			Subject:  "random_subject",
			ClientID: utils.TestClientID,
			AdditionalUserInfoClaims: map[string]any{
				"random_claim": "random_value",
			},
		},
	}

	ctx := utils.NewTestContext(t)
	require.Nil(t, ctx.SaveGrantSession(grantSession))
	ctx.Request().Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := utils.NewTestClient(t)
	client.UserInfoSignatureAlgorithm = jose.SignatureAlgorithm(utils.TestServerPrivateJWK.Algorithm)
	require.Nil(t, ctx.SaveClient(client))

	// When.
	userInfo, err := userinfo.HandleUserInfoRequest(ctx)

	// Then.
	require.Nil(t, err)
	assert.Empty(t, userInfo.Claims)

	claims := utils.SafeClaims(t, userInfo.JWTClaims, utils.TestServerPrivateJWK)
	assert.Equal(t, "random_subject", claims[goidc.ClaimSubject])
	assert.Equal(t, "random_value", claims["random_claim"])
}
