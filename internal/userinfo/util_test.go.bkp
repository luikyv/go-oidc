package userinfo_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/userinfo"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleUserInfoRequest_HappyPath(t *testing.T) {
	// Given.
	token := "opaque_token"
	now := time.Now().Unix()
	grantSession := &goidc.GrantSession{
		TokenID:                    token,
		LastTokenIssuedAtTimestamp: now,
		CreatedAtTimestamp:         now,
		ExpiresAtTimestamp:         now + 60,
		ActiveScopes:               goidc.ScopeOpenID.ID,
		Subject:                    "random_subject",
		ClientID:                   oidctest.ClientID,
		AdditionalUserInfoClaims: map[string]any{
			"random_claim": "random_value",
		},
		TokenOptions: goidc.TokenOptions{
			LifetimeSecs: 60,
		},
	}

	ctx := oidctest.NewContext(t)
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
	now := time.Now().Unix()
	grantSession := &goidc.GrantSession{
		TokenID:                    token,
		ExpiresAtTimestamp:         now + 60,
		LastTokenIssuedAtTimestamp: now + 60,
		CreatedAtTimestamp:         now,
		ActiveScopes:               goidc.ScopeOpenID.ID,
		Subject:                    "random_subject",
		ClientID:                   oidctest.ClientID,
		AdditionalUserInfoClaims: map[string]any{
			"random_claim": "random_value",
		},
	}

	ctx := oidctest.NewContext(t)
	require.Nil(t, ctx.SaveGrantSession(grantSession))
	ctx.Request().Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := oidctest.NewClient(t)
	client.UserInfoSignatureAlgorithm = jose.SignatureAlgorithm(oidctest.ServerPrivateJWK.Algorithm)
	require.Nil(t, ctx.SaveClient(client))

	// When.
	userInfo, err := userinfo.HandleUserInfoRequest(ctx)

	// Then.
	require.Nil(t, err)
	assert.Empty(t, userInfo.Claims)

	claims := oidctest.SafeClaims(t, userInfo.JWTClaims, oidctest.ServerPrivateJWK)
	assert.Equal(t, "random_subject", claims[goidc.ClaimSubject])
	assert.Equal(t, "random_value", claims["random_claim"])
}
