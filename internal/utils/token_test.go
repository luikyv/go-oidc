package utils_test

import (
	"testing"

	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeIDToken(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	idTokenOptions := utils.IDTokenOptions{
		Subject: "random_subject",
		AdditionalIDTokenClaims: map[string]any{
			"random_claim": "random_value",
		},
	}

	// When.
	idToken, err := utils.MakeIDToken(ctx, client, idTokenOptions)

	// Then.
	require.Nil(t, err)

	claims := utils.SafeClaims(t, idToken, utils.TestServerPrivateJWK)
	assert.Equal(t, ctx.Host, claims[goidc.ClaimIssuer])
	assert.Equal(t, "random_subject", claims[goidc.ClaimSubject])
	assert.Equal(t, client.ID, claims[goidc.ClaimAudience])
	assert.Equal(t, "random_value", claims["random_claim"])
}

func TestMakeToken_JWTToken(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	tokenOptions := goidc.NewJWTTokenOptions(utils.TestServerPrivateJWK.KeyID(), 60)
	tokenOptions.AddTokenClaims(map[string]any{"random_claim": "random_value"})
	grantOptions := goidc.GrantOptions{
		Subject:      "random_subject",
		TokenOptions: tokenOptions,
	}

	// When.
	token, err := utils.MakeToken(ctx, client, grantOptions)

	// Then.
	require.Nil(t, err)
	assert.Equal(t, goidc.TokenFormatJWT, token.Format)

	claims := utils.SafeClaims(t, token.Value, utils.TestServerPrivateJWK)
	assert.Equal(t, ctx.Host, claims[goidc.ClaimIssuer])
	assert.Equal(t, "random_subject", claims[goidc.ClaimSubject])
	assert.Equal(t, client.ID, claims[goidc.ClaimClientID])
	assert.Equal(t, "random_value", claims["random_claim"])
}

func TestMakeToken_OpaqueToken(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)
	client, _ := ctx.Client(utils.TestClientID)
	grantOptions := goidc.GrantOptions{
		Subject:      "random_subject",
		TokenOptions: goidc.NewOpaqueTokenOptions(10, 60),
	}

	// When.
	token, err := utils.MakeToken(ctx, client, grantOptions)

	// Then.
	require.Nil(t, err)
	assert.Equal(t, goidc.TokenFormatOpaque, token.Format)
	assert.Equal(t, token.ID, token.Value)
}
