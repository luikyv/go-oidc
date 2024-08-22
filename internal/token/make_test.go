package token_test

import (
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeIDToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := ctx.Client(oidctest.ClientID)
	idTokenOptions := token.IDTokenOptions{
		Subject: "random_subject",
		AdditionalIDTokenClaims: map[string]any{
			"random_claim": "random_value",
		},
	}

	// When.
	idToken, err := token.MakeIDToken(ctx, client, idTokenOptions)

	// Then.
	require.Nil(t, err)

	claims := oidctest.SafeClaims(t, idToken, oidctest.ServerPrivateJWK)
	assert.Equal(t, ctx.Host, claims[goidc.ClaimIssuer])
	assert.Equal(t, "random_subject", claims[goidc.ClaimSubject])
	assert.Equal(t, client.ID, claims[goidc.ClaimAudience])
	assert.Equal(t, "random_value", claims["random_claim"])
}

func TestMakeToken_JWTToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := ctx.Client(oidctest.ClientID)
	tokenOptions := goidc.NewJWTTokenOptions(oidctest.ServerPrivateJWK.KeyID, 60)
	tokenOptions.AddTokenClaims(map[string]any{"random_claim": "random_value"})
	grantOptions := token.GrantOptions{
		Subject:      "random_subject",
		TokenOptions: tokenOptions,
	}

	// When.
	token, err := token.Make(ctx, client, grantOptions)

	// Then.
	require.Nil(t, err)
	assert.Equal(t, goidc.TokenFormatJWT, token.Format)

	claims := oidctest.SafeClaims(t, token.Value, oidctest.ServerPrivateJWK)
	assert.Equal(t, ctx.Host, claims[goidc.ClaimIssuer])
	assert.Equal(t, "random_subject", claims[goidc.ClaimSubject])
	assert.Equal(t, client.ID, claims[goidc.ClaimClientID])
	assert.Equal(t, "random_value", claims["random_claim"])
}

func TestMakeToken_OpaqueToken(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)
	client, _ := ctx.Client(oidctest.ClientID)
	grantOptions := token.GrantOptions{
		Subject:      "random_subject",
		TokenOptions: goidc.NewOpaqueTokenOptions(10, 60),
	}

	// When.
	token, err := token.Make(ctx, client, grantOptions)

	// Then.
	require.Nil(t, err)
	assert.Equal(t, goidc.TokenFormatOpaque, token.Format)
	assert.Equal(t, token.ID, token.Value)
}

func TestGenerateJWKThumbprint(t *testing.T) {
	dpopSigningAlgorithms := []jose.SignatureAlgorithm{jose.ES256}
	testCases := []struct {
		DPoPJWT            string
		ExpectedThumbprint string
	}{
		{
			"eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjY1Mjk2fQ.pAqut2IRDm_De6PR93SYmGBPXpwrAk90e8cP2hjiaG5QsGSuKDYW7_X620BxqhvYC8ynrrvZLTk41mSRroapUA",
			"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			assert.Equal(t, testCase.ExpectedThumbprint, token.JWKThumbprint(testCase.DPoPJWT, dpopSigningAlgorithms))
		})
	}
}
