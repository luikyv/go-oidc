package token_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikymagno/goidc/internal/oauth/token"
	"github.com/luikymagno/goidc/internal/utils"
	"github.com/luikymagno/goidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGrantCreation_ClientCredentialsHappyPath(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)

	req := utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID: utils.TestClientID,
		},
		GrantType: goidc.GrantClientCredentials,
		Scopes:    utils.TestScope1.String(),
	}

	// When.
	tokenResp, err := token.HandleTokenCreation(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := utils.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, utils.TestClientID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, utils.TestClientID, claims["sub"], "the token subject should be the client")

	sessions := utils.TestGrantSessions(t, ctx)
	assert.Len(t, sessions, 1, "there should be one session")
}
