package token

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/authn"
	"github.com/luikyv/go-oidc/internal/utils"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGrantCreation_ClientCredentialsHappyPath(t *testing.T) {
	// Given.
	ctx := utils.NewTestContext(t)

	req := tokenRequest{
		ClientAuthnRequest: authn.ClientAuthnRequest{
			ClientID:     utils.TestClientID,
			ClientSecret: utils.TestClientSecret,
		},
		GrantType: goidc.GrantClientCredentials,
		Scopes:    utils.TestScope1.String(),
	}

	// When.
	tokenResp, err := HandleTokenCreation(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := utils.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, utils.TestClientID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, utils.TestClientID, claims["sub"], "the token subject should be the client")

	sessions := utils.GrantSessions(t, ctx)
	assert.Len(t, sessions, 1, "there should be one session")
}
