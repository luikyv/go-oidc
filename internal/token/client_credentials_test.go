package token_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGrantCreation_ClientCredentialsHappyPath(t *testing.T) {
	// Given.
	ctx := oidc.NewTestContext(t)

	req := token.Request{
		AuthnRequest: client.AuthnRequest{
			ID:     oidc.TestClientID,
			Secret: oidc.TestClientSecret,
		},
		GrantType: goidc.GrantClientCredentials,
		Scopes:    oidc.TestScope1.ID,
	}

	// When.
	tokenResp, err := token.GenerateGrant(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := oidc.TestUnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, oidc.TestClientID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, oidc.TestClientID, claims["sub"], "the token subject should be the client")

	sessions := oidc.TestGrantSessions(t, ctx)
	assert.Len(t, sessions, 1, "there should be one session")
}
