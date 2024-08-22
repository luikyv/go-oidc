package token_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidctest"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGrantCreation_ClientCredentialsHappyPath(t *testing.T) {
	// Given.
	ctx := oidctest.NewContext(t)

	req := token.Request{
		AuthnRequest: client.AuthnRequest{
			ID:     oidctest.ClientID,
			Secret: oidctest.ClientSecret,
		},
		GrantType: goidc.GrantClientCredentials,
		Scopes:    oidctest.Scope1.ID,
	}

	// When.
	tokenResp, err := token.GenerateGrant(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := oidctest.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, oidctest.ClientID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, oidctest.ClientID, claims["sub"], "the token subject should be the client")

	sessions := oidctest.GrantSessions(t, ctx)
	assert.Len(t, sessions, 1, "there should be one session")
}
