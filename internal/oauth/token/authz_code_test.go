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

func TestHandleGrantCreation_AuthorizationCodeGrantHappyPath(t *testing.T) {

	// Given.
	ctx := utils.NewTestContext(t)

	authorizationCode := "random_authz_code"
	session := goidc.AuthnSession{
		ClientID:      utils.TestClientID,
		GrantedScopes: goidc.ScopeOpenID.String(),
		AuthorizationParameters: goidc.AuthorizationParameters{
			Scopes:      goidc.ScopeOpenID.String(),
			RedirectURI: utils.TestClientRedirectURI,
		},
		AuthorizationCode:         authorizationCode,
		Subject:                   "user_id",
		CreatedAtTimestamp:        goidc.TimestampNow(),
		AuthorizationCodeIssuedAt: goidc.TimestampNow(),
		ExpiresAtTimestamp:        goidc.TimestampNow() + 60,
		Store:                     make(map[string]any),
		AdditionalTokenClaims:     make(map[string]any),
	}
	require.Nil(t, ctx.CreateOrUpdateAuthnSession(session))

	req := utils.TokenRequest{
		ClientAuthnRequest: utils.ClientAuthnRequest{
			ClientID: utils.TestClientID,
		},
		GrantType:         goidc.GrantAuthorizationCode,
		RedirectURI:       utils.TestClientRedirectURI,
		AuthorizationCode: authorizationCode,
	}

	// When.
	tokenResp, err := token.HandleTokenCreation(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := utils.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, utils.TestClientID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, session.Subject, claims["sub"], "the token subject should be the user")

	grantSessions := utils.GrantSessions(t, ctx)
	assert.Len(t, grantSessions, 1, "there should be one session")
}
