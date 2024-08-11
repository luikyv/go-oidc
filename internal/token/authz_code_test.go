package token_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/luikyv/go-oidc/internal/client"
	"github.com/luikyv/go-oidc/internal/oidc"
	"github.com/luikyv/go-oidc/internal/token"
	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleGrantCreation_AuthorizationCodeGrantHappyPath(t *testing.T) {

	// Given.
	ctx := oidc.NewTestContext(t)

	now := time.Now().Unix()
	authorizationCode := "random_authz_code"
	session := &goidc.AuthnSession{
		ClientID:      oidc.TestClientID,
		GrantedScopes: goidc.ScopeOpenID.ID,
		AuthorizationParameters: goidc.AuthorizationParameters{
			Scopes:      goidc.ScopeOpenID.ID,
			RedirectURI: oidc.TestClientRedirectURI,
		},
		AuthorizationCode:     authorizationCode,
		Subject:               "user_id",
		CreatedAtTimestamp:    now,
		ExpiresAtTimestamp:    now + 60,
		Store:                 make(map[string]any),
		AdditionalTokenClaims: make(map[string]any),
	}
	require.Nil(t, ctx.SaveAuthnSession(session))

	req := token.Request{
		AuthnRequest: client.AuthnRequest{
			ID:     oidc.TestClientID,
			Secret: oidc.TestClientSecret,
		},
		GrantType:         goidc.GrantAuthorizationCode,
		RedirectURI:       oidc.TestClientRedirectURI,
		AuthorizationCode: authorizationCode,
	}

	// When.
	tokenResp, err := token.GenerateGrant(ctx, req)

	// Then.
	require.Nil(t, err)

	claims := oidc.UnsafeClaims(t, tokenResp.AccessToken, []jose.SignatureAlgorithm{jose.PS256, jose.RS256})
	assert.Equal(t, oidc.TestClientID, claims["client_id"], "the token was assigned to a different client")
	assert.Equal(t, session.Subject, claims["sub"], "the token subject should be the user")

	grantSessions := oidc.GrantSessions(t, ctx)
	assert.Len(t, grantSessions, 1, "there should be one session")
}

func TestIsPkceValid(t *testing.T) {
	testCases := []struct {
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod goidc.CodeChallengeMethod
		isValid             bool
	}{
		{"4ea55634198fb6a0c120d46b26359cf50ccea86fd03302b9bca9fa98", "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ", goidc.CodeChallengeMethodSHA256, true},
		{"42d92ec716da149b8c0a553d5cbbdc5fd474625cdffe7335d643105b", "yQ0Wg2MXS83nBOaS3yit-n-xEaEw5LQ8TlhtX_2NkLw", goidc.CodeChallengeMethodSHA256, true},
		{"179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ", goidc.CodeChallengeMethodSHA256, false},
		{"179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", "179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", goidc.CodeChallengeMethodSHA256, false},
		{"", "ZObPYv2iA-CObk06I1Z0q5zWRG7gbGjZEWLX5ZC6rjQ", goidc.CodeChallengeMethodSHA256, false},
		{"179de59c7146cbb47757e7bc796c9b21d4a2be62535c4f577566816a", "", goidc.CodeChallengeMethodSHA256, false},
		{"random_string", "random_string", goidc.CodeChallengeMethodPlain, true},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			assert.Equal(t, testCase.isValid, token.IsPKCEValid(testCase.codeVerifier, testCase.codeChallenge, testCase.codeChallengeMethod))
		})
	}
}
